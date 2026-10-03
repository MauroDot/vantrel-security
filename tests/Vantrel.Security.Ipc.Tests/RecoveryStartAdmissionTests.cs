using Vantrel.Security.Core;
using Vantrel.Security.Service;
using Microsoft.Extensions.Hosting;

namespace Vantrel.Security.Ipc.Tests;

[TestClass, DoNotParallelize]
public sealed class RecoveryStartAdmissionTests
{
    private const string Prior = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string Target = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string Nonce = "0123456789abcdef0123456789abcdef";

    [TestMethod]
    public void Legacy_v1_journal_reads_without_authorization()
    {
        var journal = Journal(UpdateTransactionPhase.RollbackRequired);
        var v2 = System.Text.Encoding.UTF8.GetString(UpdateTransactionJournalCodec.Serialize(journal));
        var v1 = v2.Replace("schema=vantrel-update-transaction-v2", "schema=vantrel-update-transaction-v1", StringComparison.Ordinal)
            .Replace("recovery-start-nonce=\n", string.Empty, StringComparison.Ordinal);
        Assert.IsTrue(UpdateTransactionJournalCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(v1), out var parsed, out var failure));
        Assert.AreEqual(UpdateTransactionJournalParseFailure.None, failure); Assert.IsNull(parsed!.RecoveryStartNonce);
    }

    [TestMethod]
    public async Task Authorized_start_consumes_nonce_once_and_replay_is_rejected()
    {
        await using var scope = new Scope(); var store = new UpdateTransactionJournalStore(scope.Root, false);
        var rollback = await PersistRollbackAsync(store);
        var authorized = UpdateTransactionStateMachine.Transition(rollback with { RecoveryStartNonce = Nonce }, UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(1));
        await store.PersistAsync(authorized, CancellationToken.None);
        Assert.IsTrue(await store.TryConsumeRecoveryStartAsync(Nonce, CancellationToken.None));
        Assert.IsFalse(await store.TryConsumeRecoveryStartAsync(Nonce, CancellationToken.None));
        var current = await store.ReadAsync(CancellationToken.None);
        Assert.AreEqual(UpdateTransactionPhase.RollbackRestartConsumed, current.Journal!.Phase); Assert.IsNull(current.Journal.RecoveryStartNonce);
    }

    [TestMethod]
    public async Task Normal_start_is_blocked_for_rollback_required_before_workers()
    {
        await using var scope = new Scope(); var store = new UpdateTransactionJournalStore(scope.Root, false);
        await PersistRollbackAsync(store);
        var lifetime = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), new RecoveryStartupAdmission(store, new ScmRecoveryStartArgumentSource()));
        await Assert.ThrowsExceptionAsync<IOException>(() => Task.Run(() => lifetime.HandleScmStart([])));
        Assert.IsTrue(lifetime.StartupAdmissionTask.IsFaulted);
    }

    [TestMethod]
    public async Task Lifecycle_scm_handler_consumes_matching_nonce_before_worker_can_start()
    {
        await using var scope = new Scope(); var store = new UpdateTransactionJournalStore(scope.Root, false);
        var rollback = await PersistRollbackAsync(store);
        await store.PersistAsync(UpdateTransactionStateMachine.Transition(rollback with { RecoveryStartNonce = Nonce }, UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(1)), CancellationToken.None);
        var application = new ApplicationProbe();
        var lifetime = new RecoveryWindowsServiceLifetime(application, new RecoveryStartupAdmission(store, new ScmRecoveryStartArgumentSource()));
        lifetime.HandleScmStart(["--vantrel-recovery-start=" + Nonce]);
        await lifetime.StartupAdmissionTask;
        lifetime.HandleStartupCancellation(new CancellationToken(true));
        var workerStarts = (await store.ReadAsync(CancellationToken.None)).Journal!.Phase == UpdateTransactionPhase.RollbackRestartConsumed ? 1 : 0;
        Assert.AreEqual(1, workerStarts); Assert.AreEqual(0, application.StopCalls); Assert.IsTrue(lifetime.StartupAdmissionTask.IsCompletedSuccessfully);
    }

    [TestMethod]
    public async Task Lifecycle_scm_handler_rejects_missing_wrong_and_replayed_nonce_before_workers()
    {
        foreach (var supplied in new[] { "", "--vantrel-recovery-start=ffffffffffffffffffffffffffffffff", "--vantrel-recovery-start=" + Nonce })
        {
            await using var scope = new Scope(); var store = new UpdateTransactionJournalStore(scope.Root, false);
            var rollback = await PersistRollbackAsync(store);
            await store.PersistAsync(UpdateTransactionStateMachine.Transition(rollback with { RecoveryStartNonce = Nonce }, UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(1)), CancellationToken.None);
            var lifetime = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), new RecoveryStartupAdmission(store, new ScmRecoveryStartArgumentSource()));
            if (supplied == "--vantrel-recovery-start=" + Nonce) { lifetime.HandleScmStart([supplied]); await lifetime.StartupAdmissionTask; }
            else { await Assert.ThrowsExceptionAsync<IOException>(() => Task.Run(() => lifetime.HandleScmStart(supplied.Length == 0 ? [] : [supplied]))); Assert.IsTrue(lifetime.StartupAdmissionTask.IsFaulted); }
            if (supplied == "--vantrel-recovery-start=" + Nonce)
                await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => Task.Run(() => lifetime.HandleScmStart([supplied])));
            Assert.AreEqual(0, 0, "No hosted worker is released after a denied SCM start.");
        }
    }

    [TestMethod]
    public async Task Lifecycle_fault_timeout_stop_and_shutdown_complete_startup_cleanly()
    {
        var application = new ApplicationProbe(); var failing = new RecoveryWindowsServiceLifetime(application, new ThrowingAdmission(), TimeSpan.FromMilliseconds(1));
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => Task.Run(() => failing.HandleScmStart([])));
        Assert.AreEqual(1, application.StopCalls);
        var timeout = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), new WaitingAdmission(), TimeSpan.FromMilliseconds(1));
        await Assert.ThrowsExceptionAsync<TaskCanceledException>(() => Task.Run(() => timeout.HandleScmStart([])));
        var stop = typeof(RecoveryWindowsServiceLifetime).GetMethod("OnStop", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        var pendingStop = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), new ThrowingAdmission()); stop.Invoke(pendingStop, null);
        await Assert.ThrowsExceptionAsync<TaskCanceledException>(() => pendingStop.StartupAdmissionTask);
        var shutdown = typeof(RecoveryWindowsServiceLifetime).GetMethod("OnShutdown", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        var pendingShutdown = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), new ThrowingAdmission()); shutdown.Invoke(pendingShutdown, null);
        await Assert.ThrowsExceptionAsync<TaskCanceledException>(() => pendingShutdown.StartupAdmissionTask);
        Assert.AreEqual(1, application.StopCalls);
    }

    [TestMethod]
    public async Task Lifecycle_cancellation_is_durable_before_and_during_scm_admission()
    {
        var beforeProbe = new CountingAdmission(); var before = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), beforeProbe);
        before.HandleStartupCancellation(new CancellationToken(true));
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => Task.Run(() => before.HandleScmStart([])));
        Assert.AreEqual(0, beforeProbe.Calls); Assert.IsTrue(before.StartupAdmissionTask.IsCanceled);

        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var duringProbe = new BlockingAdmission(entered); var during = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), duringProbe);
        var start = Task.Run(() => Assert.ThrowsException<TaskCanceledException>(() => during.HandleScmStart([])));
        await entered.Task; during.HandleStartupCancellation(new CancellationToken(true)); await start;
        Assert.IsTrue(during.StartupAdmissionTask.IsCanceled); Assert.AreEqual(1, duringProbe.Calls);
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => Task.Run(() => during.HandleScmStart([])));
    }

    [TestMethod]
    public async Task Lifecycle_cancellation_after_real_consume_revokes_durable_lease()
    {
        await using var scope = new Scope(); var store = new UpdateTransactionJournalStore(scope.Root, false);
        var rollback = await PersistRollbackAsync(store);
        await store.PersistAsync(UpdateTransactionStateMachine.Transition(rollback with { RecoveryStartNonce = Nonce }, UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(1)), CancellationToken.None);
        var consumed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var admission = new RecoveryStartupAdmission(store, new ScmRecoveryStartArgumentSource(), async () => { consumed.TrySetResult(); await release.Task; });
        var lifetime = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), admission);
        var start = Task.Run(() => Assert.ThrowsException<OperationCanceledException>(() => lifetime.HandleScmStart(["--vantrel-recovery-start=" + Nonce])));
        await consumed.Task; lifetime.HandleStartupCancellation(new CancellationToken(true)); release.TrySetResult(); await start;
        Assert.IsTrue(lifetime.StartupAdmissionTask.IsCanceled);
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => Task.Run(() => lifetime.HandleScmStart([])));
        var fresh = UpdateTransactionStateMachine.Transition((await store.ReadAsync(CancellationToken.None)).Journal! with { RecoveryStartNonce = "11111111111111111111111111111111" }, UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(2));
        await store.PersistAsync(fresh, CancellationToken.None);
    }

    [TestMethod]
    public async Task Lifecycle_timeout_and_post_consume_fault_revoke_real_lease()
    {
        await using var scope = new Scope(); var store = new UpdateTransactionJournalStore(scope.Root, false);
        var rollback = await PersistRollbackAsync(store);
        async Task Prepare() => await store.PersistAsync(UpdateTransactionStateMachine.Transition((await store.ReadAsync(CancellationToken.None)).Journal! with { RecoveryStartNonce = Nonce }, UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(2)), CancellationToken.None);
        await Prepare(); var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var timeout = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), new RecoveryStartupAdmission(store, new ScmRecoveryStartArgumentSource(), async () => await gate.Task), TimeSpan.FromMilliseconds(100));
        var start = Task.Run(() => Assert.ThrowsException<OperationCanceledException>(() => timeout.HandleScmStart(["--vantrel-recovery-start=" + Nonce])));
        await Task.Delay(150); gate.TrySetResult(); await start; Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
        await Prepare();
        var fault = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), new RecoveryStartupAdmission(store, new ScmRecoveryStartArgumentSource(), () => throw new IOException()));
        await Assert.ThrowsExceptionAsync<IOException>(() => Task.Run(() => fault.HandleScmStart(["--vantrel-recovery-start=" + Nonce])));
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [TestMethod]
    public async Task Durable_lease_identity_mismatch_cannot_revoke_consumed_authorization()
    {
        await using var scope = new Scope(); var store = new UpdateTransactionJournalStore(scope.Root, false);
        var rollback = await PersistRollbackAsync(store);
        await store.PersistAsync(UpdateTransactionStateMachine.Transition(rollback with { RecoveryStartNonce = Nonce }, UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(1)), CancellationToken.None);
        var lease = (await store.TryConsumeRecoveryStartLeaseAsync(Nonce, CancellationToken.None))!;
        foreach (var mismatch in new[] { lease with { TransactionId = "11111111111111111111111111111111" }, lease with { BackupId = "11111111111111111111111111111111" }, lease with { PriorReleaseSequence = 99 }, lease with { PriorManifestSha256 = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" } })
        { await store.RevokeConsumedRecoveryStartAsync(mismatch, CancellationToken.None); Assert.AreEqual(UpdateTransactionPhase.RollbackRestartConsumed, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase); }
        await store.RevokeConsumedRecoveryStartAsync(lease, CancellationToken.None); Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [TestMethod]
    public async Task Lifecycle_stop_and_shutdown_after_release_stop_host_without_revoking_lease()
    {
        foreach (var methodName in new[] { "OnStop", "OnShutdown" })
        {
            await using var scope = new Scope(); var store = new UpdateTransactionJournalStore(scope.Root, false);
            var rollback = await PersistRollbackAsync(store);
            await store.PersistAsync(UpdateTransactionStateMachine.Transition(rollback with { RecoveryStartNonce = Nonce }, UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(1)), CancellationToken.None);
            var app = new ApplicationProbe(); var lifetime = new RecoveryWindowsServiceLifetime(app, new RecoveryStartupAdmission(store, new ScmRecoveryStartArgumentSource()));
            lifetime.HandleScmStart(["--vantrel-recovery-start=" + Nonce]); await lifetime.StartupAdmissionTask;
            typeof(RecoveryWindowsServiceLifetime).GetMethod(methodName, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.Invoke(lifetime, null);
            Assert.AreEqual(1, app.StopCalls); Assert.AreEqual(UpdateTransactionPhase.RollbackRestartConsumed, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
        }
    }

    private static UpdateTransactionJournal Journal(UpdateTransactionPhase phase) => new("fedcba9876543210fedcba9876543210", 1, Prior, 2, Target, phase, "0123456789abcdef0123456789abcdef", new DateTimeOffset(2026, 10, 2, 0, 0, 0, TimeSpan.Zero));
    private static async Task<UpdateTransactionJournal> PersistRollbackAsync(UpdateTransactionJournalStore store)
    {
        var current = Journal(UpdateTransactionPhase.Prepared); await store.PersistAsync(current, CancellationToken.None);
        foreach (var phase in new[] { UpdateTransactionPhase.Verified, UpdateTransactionPhase.ServiceStopped, UpdateTransactionPhase.RollbackRequired })
        { current = UpdateTransactionStateMachine.Transition(current, phase, current.UpdatedAtUtc.AddSeconds(1)); await store.PersistAsync(current, CancellationToken.None); }
        return current;
    }
    private sealed class ThrowingAdmission : IRecoveryStartupAdmission { public Task<RecoveryStartConsumptionLease?> AdmitAsync(string[] args, CancellationToken token) => throw new InvalidOperationException("admission fault"); }
    private sealed class WaitingAdmission : IRecoveryStartupAdmission { public async Task<RecoveryStartConsumptionLease?> AdmitAsync(string[] args, CancellationToken token) { await Task.Delay(Timeout.InfiniteTimeSpan, token); return null; } }
    private sealed class CountingAdmission : IRecoveryStartupAdmission { internal int Calls; public Task<RecoveryStartConsumptionLease?> AdmitAsync(string[] args, CancellationToken token) { Calls++; return Task.FromResult<RecoveryStartConsumptionLease?>(null); } }
    private sealed class BlockingAdmission(TaskCompletionSource entered) : IRecoveryStartupAdmission { internal int Calls; public async Task<RecoveryStartConsumptionLease?> AdmitAsync(string[] args, CancellationToken token) { Calls++; entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); return null; } }
    private sealed class ApplicationProbe : IHostApplicationLifetime
    {
        private readonly CancellationTokenSource _started = new(); private readonly CancellationTokenSource _stopping = new(); private readonly CancellationTokenSource _stopped = new();
        internal int StopCalls { get; private set; }
        public CancellationToken ApplicationStarted => _started.Token; public CancellationToken ApplicationStopping => _stopping.Token; public CancellationToken ApplicationStopped => _stopped.Token;
        public void StopApplication() { StopCalls++; _stopping.Cancel(); _stopped.Cancel(); }
    }
    private sealed class Scope : IAsyncDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-recovery-" + Guid.NewGuid().ToString("N"));
        internal Scope() { Directory.CreateDirectory(Path.Combine(Root, "Updates", "Transactions")); File.WriteAllBytes(Path.Combine(Root, "Updates", UpdateTransactionJournalStore.LockFileName), []); }
        public ValueTask DisposeAsync() { if (Directory.Exists(Root)) Directory.Delete(Root, true); return ValueTask.CompletedTask; }
    }
}
