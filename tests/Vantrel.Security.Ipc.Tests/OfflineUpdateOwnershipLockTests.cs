using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass, DoNotParallelize]
public sealed class OfflineUpdateOwnershipLockTests
{
    private const string Prior = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string Target = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string Nonce = "0123456789abcdef0123456789abcdef";

    [TestMethod]
    public async Task Second_independent_administrator_is_rejected_before_journal_file_policy_or_scm_work()
    {
        await using var scope = new Scope(); var firstStore = scope.Store(); var secondStore = scope.Store();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstJournalCalls = 0; var secondJournalCalls = 0;
        var first = Administrator(firstStore, scope, async token => await OfflineUpdateAdministrator.WithValidatedJournalAsync(firstStore, async _ =>
        {
            firstJournalCalls++; entered.TrySetResult(); await release.Task.WaitAsync(token); return UpdateTransactionPhase.Completed;
        }, token));
        var second = Administrator(secondStore, scope, token => OfflineUpdateAdministrator.WithValidatedJournalAsync(secondStore, _ =>
        {
            secondJournalCalls++; return Task.FromResult(UpdateTransactionPhase.Completed);
        }, token));

        var running = first.ApplyFixedStagedCandidateAsync(CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.AreEqual(OfflineUpdateInvocationResult.AlreadyInProgress, await second.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        Assert.AreEqual(1, firstJournalCalls); Assert.AreEqual(0, secondJournalCalls);
        release.TrySetResult(); Assert.AreEqual(OfflineUpdateInvocationResult.Completed, await running);
    }

    [DataTestMethod]
    [DataRow(UpdateTransactionPhase.ServiceStopped)]
    [DataRow(UpdateTransactionPhase.RollbackRequired)]
    public async Task Only_owner_can_restore_or_start_concurrent_recovery(UpdateTransactionPhase phase)
    {
        await using var scope = new Scope(); var firstStore = scope.Store(); var secondStore = scope.Store();
        await PersistThroughAsync(firstStore, phase);
        var firstFiles = new BlockingFiles(); var firstService = new ServiceProbe(); var firstHealth = new HealthProbe();
        var secondFiles = new CountingFiles(); var secondService = new ServiceProbe(); var secondHealth = new HealthProbe();
        var first = Administrator(firstStore, scope, token => RecoverAsync(firstStore, firstFiles, firstService, firstHealth, token));
        var second = Administrator(secondStore, scope, token => RecoverAsync(secondStore, secondFiles, secondService, secondHealth, token));

        var running = first.ApplyFixedStagedCandidateAsync(CancellationToken.None);
        await firstFiles.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.AreEqual(OfflineUpdateInvocationResult.AlreadyInProgress, await second.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        Assert.AreEqual(0, secondFiles.RestoreCount); Assert.AreEqual(0, secondService.StartCount); Assert.AreEqual(0, secondHealth.PolicyReads);
        firstFiles.Release.TrySetResult(); Assert.AreEqual(OfflineUpdateInvocationResult.Failed, await running);
        Assert.AreEqual(1, firstFiles.RestoreCount); Assert.AreEqual(1, firstService.StartCount);
    }

    [TestMethod]
    public async Task Owner_holds_across_authorization_and_scm_consumption_without_deadlock_or_stale_revocation()
    {
        await using var scope = new Scope(); var firstStore = scope.Store(); var secondStore = scope.Store();
        await PersistThroughAsync(firstStore, UpdateTransactionPhase.ServiceStopped);
        var files = new CountingFiles(); var firstHealth = new HealthProbe();
        var recoveryService = new ScmRecoveryService(firstStore);
        var secondFiles = new CountingFiles(); var secondService = new ServiceProbe(); var secondHealth = new HealthProbe();
        var first = Administrator(firstStore, scope, token => RecoverAsync(firstStore, files, recoveryService, firstHealth, token));
        var second = Administrator(secondStore, scope, token => RecoverAsync(secondStore, secondFiles, secondService, secondHealth, token));

        var running = first.ApplyFixedStagedCandidateAsync(CancellationToken.None);
        await recoveryService.Consumed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.AreEqual(UpdateTransactionPhase.RollbackRestartConsumed, (await firstStore.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.AreEqual(OfflineUpdateInvocationResult.AlreadyInProgress, await second.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        Assert.AreEqual(0, secondFiles.RestoreCount); Assert.AreEqual(0, secondService.StartCount); Assert.AreEqual(0, secondHealth.PolicyReads);
        recoveryService.Release.TrySetResult(); Assert.AreEqual(OfflineUpdateInvocationResult.Failed, await running);
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, (await firstStore.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [TestMethod]
    public async Task Owner_holds_across_consumed_verification_and_allows_one_terminal_transition()
    {
        await using var scope = new Scope(); var firstStore = scope.Store(); var secondStore = scope.Store();
        await PersistConsumedAsync(firstStore);
        var firstHealth = new BlockingHealth(); var secondHealth = new HealthProbe();
        var first = Administrator(firstStore, scope, token => RecoverAsync(firstStore, new CountingFiles(), new ServiceProbe(), firstHealth, token));
        var second = Administrator(secondStore, scope, token => RecoverAsync(secondStore, new CountingFiles(), new ServiceProbe(), secondHealth, token));

        var running = first.ApplyFixedStagedCandidateAsync(CancellationToken.None);
        await firstHealth.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.AreEqual(OfflineUpdateInvocationResult.AlreadyInProgress, await second.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        Assert.AreEqual(0, secondHealth.PolicyReads); Assert.AreEqual(0, secondHealth.PredecessorVerifications);
        firstHealth.Release.TrySetResult(); Assert.AreEqual(OfflineUpdateInvocationResult.Failed, await running);
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, (await firstStore.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [TestMethod]
    public async Task Released_owner_handle_allows_independent_administrator_to_resume()
    {
        await using var scope = new Scope(); var firstLock = scope.OwnerLock();
        using var held = firstLock.TryAcquire(CancellationToken.None);
        Assert.IsNotNull(held);
        var calls = 0; var second = Administrator(scope.Store(), scope, _ => { calls++; return Task.FromResult(UpdateTransactionPhase.Completed); });
        Assert.AreEqual(OfflineUpdateInvocationResult.AlreadyInProgress, await second.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        held.Dispose();
        Assert.AreEqual(OfflineUpdateInvocationResult.Completed, await second.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        Assert.AreEqual(1, calls);
    }

    [TestMethod]
    public async Task Fresh_admission_has_one_identity_and_no_competing_storage_work()
    {
        await using var scope = new Scope(); var firstStore = scope.Store(); var secondStore = scope.Store();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstStorage = new AdmissionProbe(); var secondStorage = new AdmissionProbe();
        var first = Administrator(firstStore, scope, token => AdmitAsync(firstStore, "0123456789abcdef0123456789abcdef", firstStorage, entered, release, token));
        var second = Administrator(secondStore, scope, token => AdmitAsync(secondStore, "fedcba9876543210fedcba9876543210", secondStorage, null, null, token));

        var running = first.ApplyFixedStagedCandidateAsync(CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.AreEqual(OfflineUpdateInvocationResult.AlreadyInProgress, await second.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        Assert.AreEqual(0, secondStorage.PrivateCopies); Assert.AreEqual(0, secondStorage.Backups);
        release.TrySetResult(); Assert.AreEqual(OfflineUpdateInvocationResult.Completed, await running);
        Assert.AreEqual("0123456789abcdef0123456789abcdef", (await firstStore.ReadAsync(CancellationToken.None)).Journal!.TransactionId);
        Assert.AreEqual(1, firstStorage.PrivateCopies); Assert.AreEqual(1, firstStorage.Backups);
    }

    [TestMethod]
    public async Task Cancellation_and_exception_release_owner_for_a_later_invocation()
    {
        await using var scope = new Scope();
        var exception = Administrator(scope.Store(), scope, _ => Task.FromException<UpdateTransactionPhase>(new IOException("test failure")));
        Assert.AreEqual(OfflineUpdateInvocationResult.Failed, await exception.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        var calls = 0; var follower = Administrator(scope.Store(), scope, _ => { calls++; return Task.FromResult(UpdateTransactionPhase.Completed); });
        Assert.AreEqual(OfflineUpdateInvocationResult.Completed, await follower.ApplyFixedStagedCandidateAsync(CancellationToken.None));

        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        var cancelled = Administrator(scope.Store(), scope, async token => { entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); return UpdateTransactionPhase.Completed; });
        var cancelledTask = cancelled.ApplyFixedStagedCandidateAsync(cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); cancellation.Cancel();
        await Assert.ThrowsExceptionAsync<TaskCanceledException>(() => cancelledTask);
        Assert.AreEqual(OfflineUpdateInvocationResult.Completed, await follower.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        Assert.AreEqual(2, calls);
    }

    [DataTestMethod]
    [DataRow("missing")]
    [DataRow("directory")]
    [DataRow("reparse")]
    [DataRow("denied")]
    public async Task Unsafe_owner_lock_infrastructure_fails_closed_before_administrator_operation(string scenario)
    {
        await using var scope = new Scope();
        if (scenario == "missing") File.Delete(scope.OwnerLockPath);
        if (scenario == "directory") { File.Delete(scope.OwnerLockPath); Directory.CreateDirectory(scope.OwnerLockPath); }
        if (scenario == "reparse")
        {
            File.Delete(scope.OwnerLockPath); var target = Path.Combine(scope.Root, "owner-lock-target"); File.WriteAllText(target, "target");
            try { File.CreateSymbolicLink(scope.OwnerLockPath, target); }
            catch (UnauthorizedAccessException) { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
            catch (IOException error) when ((uint)error.HResult == 0x80070522) { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
        }
        FileSecurity? original = null;
        if (scenario == "denied")
        {
            var file = new FileInfo(scope.OwnerLockPath); original = file.GetAccessControl(); var denied = file.GetAccessControl();
            using var identity = WindowsIdentity.GetCurrent();
            denied.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.ReadData | FileSystemRights.WriteData, AccessControlType.Deny));
            file.SetAccessControl(denied);
        }
        try
        {
            var calls = 0; var administrator = Administrator(scope.Store(), scope, _ => { calls++; return Task.FromResult(UpdateTransactionPhase.Completed); });
            Assert.AreEqual(OfflineUpdateInvocationResult.Failed, await administrator.ApplyFixedStagedCandidateAsync(CancellationToken.None));
            Assert.AreEqual(0, calls);
        }
        finally
        {
            if (original is not null && File.Exists(scope.OwnerLockPath)) new FileInfo(scope.OwnerLockPath).SetAccessControl(original);
        }
    }

    private static OfflineUpdateAdministrator Administrator(UpdateTransactionJournalStore store, Scope scope,
        Func<CancellationToken, Task<UpdateTransactionPhase>> operation) =>
        new(operation, new SemaphoreSlim(1, 1), scope.OwnerLock());

    private static async Task<UpdateTransactionPhase> AdmitAsync(UpdateTransactionJournalStore store, string id, AdmissionProbe storage,
        TaskCompletionSource? entered, TaskCompletionSource? release, CancellationToken token) =>
        await OfflineUpdateAdministrator.WithValidatedJournalAsync(store, async existing =>
        {
            Assert.IsNull(existing); storage.PrivateCopies++; storage.Backups++;
            await store.PersistAsync(Journal(id, UpdateTransactionPhase.Prepared), token);
            entered?.TrySetResult(); if (release is not null) await release.Task.WaitAsync(token);
            return UpdateTransactionPhase.Completed;
        }, token);

    private static async Task<UpdateTransactionPhase> RecoverAsync(UpdateTransactionJournalStore store, IOfflineUpdateReleaseFiles files,
        IOfflineUpdateServiceControl service, IOfflineUpdateHealth health, CancellationToken token)
    {
        var engine = new OfflineUpdateTransactionEngine(new EmptyPreflight(), service, files, health, new JournalAdapter(store));
        return await OfflineUpdateAdministrator.WithValidatedJournalAsync(store, journal =>
        {
            Assert.IsNotNull(journal); return engine.RecoverAsync(journal!, token);
        }, token);
    }

    private static async Task PersistThroughAsync(UpdateTransactionJournalStore store, UpdateTransactionPhase target)
    {
        var current = Journal("0123456789abcdef0123456789abcdef", UpdateTransactionPhase.Prepared);
        await store.PersistAsync(current, CancellationToken.None);
        foreach (var phase in new[] { UpdateTransactionPhase.Verified, UpdateTransactionPhase.ServiceStopped, UpdateTransactionPhase.RollbackRequired })
        {
            if (phase == UpdateTransactionPhase.RollbackRequired && target != phase) break;
            current = UpdateTransactionStateMachine.Transition(current, phase, current.UpdatedAtUtc.AddSeconds(1));
            await store.PersistAsync(current, CancellationToken.None);
            if (phase == target) return;
        }
    }

    private static async Task PersistConsumedAsync(UpdateTransactionJournalStore store)
    {
        await PersistThroughAsync(store, UpdateTransactionPhase.RollbackRequired);
        var rollback = (await store.ReadAsync(CancellationToken.None)).Journal!;
        var authorized = UpdateTransactionStateMachine.Transition(rollback with { RecoveryStartNonce = Nonce },
            UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(1));
        await store.PersistAsync(authorized, CancellationToken.None);
        Assert.IsNotNull(await store.TryConsumeRecoveryStartLeaseAsync(Nonce, CancellationToken.None));
    }

    private static UpdateTransactionJournal Journal(string transactionId, UpdateTransactionPhase phase) => new(transactionId, 1, Prior, 2, Target,
        phase, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", new DateTimeOffset(2026, 10, 2, 0, 0, 0, TimeSpan.Zero));

    private sealed class EmptyPreflight : IOfflineUpdatePreflight
    {
        public Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
    }
    private sealed class JournalAdapter(UpdateTransactionJournalStore store) : IOfflineUpdateJournal
    {
        public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token) => store.PersistAsync(journal, token);
    }
    private sealed class AdmissionProbe { internal int PrivateCopies; internal int Backups; }
    private class CountingFiles : IOfflineUpdateReleaseFiles
    {
        internal int RestoreCount;
        public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public virtual Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { RestoreCount++; return Task.CompletedTask; }
    }
    private sealed class BlockingFiles : CountingFiles
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            RestoreCount++; Entered.TrySetResult(); await Release.Task.WaitAsync(token);
        }
    }
    private class ServiceProbe : IOfflineUpdateServiceControl
    {
        internal int StartCount;
        public Task StopAsync(CancellationToken token) => Task.CompletedTask;
        public Task StartAsync(CancellationToken token) { StartCount++; return Task.CompletedTask; }
        public virtual Task StartRecoveryAsync(string nonce, CancellationToken token) => StartAsync(token);
        public Task RequireStoppedAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.CompletedTask; }
    }
    private sealed class ScmRecoveryService(UpdateTransactionJournalStore store) : ServiceProbe
    {
        internal TaskCompletionSource Consumed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async Task StartRecoveryAsync(string nonce, CancellationToken token)
        {
            StartCount++;
            var lifetime = new RecoveryWindowsServiceLifetime(new ApplicationProbe(), new RecoveryStartupAdmission(store, new ScmRecoveryStartArgumentSource()));
            lifetime.HandleScmStart(["--vantrel-recovery-start=" + nonce]);
            await lifetime.StartupAdmissionTask;
            Consumed.TrySetResult(); await Release.Task.WaitAsync(token);
        }
    }
    private class HealthProbe : IOfflineUpdateHealth
    {
        internal int PolicyReads;
        internal int PredecessorVerifications;
        public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public virtual Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { PredecessorVerifications++; return Task.CompletedTask; }
        public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            PolicyReads++; return Task.FromResult(PolicyCommitObservation.PredecessorRetained);
        }
    }
    private sealed class BlockingHealth : HealthProbe
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            PredecessorVerifications++; Entered.TrySetResult(); await Release.Task.WaitAsync(token);
        }
    }
    private sealed class ApplicationProbe : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() { }
    }
    private sealed class Scope : IAsyncDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-owner-" + Guid.NewGuid().ToString("N"));
        internal string OwnerLockPath => Path.Combine(Root, "Updates", OfflineUpdateOwnershipLock.OwnerLockFileName);
        internal Scope()
        {
            Directory.CreateDirectory(Path.Combine(Root, "Updates", "Transactions"));
            File.WriteAllBytes(Path.Combine(Root, "Updates", UpdateTransactionJournalStore.LockFileName), []);
            File.WriteAllBytes(OwnerLockPath, []);
        }
        internal UpdateTransactionJournalStore Store() => new(Root, applyAcls: false);
        internal OfflineUpdateOwnershipLock OwnerLock() => new(Root, applyAcls: false);
        public ValueTask DisposeAsync() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); return ValueTask.CompletedTask; }
    }
}
