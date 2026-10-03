using System.Security.Cryptography;
using System.ServiceProcess;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class RollbackRecoveryPersistenceTests
{
    [DataTestMethod]
    [DataRow("running")]
    [DataRow("start-pending")]
    [DataRow("stop-pending")]
    [DataRow("paused")]
    [DataRow("pause-pending")]
    [DataRow("continue-pending")]
    [DataRow("missing")]
    [DataRow("inaccessible")]
    [DataRow("query-failure")]
    [DataRow("timeout")]
    [DataRow("unknown")]
    public async Task Final_stopped_guard_blocks_restore_and_start_and_retains_durable_rollback(string state)
    {
        await using var fixture = await DurableFixture.CreateAsync();
        var controller = new WindowsVantrelServiceControl(_ => ReadState(state));
        fixture.Service.StoppedGuard = controller.RequireStoppedAsync;
        var before = await fixture.InstalledFingerprintAsync();
        var engine = fixture.CreateEngine(fixture.RealFiles);

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(1, fixture.Service.GuardCount);
        Assert.AreEqual(0, fixture.Service.StartCount);
        Assert.AreEqual(before, await fixture.InstalledFingerprintAsync());

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(2, fixture.Service.GuardCount);
        Assert.AreEqual(0, fixture.Service.StartCount);
        Assert.AreEqual(before, await fixture.InstalledFingerprintAsync());
    }

    [TestMethod]
    public async Task Later_stopped_retry_reauthenticates_before_guard_and_restores_predecessor()
    {
        await using var fixture = await DurableFixture.CreateAsync();
        var state = ServiceControllerStatus.Running;
        var controller = new WindowsVantrelServiceControl(_ => Task.FromResult(state));
        fixture.Service.StoppedGuard = controller.RequireStoppedAsync;
        var engine = fixture.CreateEngine(fixture.RealFiles);
        var before = await fixture.InstalledFingerprintAsync();
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));

        state = ServiceControllerStatus.Stopped;
        await fixture.TamperBackupAsync();
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        Assert.AreEqual(1, fixture.Service.GuardCount, "Fresh authentication must reject tampering before even querying service state.");
        Assert.AreEqual(0, fixture.Service.StartCount);
        Assert.AreEqual(before, await fixture.InstalledFingerprintAsync());

        await fixture.RestoreBackupBytesAsync();
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RolledBack);
        Assert.AreEqual(2, fixture.Service.GuardCount);
        Assert.AreEqual(1, fixture.Service.StartCount);
        Assert.AreEqual(1, fixture.Health.PredecessorVerificationCount);
        await fixture.AssertInstalledPredecessorAsync();
    }

    [TestMethod]
    public async Task Restart_after_journal_persistence_is_seen_by_final_point_in_time_guard()
    {
        await using var fixture = await DurableFixture.CreateAsync();
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.ServiceStopped);
        // The historical stop does not reserve SCM state: an external start occurred.
        var controller = new WindowsVantrelServiceControl(_ => Task.FromResult(ServiceControllerStatus.Running));
        fixture.Service.StoppedGuard = controller.RequireStoppedAsync;
        var before = await fixture.InstalledFingerprintAsync();
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(fixture.CreateEngine(fixture.RealFiles)));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(before, await fixture.InstalledFingerprintAsync());
        Assert.AreEqual(0, fixture.Service.StartCount);
    }

    [TestMethod]
    public async Task State_changes_while_final_query_is_pending_are_not_hidden_by_historical_stop()
    {
        await using var fixture = await DurableFixture.CreateAsync();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var observed = new TaskCompletionSource<ServiceControllerStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        var controller = new WindowsVantrelServiceControl(_ => { entered.TrySetResult(); return observed.Task; });
        fixture.Service.StoppedGuard = controller.RequireStoppedAsync;
        var before = await fixture.InstalledFingerprintAsync();
        var recovery = fixture.RecoverAsync(fixture.CreateEngine(fixture.RealFiles));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.IsFalse(recovery.IsCompleted);
            observed.TrySetResult(ServiceControllerStatus.Running);
            Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await recovery.WaitAsync(TimeSpan.FromSeconds(5)));
            await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
            Assert.AreEqual(before, await fixture.InstalledFingerprintAsync());
            Assert.AreEqual(0, fixture.Service.StartCount);
        }
        finally { observed.TrySetResult(ServiceControllerStatus.Running); await recovery.WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    [TestMethod]
    public async Task Restart_during_backup_policy_authentication_is_rejected_by_final_guard()
    {
        await using var fixture = await DurableFixture.CreateAsync();
        var state = ServiceControllerStatus.Stopped;
        var controller = new WindowsVantrelServiceControl(_ => Task.FromResult(state));
        fixture.Service.StoppedGuard = controller.RequireStoppedAsync;
        // Hold the real durable-policy read in the restore authentication boundary.
        // Reflection avoids adding a production verifier hook just for coordination.
        var gate = (SemaphoreSlim)typeof(ReleasePolicyStore).GetField("_gate",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(fixture.Policy)!;
        var initialPolicyRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = false;
        fixture.Health.AfterPolicyRead = () =>
        {
            Assert.IsTrue(gate.Wait(0));
            held = true;
            fixture.Health.AfterPolicyRead = null;
            initialPolicyRead.TrySetResult();
        };
        var before = await fixture.InstalledFingerprintAsync();
        var recovery = fixture.RecoverAsync(fixture.CreateEngine(fixture.RealFiles));
        try
        {
            await initialPolicyRead.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.IsFalse(recovery.IsCompleted);
            Assert.AreEqual(0, fixture.Service.GuardCount);
            state = ServiceControllerStatus.Running;
            gate.Release(); held = false;
            Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await recovery.WaitAsync(TimeSpan.FromSeconds(5)));
            await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
            Assert.AreEqual(1, fixture.Service.GuardCount);
            Assert.AreEqual(0, fixture.Service.StartCount);
            Assert.AreEqual(before, await fixture.InstalledFingerprintAsync());
        }
        finally
        {
            if (held) gate.Release();
            await recovery.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [TestMethod]
    public async Task Pending_state_query_is_bounded_by_controller_timeout()
    {
        var pending = new TaskCompletionSource<ServiceControllerStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        var controller = new WindowsVantrelServiceControl(_ => pending.Task);
        try
        {
            await Assert.ThrowsExceptionAsync<System.TimeoutException>(() => controller.RequireStoppedAsync(CancellationToken.None))
                .WaitAsync(WindowsVantrelServiceControl.Timeout + TimeSpan.FromSeconds(5));
            Assert.IsFalse(pending.Task.IsCompleted, "Timeout must not convert an unfinished query into stopped evidence.");
        }
        finally { pending.TrySetResult(ServiceControllerStatus.Stopped); }
    }

    [TestMethod]
    public async Task Cancellation_at_pending_stopped_guard_propagates_without_restore_or_start()
    {
        await using var fixture = await DurableFixture.CreateAsync();
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = new TaskCompletionSource<ServiceControllerStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        var controller = new WindowsVantrelServiceControl(_ => { entered.TrySetResult(); return pending.Task; });
        fixture.Service.StoppedGuard = controller.RequireStoppedAsync;
        var before = await fixture.InstalledFingerprintAsync();
        var recovery = fixture.RecoverAsync(fixture.CreateEngine(fixture.RealFiles), cancellation.Token);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
            try { await recovery.WaitAsync(TimeSpan.FromSeconds(5)); Assert.Fail("Cancellation must propagate."); }
            catch (OperationCanceledException error) { Assert.AreEqual(cancellation.Token, error.CancellationToken); }
            await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
            Assert.AreEqual(0, fixture.Service.StartCount);
            Assert.AreEqual(before, await fixture.InstalledFingerprintAsync());
        }
        finally
        {
            cancellation.Cancel(); pending.TrySetResult(ServiceControllerStatus.Stopped);
            try { await recovery.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        }
    }

    [TestMethod]
    public async Task Predecessor_health_failure_retry_cannot_bypass_running_service_guard()
    {
        await using var fixture = await DurableFixture.CreateAsync();
        var state = ServiceControllerStatus.Stopped;
        var controller = new WindowsVantrelServiceControl(_ => Task.FromResult(state));
        fixture.Service.StoppedGuard = controller.RequireStoppedAsync;
        fixture.Health.FailPredecessorVerificationRemaining = 1;
        var engine = fixture.CreateEngine(fixture.RealFiles);
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        state = ServiceControllerStatus.Running;
        var before = await fixture.InstalledFingerprintAsync();
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(1, fixture.Service.StartCount);
        Assert.AreEqual(1, fixture.Health.PredecessorVerificationCount);
        Assert.AreEqual(before, await fixture.InstalledFingerprintAsync());
        state = ServiceControllerStatus.Stopped;
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await fixture.RecoverAsync(engine));
    }

    private static Task<ServiceControllerStatus> ReadState(string state) => state switch
    {
        "running" => Task.FromResult(ServiceControllerStatus.Running),
        "start-pending" => Task.FromResult(ServiceControllerStatus.StartPending),
        "stop-pending" => Task.FromResult(ServiceControllerStatus.StopPending),
        "paused" => Task.FromResult(ServiceControllerStatus.Paused),
        "pause-pending" => Task.FromResult(ServiceControllerStatus.PausePending),
        "continue-pending" => Task.FromResult(ServiceControllerStatus.ContinuePending),
        "missing" => Task.FromException<ServiceControllerStatus>(new InvalidOperationException("Test-only missing service.")),
        "inaccessible" => Task.FromException<ServiceControllerStatus>(new UnauthorizedAccessException("Test-only inaccessible SCM.")),
        "query-failure" => Task.FromException<ServiceControllerStatus>(new IOException("Test-only SCM query failure.")),
        "timeout" => Task.FromException<ServiceControllerStatus>(new System.TimeoutException("Test-only SCM timeout.")),
        "unknown" => Task.FromResult((ServiceControllerStatus)999),
        _ => throw new ArgumentOutOfRangeException(nameof(state))
    };

    [TestMethod]
    public async Task Target_health_failure_cannot_restore_while_target_service_is_running()
    {
        await using var fixture = await DurableFixture.CreateAsync(UpdateTransactionPhase.Prepared);
        var state = ServiceControllerStatus.Stopped;
        var controller = new WindowsVantrelServiceControl(_ => Task.FromResult(state));
        fixture.Service.StoppedGuard = controller.RequireStoppedAsync;
        fixture.Service.AfterStart = () => state = ServiceControllerStatus.Running;
        fixture.Health.FailTargetVerificationRemaining = 1;
        var engine = fixture.CreateEngine(new FailAfterCopiesThenRestore(fixture, null));
        var before = await fixture.InstalledFingerprintAsync();

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await engine.ExecuteAsync(fixture.Journal, CancellationToken.None));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(1, fixture.Service.GuardCount);
        Assert.AreEqual(1, fixture.Service.StartCount, "Only the original target start is permitted; rollback must not issue a start.");
        Assert.AreEqual(0, fixture.Health.PredecessorVerificationCount);
        Assert.AreEqual(before, await fixture.InstalledFingerprintAsync());
    }

    [TestMethod]
    public async Task Rollback_restore_failure_returns_recoverable_phase_without_starting_service()
    {
        var phases = new List<UpdateTransactionPhase>();
        var service = new StartProbe();
        var engine = new OfflineUpdateTransactionEngine(new EmptyPreflight(), service, new ThrowingRestoreFiles(),
            new PredecessorRetainedHealth(), new MemoryJournal(phases));
        var journal = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", 1, new string('A', 64),
            2, new string('B', 64), UpdateTransactionPhase.ServiceStopped, "fedcba9876543210fedcba9876543210",
            new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await engine.RecoverAsync(journal, CancellationToken.None));

        Assert.AreEqual(0, service.StartCount);
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.RollbackRequired }, phases);
    }

    [DataTestMethod]
    [DataRow(0)]
    [DataRow(4)]
    [DataRow(8)]
    public async Task Partial_restore_failure_preserves_durable_rollback_required_and_retry_repairs(int replacementsBeforeFailure)
    {
        await using var fixture = await DurableFixture.CreateAsync();
        var files = new FailAfterCopiesThenRestore(fixture, replacementsBeforeFailure);
        var engine = fixture.CreateEngine(files);

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(0, fixture.Service.StartCount);
        Assert.AreEqual(0, fixture.Health.PredecessorVerificationCount);
        await fixture.AssertPartialRestoreAsync(replacementsBeforeFailure);

        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RolledBack);
        Assert.AreEqual(1, files.RealRestoreCount);
        Assert.AreEqual(1, fixture.Service.StartCount);
        Assert.AreEqual(1, fixture.Health.PredecessorVerificationCount);
        await fixture.AssertInstalledPredecessorAsync();
    }

    [TestMethod]
    public async Task Retry_reauthenticates_backup_before_repair()
    {
        await using var fixture = await DurableFixture.CreateAsync();
        var files = new FailAfterCopiesThenRestore(fixture, 4);
        var engine = fixture.CreateEngine(files);

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(0, fixture.Service.StartCount);
        Assert.AreEqual(0, files.RealRestoreAttemptCount);
        await fixture.TamperBackupAsync();
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(0, fixture.Service.StartCount);
        Assert.AreEqual(1, files.RealRestoreAttemptCount, "The retry must enter the real adapter and reject the newly tampered backup.");
        Assert.AreEqual(0, files.RealRestoreCount);
        await fixture.AssertPartialRestoreAsync(4);

        await fixture.RestoreBackupBytesAsync();
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RolledBack);
        Assert.AreEqual(2, files.RealRestoreAttemptCount);
        Assert.AreEqual(1, files.RealRestoreCount);
        Assert.AreEqual(1, fixture.Service.StartCount);
        Assert.AreEqual(1, fixture.Health.PredecessorVerificationCount);
        await fixture.AssertInstalledPredecessorAsync();
    }

    [TestMethod]
    public async Task Start_failure_after_completed_restore_preserves_rollback_required_for_retry()
    {
        await using var fixture = await DurableFixture.CreateAsync();
        fixture.Service.FailStartsRemaining = 1;
        var files = new FailAfterCopiesThenRestore(fixture, null);
        var engine = fixture.CreateEngine(files);

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(1, files.RealRestoreCount);
        Assert.AreEqual(1, fixture.Service.StartCount);
        Assert.AreEqual(0, fixture.Health.PredecessorVerificationCount);
        await fixture.AssertInstalledPredecessorAsync();

        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await fixture.RecoverAsync(engine));
        Assert.AreEqual(2, files.RealRestoreCount);
        Assert.AreEqual(2, fixture.Service.StartCount);
        Assert.AreEqual(1, fixture.Health.PredecessorVerificationCount);
    }

    [TestMethod]
    public async Task Predecessor_health_failure_preserves_rollback_required_for_retry()
    {
        await using var fixture = await DurableFixture.CreateAsync();
        fixture.Health.FailPredecessorVerificationRemaining = 1;
        var files = new FailAfterCopiesThenRestore(fixture, null);
        var engine = fixture.CreateEngine(files);

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(1, files.RealRestoreCount);
        Assert.AreEqual(1, fixture.Service.StartCount);
        Assert.AreEqual(1, fixture.Health.PredecessorVerificationCount);

        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await fixture.RecoverAsync(engine));
        Assert.AreEqual(2, files.RealRestoreCount);
        Assert.AreEqual(2, fixture.Health.PredecessorVerificationCount);
    }

    [DataTestMethod]
    [DataRow("partial", "target")]
    [DataRow("partial", "unavailable")]
    [DataRow("partial", "corrupt")]
    [DataRow("partial", "mismatch")]
    [DataRow("restart", "target")]
    [DataRow("restart", "unavailable")]
    [DataRow("restart", "corrupt")]
    [DataRow("restart", "mismatch")]
    [DataRow("health", "target")]
    [DataRow("health", "unavailable")]
    [DataRow("health", "corrupt")]
    [DataRow("health", "mismatch")]
    public async Task Blocking_policy_after_recoverable_rollback_failure_retains_durable_phase_without_side_effects(string failure, string policy)
    {
        await using var fixture = await DurableFixture.CreateAsync();
        var files = new FailAfterCopiesThenRestore(fixture, failure == "partial" ? 4 : null);
        if (failure == "restart") fixture.Service.FailStartsRemaining = 1;
        if (failure == "health") fixture.Health.FailPredecessorVerificationRemaining = 1;
        var engine = fixture.CreateEngine(files);

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        var attemptsBefore = files.RealRestoreAttemptCount;
        var restoresBefore = files.RealRestoreCount;
        var startsBefore = fixture.Service.StartCount;
        var guardsBefore = fixture.Service.GuardCount;
        var policyBefore = await fixture.WriteAndReadPolicyAsync(policy);

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await fixture.RecoverAsync(engine));

        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(attemptsBefore, files.RealRestoreAttemptCount);
        Assert.AreEqual(restoresBefore, files.RealRestoreCount);
        Assert.AreEqual(startsBefore, fixture.Service.StartCount);
        Assert.AreEqual(guardsBefore, fixture.Service.GuardCount, "Blocked policy must reject before querying service state.");
        CollectionAssert.AreEqual(policyBefore, await fixture.ReadPolicyBytesAsync());
    }

    [DataTestMethod]
    [DataRow("target")]
    [DataRow("unavailable")]
    [DataRow("mismatch")]
    public async Task Nonpredecessor_or_unavailable_policy_fails_closed_before_restore(string policy)
    {
        await using var fixture = await DurableFixture.CreateAsync();
        await fixture.WritePolicyAsync(policy);
        var files = new NeverRestoreFiles();
        var engine = fixture.CreateEngine(files);

        Assert.AreEqual(UpdateTransactionPhase.Failed, await fixture.RecoverAsync(engine));
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.Failed);
        Assert.AreEqual(0, files.RestoreCount);
        Assert.AreEqual(0, fixture.Service.StartCount);
    }

    [DataTestMethod]
    [DataRow(UpdateTransactionPhase.PolicyCommitted)]
    [DataRow(UpdateTransactionPhase.Completed)]
    public async Task Committed_or_completed_journal_never_restores(UpdateTransactionPhase phase)
    {
        await using var fixture = await DurableFixture.CreateAsync();
        await fixture.PersistThroughAsync(phase);
        await fixture.AssertDurablePhaseAsync(phase);
        await fixture.WritePolicyAsync("target");
        var files = new NeverRestoreFiles();
        var engine = fixture.CreateEngine(files);

        var result = await fixture.RecoverAsync(engine);

        Assert.AreEqual(UpdateTransactionPhase.Completed, result);
        await fixture.AssertDurablePhaseAsync(UpdateTransactionPhase.Completed);
        Assert.AreEqual(0, files.RestoreCount);
        Assert.AreEqual(0, fixture.Service.StartCount);
    }

    private sealed class DurableFixture : IAsyncDisposable
    {
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly Dictionary<string, byte[]> _backupBytes = new(StringComparer.Ordinal);
        private readonly Dictionary<string, byte[]> _targetBytes = new(StringComparer.Ordinal);
        private DurableFixture()
        {
            Storage = new OfflineUpdateStorage(Updates, Installed, applyAcls: false, WindowsOfflineUpdateFileOperations.Instance);
            Policy = new ReleasePolicyStore(Root, applyAcls: false);
            Verifier = new OfflineReleaseVerifier(_metadataKey.ExportSubjectPublicKeyInfo(), _manifestKey.ExportSubjectPublicKeyInfo());
            Journals = new UpdateTransactionJournalStore(Root, applyAcls: false);
            Service = new StartProbe();
            Health = new DurablePolicyHealth(Policy);
            RealFiles = new FixedOfflineUpdateReleaseFiles(Verifier, Policy, Storage, Service);
        }

        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-task019-" + Guid.NewGuid().ToString("N"));
        private string Updates => Path.Combine(Root, "Updates");
        internal string Installed => Path.Combine(Root, "Installed");
        internal string Backup => Storage.Backup("fedcba9876543210fedcba9876543210");
        internal OfflineUpdateStorage Storage { get; }
        internal ReleasePolicyStore Policy { get; }
        internal OfflineReleaseVerifier Verifier { get; }
        internal UpdateTransactionJournalStore Journals { get; }
        internal StartProbe Service { get; }
        internal DurablePolicyHealth Health { get; }
        internal FixedOfflineUpdateReleaseFiles RealFiles { get; }
        internal UpdateTransactionJournal Journal { get; private set; } = null!;

        internal static async Task<DurableFixture> CreateAsync(UpdateTransactionPhase initialPhase = UpdateTransactionPhase.ServiceStopped)
        {
            var fixture = new DurableFixture();
            await fixture.WriteReleaseAsync(fixture.Installed, 1, "predecessor");
            var predecessor = await fixture.Verifier.VerifyChainAsync(fixture.Installed, CancellationToken.None);
            Assert.AreEqual(ReleasePolicyDecision.BootstrapAccepted, await fixture.Policy.BootstrapVerifiedSequenceOneAsync(
                VerifiedRelease.FromVerifiedEvidence(predecessor.Sequence, predecessor.ManifestSha256), CancellationToken.None));
            await fixture.Storage.CopyInstalledToBackupAsync("fedcba9876543210fedcba9876543210", CancellationToken.None);
            foreach (var name in FixedServiceReleaseFiles.AllNames)
                fixture._backupBytes.Add(name, await File.ReadAllBytesAsync(Path.Combine(fixture.Backup, name)));
            await fixture.WriteReleaseAsync(fixture.Installed, 2, "target");
            foreach (var name in FixedServiceReleaseFiles.AllNames)
                fixture._targetBytes.Add(name, await File.ReadAllBytesAsync(Path.Combine(fixture.Installed, name)));
            var target = await fixture.Verifier.VerifyChainAsync(fixture.Installed, CancellationToken.None);
            fixture.Journal = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", predecessor.Sequence,
                predecessor.ManifestSha256, target.Sequence, target.ManifestSha256, UpdateTransactionPhase.Prepared,
                "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));
            Directory.CreateDirectory(Path.Combine(fixture.Updates, "Transactions"));
            await File.WriteAllBytesAsync(Path.Combine(fixture.Updates, UpdateTransactionJournalStore.LockFileName), Array.Empty<byte>());
            await fixture.PersistThroughAsync(initialPhase);
            return fixture;
        }

        internal OfflineUpdateTransactionEngine CreateEngine(IOfflineUpdateReleaseFiles files) =>
            new(new EmptyPreflight(), Service, files, Health, new JournalAdapter(Journals));

        internal async Task<UpdateTransactionPhase> RecoverAsync(OfflineUpdateTransactionEngine engine, CancellationToken token = default)
        {
            var read = await Journals.ReadAsync(CancellationToken.None);
            Assert.AreEqual(JournalReadState.Present, read.State);
            Assert.IsNotNull(read.Journal);
            return await engine.RecoverAsync(read.Journal, token);
        }

        internal async Task PersistThroughAsync(UpdateTransactionPhase phase)
        {
            var path = new[] { UpdateTransactionPhase.Prepared, UpdateTransactionPhase.Verified, UpdateTransactionPhase.ServiceStopped,
                UpdateTransactionPhase.Replaced, UpdateTransactionPhase.Restarted, UpdateTransactionPhase.PostVerified,
                UpdateTransactionPhase.PolicyCommitted, UpdateTransactionPhase.Completed };
            var read = await Journals.ReadAsync(CancellationToken.None);
            Assert.IsTrue(read.State is JournalReadState.Present or JournalReadState.Absent);
            var current = read.State == JournalReadState.Present
                ? read.Journal!
                : Journal;
            if (read.State != JournalReadState.Present)
            {
                Assert.AreEqual(UpdateTransactionPhase.Prepared, current.Phase);
                await Journals.PersistAsync(current, CancellationToken.None);
            }
            var currentIndex = Array.IndexOf(path, current.Phase);
            var targetIndex = Array.IndexOf(path, phase);
            Assert.IsTrue(currentIndex >= 0 && targetIndex >= currentIndex, "Fixture setup must advance along the legal forward transition path.");
            for (var index = currentIndex + 1; index <= targetIndex; index++)
            {
                current = UpdateTransactionStateMachine.Transition(current, path[index], current.UpdatedAtUtc.AddSeconds(1));
                await Journals.PersistAsync(current, CancellationToken.None);
            }
            Journal = current;
        }

        internal async Task AssertDurablePhaseAsync(UpdateTransactionPhase phase)
        {
            var read = await Journals.ReadAsync(CancellationToken.None);
            Assert.AreEqual(JournalReadState.Present, read.State);
            Assert.AreEqual(phase, read.Journal!.Phase);
        }

        internal async Task AssertPartialRestoreAsync(int replacements)
        {
            for (var index = 0; index < FixedServiceReleaseFiles.AllNames.Length; index++)
            {
                var actual = await File.ReadAllBytesAsync(Path.Combine(Installed, FixedServiceReleaseFiles.AllNames[index]));
                CollectionAssert.AreEqual(index < replacements ? _backupBytes[FixedServiceReleaseFiles.AllNames[index]] :
                    _targetBytes[FixedServiceReleaseFiles.AllNames[index]], actual);
            }
        }

        internal async Task<string> InstalledFingerprintAsync()
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var name in FixedServiceReleaseFiles.AllNames)
                hash.AppendData(await File.ReadAllBytesAsync(Path.Combine(Installed, name)));
            return Convert.ToHexString(hash.GetHashAndReset());
        }

        internal async Task AssertInstalledPredecessorAsync()
        {
            foreach (var name in FixedServiceReleaseFiles.AllNames)
                CollectionAssert.AreEqual(_backupBytes[name], await File.ReadAllBytesAsync(Path.Combine(Installed, name)));
            var verified = await Verifier.VerifyChainAsync(Installed, CancellationToken.None);
            Assert.AreEqual(Journal.PriorReleaseSequence, verified.Sequence);
            Assert.AreEqual(Journal.PriorManifestSha256, verified.ManifestSha256);
        }

        internal async Task TamperBackupAsync() =>
            await File.AppendAllTextAsync(Path.Combine(Backup, FixedServiceReleaseFiles.Components[0].Name), "tamper");

        internal async Task RestoreBackupBytesAsync()
        {
            foreach (var (name, bytes) in _backupBytes)
                await File.WriteAllBytesAsync(Path.Combine(Backup, name), bytes);
        }

        internal async Task WritePolicyAsync(string kind)
        {
            var path = Path.Combine(Root, "ReleasePolicy", ReleasePolicyStore.PolicyFileName);
            if (kind == "unavailable") { File.Delete(path); return; }
            if (kind == "corrupt") { await File.WriteAllTextAsync(path, "not-a-policy"); return; }
            var record = kind == "target" ? new ReleasePolicyRecord(Journal.TargetReleaseSequence, Journal.TargetManifestSha256) :
                new ReleasePolicyRecord(99, new string('A', 64));
            await File.WriteAllBytesAsync(path, ReleasePolicyCodec.Serialize(record));
        }

        internal async Task<byte[]> WriteAndReadPolicyAsync(string kind)
        {
            await WritePolicyAsync(kind);
            return await ReadPolicyBytesAsync();
        }

        internal async Task<byte[]> ReadPolicyBytesAsync()
        {
            var path = Path.Combine(Root, "ReleasePolicy", ReleasePolicyStore.PolicyFileName);
            return File.Exists(path) ? await File.ReadAllBytesAsync(path) : [];
        }

        private async Task WriteReleaseAsync(string root, ulong sequence, string marker)
        {
            Directory.CreateDirectory(root);
            var hashes = new Dictionary<TrustedManifestComponent, string>();
            foreach (var (component, name) in FixedServiceReleaseFiles.Components)
            {
                await File.WriteAllTextAsync(Path.Combine(root, name), marker + ":" + name);
                hashes.Add(component, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(root, name)))));
            }
            var manifest = TrustedManifestCodec.CreateFile("0.1.0", hashes, _manifestKey);
            await File.WriteAllBytesAsync(Path.Combine(root, "Vantrel.Security.TrustedManifest"), manifest);
            await File.WriteAllBytesAsync(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"), ReleaseMetadataCodec.CreateFile(sequence,
                Convert.ToHexString(SHA256.HashData(manifest)), "0.1.0", new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero), _metadataKey));
        }

        public ValueTask DisposeAsync()
        {
            _metadataKey.Dispose(); _manifestKey.Dispose();
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FailAfterCopiesThenRestore(DurableFixture fixture, int? copiesBeforeFailure) : IOfflineUpdateReleaseFiles
    {
        private bool _failOnce = copiesBeforeFailure is not null;
        internal int RealRestoreAttemptCount;
        internal int RealRestoreCount;
        public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public async Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            if (_failOnce)
            {
                _failOnce = false;
                foreach (var name in FixedServiceReleaseFiles.AllNames.Take(copiesBeforeFailure!.Value))
                    File.Copy(Path.Combine(fixture.Backup, name), Path.Combine(fixture.Installed, name), overwrite: true);
                throw new IOException("Test-only rollback interruption after fixed-file replacements.");
            }
            RealRestoreAttemptCount++;
            await fixture.RealFiles.RestoreVerifiedPredecessorAsync(journal, token);
            RealRestoreCount++;
        }
    }

    private sealed class NeverRestoreFiles : IOfflineUpdateReleaseFiles
    {
        internal int RestoreCount;
        public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { RestoreCount++; return Task.CompletedTask; }
    }
    private sealed class ThrowingRestoreFiles : IOfflineUpdateReleaseFiles
    {
        public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) => throw new IOException("Test-only restore failure.");
    }

    private sealed class StartProbe : IOfflineUpdateServiceControl
    {
        internal Func<CancellationToken, Task> StoppedGuard = token => { token.ThrowIfCancellationRequested(); return Task.CompletedTask; };
        internal int GuardCount;
        internal Action? AfterStart;
        public Task RequireStoppedAsync(CancellationToken token) { GuardCount++; return StoppedGuard(token); }
        internal int StartCount;
        internal int FailStartsRemaining;
        public Task StopAsync(CancellationToken token) => Task.CompletedTask;
        public Task StartAsync(CancellationToken token)
        {
            StartCount++;
            if (FailStartsRemaining-- > 0) throw new IOException("Test-only restart failure.");
            AfterStart?.Invoke();
            return Task.CompletedTask;
        }
    }

    private sealed class DurablePolicyHealth(ReleasePolicyStore policy) : IOfflineUpdateHealth
    {
        internal Action? AfterPolicyRead;
        internal int PredecessorVerificationCount;
        internal int FailPredecessorVerificationRemaining;
        internal int FailTargetVerificationRemaining;
        public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            if (FailTargetVerificationRemaining-- > 0) throw new IOException("Test-only target health failure.");
            return Task.CompletedTask;
        }
        public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            PredecessorVerificationCount++;
            if (FailPredecessorVerificationRemaining-- > 0) throw new IOException("Test-only predecessor health failure.");
            return Task.CompletedTask;
        }
        public async Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            var durable = await policy.ReadDurableAsync(token);
            AfterPolicyRead?.Invoke();
            if (durable.Failure != ReleasePolicyParseFailure.None || durable.Record is null) return PolicyCommitObservation.Unavailable;
            if (durable.Record.HighestAcceptedReleaseSequence == journal.TargetReleaseSequence &&
                string.Equals(durable.Record.AcceptedManifestSha256, journal.TargetManifestSha256, StringComparison.Ordinal)) return PolicyCommitObservation.TargetCommitted;
            return durable.Record.HighestAcceptedReleaseSequence == journal.PriorReleaseSequence &&
                string.Equals(durable.Record.AcceptedManifestSha256, journal.PriorManifestSha256, StringComparison.Ordinal)
                ? PolicyCommitObservation.PredecessorRetained : PolicyCommitObservation.Unavailable;
        }
    }

    private sealed class EmptyPreflight : IOfflineUpdatePreflight
    {
        public Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
    }
    private sealed class PredecessorRetainedHealth : IOfflineUpdateHealth
    {
        public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token) =>
            Task.FromResult(PolicyCommitObservation.PredecessorRetained);
    }
    private sealed class MemoryJournal(List<UpdateTransactionPhase> phases) : IOfflineUpdateJournal
    {
        public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token) { phases.Add(journal.Phase); return Task.CompletedTask; }
    }
    private sealed class JournalAdapter(UpdateTransactionJournalStore store) : IOfflineUpdateJournal
    {
        public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token) => store.PersistAsync(journal, token);
    }
}
