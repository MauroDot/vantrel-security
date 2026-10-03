using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass, DoNotParallelize]
public sealed class PreReplacementRecoveryClosureTests
{
    private const string Prior = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string Target = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string TransactionId = "0123456789abcdef0123456789abcdef";
    private const string BackupId = "fedcba9876543210fedcba9876543210";

    [TestMethod]
    public async Task Prepared_recovery_closes_without_service_file_or_policy_actions_and_terminal_retirement_restores_admission()
    {
        await using var scope = new Scope(); var journal = await scope.PersistAsync(UpdateTransactionPhase.Prepared);
        var probes = new Probes(); var engine = scope.Engine(probes);

        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.RecoverAsync(journal, CancellationToken.None));
        await scope.AssertPhaseAsync(UpdateTransactionPhase.Failed);
        probes.AssertNoTransactionSideEffects();

        using var owner = scope.OwnerLock().TryAcquire(CancellationToken.None);
        Assert.IsNotNull(owner);
        var retired = await scope.Store.TryRetireTerminalTransactionAsync((await scope.ReadAsync())!, owner!,
            (_, _) => Task.CompletedTask, CancellationToken.None);
        Assert.AreEqual(TerminalTransactionRetirementResult.Retired, retired);
        var admissions = 0;
        await OfflineUpdateAdministrator.WithValidatedJournalAsync(scope.Store, current =>
        {
            Assert.IsNull(current); admissions++; return Task.FromResult(UpdateTransactionPhase.Prepared);
        }, CancellationToken.None);
        Assert.AreEqual(1, admissions);
    }

    [TestMethod]
    public async Task Verified_running_authenticated_predecessor_closes_without_service_or_file_mutation()
    {
        await using var scope = new Scope(); var journal = await scope.PersistAsync(UpdateTransactionPhase.Verified);
        var probes = new Probes { State = OfflineUpdateServiceState.Running }; var engine = scope.Engine(probes);

        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.RecoverAsync(journal, CancellationToken.None));
        await scope.AssertPhaseAsync(UpdateTransactionPhase.Failed);
        Assert.AreEqual(1, probes.PredecessorAuthenticationCount); Assert.AreEqual(1, probes.StateQueries);
        probes.AssertNoTransactionSideEffects();
    }

    [TestMethod]
    public async Task Verified_stopped_authenticated_predecessor_restarts_once_verifies_health_and_closes()
    {
        await using var scope = new Scope(); var journal = await scope.PersistAsync(UpdateTransactionPhase.Verified);
        var probes = new Probes { State = OfflineUpdateServiceState.Stopped }; var engine = scope.Engine(probes);

        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.RecoverAsync(journal, CancellationToken.None));
        await scope.AssertPhaseAsync(UpdateTransactionPhase.Failed);
        Assert.AreEqual(1, probes.StartCount); Assert.AreEqual(1, probes.PredecessorHealthCount); Assert.AreEqual(1, probes.PredecessorAuthenticationCount);
        Assert.AreEqual(0, probes.StopCount); Assert.AreEqual(0, probes.ReplaceCount); Assert.AreEqual(0, probes.RestoreCount); Assert.AreEqual(0, probes.PolicyReads);
    }

    [TestMethod]
    public async Task Verified_stop_before_persist_window_restarts_predecessor_and_closes()
    {
        await using var scope = new Scope(); var journal = await scope.PersistAsync(UpdateTransactionPhase.Verified);
        var probes = new Probes { State = OfflineUpdateServiceState.Stopped }; var engine = scope.Engine(probes);

        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.RecoverAsync(journal, CancellationToken.None));
        await scope.AssertPhaseAsync(UpdateTransactionPhase.Failed);
        Assert.AreEqual(1, probes.StartCount); Assert.AreEqual(1, probes.PredecessorHealthCount); Assert.AreEqual(0, probes.ReplaceCount);
    }

    [DataTestMethod]
    [DataRow("start")]
    [DataRow("health")]
    [DataRow("authentication-running")]
    [DataRow("authentication-stopped")]
    [DataRow("pending")]
    [DataRow("unavailable")]
    public async Task Verified_unresolvable_or_failed_predecessor_recovery_moves_to_rollback_required_without_target_work(string failure)
    {
        await using var scope = new Scope(); var journal = await scope.PersistAsync(UpdateTransactionPhase.Verified);
        var probes = new Probes
        {
            State = failure == "authentication-running" ? OfflineUpdateServiceState.Running :
                failure is "pending" or "unavailable" ? OfflineUpdateServiceState.Unavailable : OfflineUpdateServiceState.Stopped
        };
        if (failure == "start") probes.StartAction = _ => Task.FromException(new IOException("start"));
        if (failure == "health") probes.HealthAction = _ => Task.FromException(new IOException("health"));
        if (failure.StartsWith("authentication", StringComparison.Ordinal)) probes.AuthenticateAction = _ => Task.FromException(new IOException("tampered"));

        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await scope.Engine(probes).RecoverAsync(journal, CancellationToken.None));
        await scope.AssertPhaseAsync(UpdateTransactionPhase.RollbackRequired);
        Assert.AreEqual(0, probes.ReplaceCount); Assert.AreEqual(0, probes.RestoreCount); Assert.AreEqual(0, probes.StopCount); Assert.AreEqual(0, probes.PolicyReads);

        using var owner = scope.OwnerLock().TryAcquire(CancellationToken.None);
        Assert.IsNotNull(owner); var retireCalls = 0;
        Assert.AreEqual(TerminalTransactionRetirementResult.NotEligible, await scope.Store.TryRetireTerminalTransactionAsync((await scope.ReadAsync())!, owner!,
            (_, _) => { retireCalls++; return Task.CompletedTask; }, CancellationToken.None));
        Assert.AreEqual(0, retireCalls);
    }

    [DataTestMethod]
    [DataRow("state")]
    [DataRow("authentication")]
    [DataRow("start")]
    [DataRow("health")]
    public async Task Cancellation_during_verified_recovery_retains_verified(string point)
    {
        await using var scope = new Scope(); var journal = await scope.PersistAsync(UpdateTransactionPhase.Verified);
        using var cancellation = new CancellationTokenSource(); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var probes = new Probes { State = OfflineUpdateServiceState.Stopped };
        if (point == "state") probes.StateAction = async token => { entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); return OfflineUpdateServiceState.Stopped; };
        if (point == "authentication") probes.AuthenticateAction = async token => { entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); };
        if (point == "start") probes.StartAction = async token => { entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); };
        if (point == "health") probes.HealthAction = async token => { entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); };

        var recovery = scope.Engine(probes).RecoverAsync(journal, cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); cancellation.Cancel();
        await Assert.ThrowsExceptionAsync<TaskCanceledException>(() => recovery);
        await scope.AssertPhaseAsync(UpdateTransactionPhase.Verified);
        Assert.AreEqual(0, probes.ReplaceCount); Assert.AreEqual(0, probes.RestoreCount);
    }

    [TestMethod]
    public async Task Cancellation_immediately_before_prepared_finalization_retains_prepared()
    {
        await using var scope = new Scope(); var journal = await scope.PersistAsync(UpdateTransactionPhase.Prepared);
        using var cancellation = new CancellationTokenSource();
        var adapter = new JournalAdapter(scope.Store, beforeExact: async (current, token) =>
        {
            var exact = await scope.Store.IsExactCurrentAsync(current, token);
            cancellation.Cancel(); return exact;
        });

        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => scope.Engine(new Probes(), adapter).RecoverAsync(journal, cancellation.Token));
        await scope.AssertPhaseAsync(UpdateTransactionPhase.Prepared);
    }

    [TestMethod]
    public async Task Cancellation_immediately_before_successful_verified_finalization_retains_verified()
    {
        await using var scope = new Scope(); var journal = await scope.PersistAsync(UpdateTransactionPhase.Verified);
        using var cancellation = new CancellationTokenSource();
        var probes = new Probes
        {
            State = OfflineUpdateServiceState.Running,
            AuthenticateAction = _ => { cancellation.Cancel(); return Task.CompletedTask; }
        };

        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => scope.Engine(probes).RecoverAsync(journal, cancellation.Token));
        await scope.AssertPhaseAsync(UpdateTransactionPhase.Verified);
    }

    [TestMethod]
    public async Task Cancellation_after_final_precommit_check_commits_failed_without_surface_cancellation()
    {
        await using var scope = new Scope(); var journal = await scope.PersistAsync(UpdateTransactionPhase.Prepared);
        using var cancellation = new CancellationTokenSource();
        var adapter = new JournalAdapter(scope.Store, beforePersist: (next, token) =>
        {
            if (next.Phase == UpdateTransactionPhase.Failed) { Assert.IsFalse(token.CanBeCanceled); cancellation.Cancel(); }
            return Task.CompletedTask;
        });

        Assert.AreEqual(UpdateTransactionPhase.Failed, await scope.Engine(new Probes(), adapter).RecoverAsync(journal, cancellation.Token));
        Assert.IsTrue(cancellation.IsCancellationRequested); await scope.AssertPhaseAsync(UpdateTransactionPhase.Failed);
    }

    [TestMethod]
    public async Task Cancellation_after_journal_replacement_does_not_interrupt_terminal_readback()
    {
        using var cancellation = new CancellationTokenSource(); var arm = false;
        await using var scope = new Scope(token =>
        {
            if (arm) { Assert.IsFalse(token.CanBeCanceled); cancellation.Cancel(); }
            return Task.CompletedTask;
        });
        var journal = await scope.PersistAsync(UpdateTransactionPhase.Prepared); arm = true;

        Assert.AreEqual(UpdateTransactionPhase.Failed, await scope.Engine(new Probes()).RecoverAsync(journal, cancellation.Token));
        Assert.IsTrue(cancellation.IsCancellationRequested); await scope.AssertPhaseAsync(UpdateTransactionPhase.Failed);
    }

    [TestMethod]
    public async Task Exact_journal_recheck_declines_stale_verified_view_without_service_or_file_actions()
    {
        await using var scope = new Scope(); var current = await scope.PersistAsync(UpdateTransactionPhase.Verified);
        var stale = current with { BackupId = "11111111111111111111111111111111" };
        var probes = new Probes { State = OfflineUpdateServiceState.Running };

        Assert.AreEqual(UpdateTransactionPhase.Verified, await scope.Engine(probes).RecoverAsync(stale, CancellationToken.None));
        await scope.AssertPhaseAsync(UpdateTransactionPhase.Verified);
        probes.AssertNoTransactionSideEffects();
    }

    private static UpdateTransactionJournal Journal(UpdateTransactionPhase phase) => new(TransactionId, 1, Prior, 2, Target, phase, BackupId,
        new DateTimeOffset(2026, 10, 3, 0, 0, 0, TimeSpan.Zero));

    private sealed class Scope : IAsyncDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-preplacement-recovery-" + Guid.NewGuid().ToString("N"));
        internal UpdateTransactionJournalStore Store { get; }
        internal Scope(Func<CancellationToken, Task>? afterJournalReplacementForTest = null)
        {
            var updates = Path.Combine(Root, "Updates"); var transactions = Path.Combine(updates, "Transactions");
            Directory.CreateDirectory(transactions); File.WriteAllBytes(Path.Combine(updates, UpdateTransactionJournalStore.LockFileName), []);
            File.WriteAllBytes(Path.Combine(updates, OfflineUpdateOwnershipLock.OwnerLockFileName), []);
            Store = new UpdateTransactionJournalStore(Root, applyAcls: false, afterJournalReplacementForTest: afterJournalReplacementForTest);
        }
        internal OfflineUpdateOwnershipLock OwnerLock() => new(Root, applyAcls: false);
        internal async Task<UpdateTransactionJournal> PersistAsync(UpdateTransactionPhase phase)
        {
            var current = Journal(UpdateTransactionPhase.Prepared); await Store.PersistAsync(current, CancellationToken.None);
            if (phase != UpdateTransactionPhase.Prepared)
            {
                current = UpdateTransactionStateMachine.Transition(current, phase, current.UpdatedAtUtc.AddSeconds(1));
                await Store.PersistAsync(current, CancellationToken.None);
            }
            return current;
        }
        internal async Task<UpdateTransactionJournal?> ReadAsync() => (await Store.ReadAsync(CancellationToken.None)).Journal;
        internal async Task AssertPhaseAsync(UpdateTransactionPhase expected) => Assert.AreEqual(expected, (await ReadAsync())!.Phase);
        internal OfflineUpdateTransactionEngine Engine(Probes probes, IOfflineUpdateJournal? journal = null) => new(probes, probes, probes, probes, journal ?? new JournalAdapter(Store));
        public ValueTask DisposeAsync() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); return ValueTask.CompletedTask; }
    }

    private sealed class JournalAdapter(UpdateTransactionJournalStore store,
        Func<UpdateTransactionJournal, CancellationToken, Task>? beforePersist = null,
        Func<UpdateTransactionJournal, CancellationToken, Task<bool>>? beforeExact = null) : IOfflineUpdateJournal
    {
        public async Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            if (beforePersist is not null) await beforePersist(journal, token);
            await store.PersistAsync(journal, token);
        }
        public Task<bool> IsExactCurrentAsync(UpdateTransactionJournal journal, CancellationToken token) =>
            beforeExact is null ? store.IsExactCurrentAsync(journal, token) : beforeExact(journal, token);
    }

    private sealed class Probes : IOfflineUpdatePreflight, IOfflineUpdateServiceControl, IOfflineUpdateReleaseFiles, IOfflineUpdateHealth
    {
        internal OfflineUpdateServiceState State;
        internal int StateQueries, PredecessorAuthenticationCount, StopCount, StartCount, ReplaceCount, RestoreCount, PredecessorHealthCount, PolicyReads;
        internal Func<CancellationToken, Task<OfflineUpdateServiceState>>? StateAction;
        internal Func<CancellationToken, Task>? AuthenticateAction, StartAction, HealthAction;
        public Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public async Task VerifyInstalledPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            PredecessorAuthenticationCount++; if (AuthenticateAction is not null) await AuthenticateAction(token);
        }
        public async Task<OfflineUpdateServiceState> InspectStateAsync(CancellationToken token)
        {
            StateQueries++; return StateAction is null ? State : await StateAction(token);
        }
        public Task StopAsync(CancellationToken token) { StopCount++; return Task.CompletedTask; }
        public async Task StartAsync(CancellationToken token) { StartCount++; if (StartAction is not null) await StartAction(token); }
        public Task RequireStoppedAsync(CancellationToken token) => Task.CompletedTask;
        public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) { ReplaceCount++; return Task.CompletedTask; }
        public Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { RestoreCount++; return Task.CompletedTask; }
        public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public async Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            PredecessorHealthCount++; if (HealthAction is not null) await HealthAction(token);
        }
        public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            PolicyReads++; return Task.FromResult(PolicyCommitObservation.PredecessorRetained);
        }
        internal void AssertNoTransactionSideEffects()
        {
            Assert.AreEqual(0, StopCount); Assert.AreEqual(0, StartCount); Assert.AreEqual(0, ReplaceCount); Assert.AreEqual(0, RestoreCount);
            Assert.AreEqual(0, PredecessorHealthCount); Assert.AreEqual(0, PolicyReads);
        }
    }
}
