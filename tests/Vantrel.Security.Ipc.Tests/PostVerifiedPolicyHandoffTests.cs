using Microsoft.Extensions.Logging.Abstractions;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass, DoNotParallelize]
public sealed class PostVerifiedPolicyHandoffTests
{
    private const string Prior = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string Target = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string Nonce = "0123456789abcdef0123456789abcdef";

    [TestMethod]
    public async Task Worker_handoff_wins_and_stale_elevated_recovery_cannot_restore()
    {
        await using var scope = new Scope(); var store = scope.Store(); var policy = await scope.PolicyWithPriorAsync();
        var postVerified = await PersistThroughAsync(store, UpdateTransactionPhase.PostVerified);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var worker = Worker(store, policy, async token =>
        {
            entered.TrySetResult(); await release.Task.WaitAsync(token); return Provenance(postVerified);
        });

        var handoff = worker.RunOnceAsync(CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var health = new PredecessorHealth(); var files = new CountingFiles();
        var staleRecovery = Engine(store, files, health).RecoverAsync(postVerified, CancellationToken.None);
        await health.SecondPolicyObservation.Task.WaitAsync(TimeSpan.FromSeconds(5));
        release.TrySetResult();

        Assert.AreEqual(PostVerifiedPolicyHandoffResult.Completed, await handoff);
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => staleRecovery);
        Assert.AreEqual(0, files.RestoreCount);
        Assert.AreEqual(new ReleasePolicyRecord(2, Target), (await policy.ReadDurableAsync(CancellationToken.None)).Record);
        Assert.AreEqual(UpdateTransactionPhase.PolicyCommitted, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [TestMethod]
    public async Task Elevated_transition_wins_and_stale_phase_or_identity_declines_without_policy_work()
    {
        await using var scope = new Scope(); var store = scope.Store(); var policy = await scope.PolicyWithPriorAsync();
        var postVerified = await PersistThroughAsync(store, UpdateTransactionPhase.PostVerified);
        var calls = 0;
        var wrongIdentity = postVerified with { BackupId = "11111111111111111111111111111111" };
        var result = await store.TryCompletePostVerifiedPolicyHandoffAsync(wrongIdentity, (_, _) =>
        {
            calls++; return Task.FromResult(true);
        }, CancellationToken.None);
        Assert.AreEqual(PostVerifiedPolicyHandoffResult.NotEligible, result); Assert.AreEqual(0, calls);
        var rollback = UpdateTransactionStateMachine.Transition(postVerified, UpdateTransactionPhase.RollbackRequired, postVerified.UpdatedAtUtc.AddSeconds(1));
        await store.PersistAsync(rollback, CancellationToken.None);
        result = await store.TryCompletePostVerifiedPolicyHandoffAsync(postVerified, (_, _) =>
        {
            calls++; return Task.FromResult(true);
        }, CancellationToken.None);
        Assert.AreEqual(PostVerifiedPolicyHandoffResult.NotEligible, result); Assert.AreEqual(0, calls);
        Assert.AreEqual(new ReleasePolicyRecord(1, Prior), (await policy.ReadDurableAsync(CancellationToken.None)).Record);

        var provenanceCalls = 0;
        using var worker = Worker(store, policy, _ =>
        {
            provenanceCalls++; return Task.FromResult(Provenance(postVerified));
        });
        Assert.AreEqual(PostVerifiedPolicyHandoffResult.NotEligible, await worker.RunOnceAsync(CancellationToken.None));
        Assert.AreEqual(0, provenanceCalls);
    }

    [TestMethod]
    public async Task Unverified_target_declines_before_any_policy_write()
    {
        await using var scope = new Scope(); var store = scope.Store(); var policy = await scope.PolicyWithPriorAsync();
        var postVerified = await PersistThroughAsync(store, UpdateTransactionPhase.PostVerified);
        var calls = 0;
        using var worker = Worker(store, policy, _ =>
        {
            calls++; return Task.FromResult(Provenance(postVerified) with { ReleaseSequence = postVerified.TargetReleaseSequence + 1 });
        });
        Assert.AreEqual(PostVerifiedPolicyHandoffResult.NotEligible, await worker.RunOnceAsync(CancellationToken.None));
        Assert.AreEqual(1, calls);
        Assert.AreEqual(UpdateTransactionPhase.PostVerified, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.AreEqual(new ReleasePolicyRecord(1, Prior), (await policy.ReadDurableAsync(CancellationToken.None)).Record);
    }

    [TestMethod]
    public async Task Cancellation_after_durable_policy_commit_leaves_postverified_and_retry_completes_forward()
    {
        await using var scope = new Scope(); var store = scope.Store(); var policy = await scope.PolicyWithPriorAsync();
        var postVerified = await PersistThroughAsync(store, UpdateTransactionPhase.PostVerified);
        using var cancellation = new CancellationTokenSource();
        await Assert.ThrowsExceptionAsync<TaskCanceledException>(() => store.TryCompletePostVerifiedPolicyHandoffAsync(postVerified,
            async (journal, token) =>
            {
                Assert.AreEqual(ReleasePolicyDecision.HigherRelease, await policy.CommitVerifiedInstalledReleaseAsync(
                    VerifiedRelease.FromVerifiedEvidence(journal.TargetReleaseSequence, journal.TargetManifestSha256), token));
                cancellation.Cancel();
                return true;
            }, cancellation.Token));

        Assert.AreEqual(UpdateTransactionPhase.PostVerified, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.AreEqual(new ReleasePolicyRecord(2, Target), (await policy.ReadDurableAsync(CancellationToken.None)).Record);
        using var worker = Worker(store, policy, _ => Task.FromResult(Provenance(postVerified)));
        Assert.AreEqual(PostVerifiedPolicyHandoffResult.Completed, await worker.RunOnceAsync(CancellationToken.None));
        var files = new CountingFiles();
        Assert.AreEqual(UpdateTransactionPhase.Completed, await Engine(store, files, new DurablePolicyHealth(policy)).RecoverAsync(
            (await store.ReadAsync(CancellationToken.None)).Journal!, CancellationToken.None));
        Assert.AreEqual(0, files.RestoreCount);
    }

    [TestMethod]
    public async Task Journal_write_failure_after_target_policy_commit_preserves_high_water_and_retry_completes()
    {
        await using var scope = new Scope(); var store = scope.Store(); var policy = await scope.PolicyWithPriorAsync();
        var postVerified = await PersistThroughAsync(store, UpdateTransactionPhase.PostVerified);
        using (new FileStream(scope.JournalPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            await Assert.ThrowsExceptionAsync<IOException>(() => store.TryCompletePostVerifiedPolicyHandoffAsync(postVerified,
                async (journal, token) =>
                {
                    var decision = await policy.CommitVerifiedInstalledReleaseAsync(
                        VerifiedRelease.FromVerifiedEvidence(journal.TargetReleaseSequence, journal.TargetManifestSha256), token);
                    return decision is ReleasePolicyDecision.HigherRelease or ReleasePolicyDecision.SameAcceptedRelease;
                }, CancellationToken.None));
        }
        Assert.AreEqual(UpdateTransactionPhase.PostVerified, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.AreEqual(new ReleasePolicyRecord(2, Target), (await policy.ReadDurableAsync(CancellationToken.None)).Record);
        using var worker = Worker(store, policy, _ => Task.FromResult(Provenance(postVerified)));
        Assert.AreEqual(PostVerifiedPolicyHandoffResult.Completed, await worker.RunOnceAsync(CancellationToken.None));
        Assert.AreEqual(UpdateTransactionPhase.PolicyCommitted, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [TestMethod]
    public async Task Owner_held_authorized_and_consumed_recovery_keeps_policy_worker_inactive_without_deadlock()
    {
        await using var scope = new Scope(); var store = scope.Store(); var policy = await scope.PolicyWithPriorAsync();
        var rollback = await PersistThroughAsync(store, UpdateTransactionPhase.RollbackRequired);
        var authorized = UpdateTransactionStateMachine.Transition(rollback with { RecoveryStartNonce = Nonce },
            UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(1));
        await store.PersistAsync(authorized, CancellationToken.None);
        using var owner = scope.OwnerLock().TryAcquire(CancellationToken.None);
        Assert.IsNotNull(owner);
        var lease = await store.TryConsumeRecoveryStartLeaseAsync(Nonce, CancellationToken.None);
        Assert.IsNotNull(lease);
        var provenanceCalls = 0;
        using var worker = Worker(store, policy, _ =>
        {
            provenanceCalls++; return Task.FromResult(Provenance(authorized));
        });
        Assert.AreEqual(PostVerifiedPolicyHandoffResult.NotEligible, await worker.RunOnceAsync(CancellationToken.None));
        Assert.AreEqual(0, provenanceCalls);
        await store.RevokeConsumedRecoveryStartAsync(lease!, CancellationToken.None);
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, (await store.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.AreEqual(new ReleasePolicyRecord(1, Prior), (await policy.ReadDurableAsync(CancellationToken.None)).Record);
    }

    [TestMethod]
    public async Task Consumed_verification_and_policy_worker_leave_one_rollback_transition_without_policy_mutation()
    {
        await using var scope = new Scope(); var store = scope.Store(); var policy = await scope.PolicyWithPriorAsync();
        await PersistConsumedAsync(store);
        var provenanceCalls = 0;
        using var worker = Worker(store, policy, async _ =>
        {
            provenanceCalls++; return Provenance((await store.ReadAsync(CancellationToken.None)).Journal!);
        });
        Assert.AreEqual(PostVerifiedPolicyHandoffResult.NotEligible, await worker.RunOnceAsync(CancellationToken.None));
        var files = new CountingFiles(); var health = new PredecessorHealth();
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await Engine(store, files, health).RecoverAsync(
            (await store.ReadAsync(CancellationToken.None)).Journal!, CancellationToken.None));
        Assert.AreEqual(0, provenanceCalls); Assert.AreEqual(0, files.RestoreCount); Assert.AreEqual(1, health.PredecessorVerifications);
        Assert.AreEqual(new ReleasePolicyRecord(1, Prior), (await policy.ReadDurableAsync(CancellationToken.None)).Record);
    }

    private static UpdateTransactionPolicyCommitWorker Worker(UpdateTransactionJournalStore store, ReleasePolicyStore policy,
        Func<CancellationToken, Task<ReleaseProvenanceSnapshot>> provenance) =>
        new(store, provenance, policy, NullLogger<UpdateTransactionPolicyCommitWorker>.Instance);

    private static OfflineUpdateTransactionEngine Engine(UpdateTransactionJournalStore store, CountingFiles files, IOfflineUpdateHealth health) =>
        new(new EmptyPreflight(), new ServiceProbe(), files, health, new JournalAdapter(store));

    private static async Task<UpdateTransactionJournal> PersistThroughAsync(UpdateTransactionJournalStore store, UpdateTransactionPhase target)
    {
        var current = Journal(UpdateTransactionPhase.Prepared);
        await store.PersistAsync(current, CancellationToken.None);
        foreach (var phase in new[] { UpdateTransactionPhase.Verified, UpdateTransactionPhase.ServiceStopped, UpdateTransactionPhase.Replaced,
                     UpdateTransactionPhase.Restarted, UpdateTransactionPhase.PostVerified, UpdateTransactionPhase.RollbackRequired })
        {
            if (phase == UpdateTransactionPhase.RollbackRequired && target != phase) break;
            current = UpdateTransactionStateMachine.Transition(current, phase, current.UpdatedAtUtc.AddSeconds(1));
            await store.PersistAsync(current, CancellationToken.None);
            if (phase == target) return current;
        }
        throw new InvalidOperationException("Requested phase was not reached.");
    }

    private static async Task PersistConsumedAsync(UpdateTransactionJournalStore store)
    {
        var rollback = await PersistThroughAsync(store, UpdateTransactionPhase.RollbackRequired);
        var authorized = UpdateTransactionStateMachine.Transition(rollback with { RecoveryStartNonce = Nonce },
            UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(1));
        await store.PersistAsync(authorized, CancellationToken.None);
        Assert.IsNotNull(await store.TryConsumeRecoveryStartLeaseAsync(Nonce, CancellationToken.None));
    }

    private static UpdateTransactionJournal Journal(UpdateTransactionPhase phase) => new("0123456789abcdef0123456789abcdef", 1, Prior, 2, Target,
        phase, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", new DateTimeOffset(2026, 10, 2, 0, 0, 0, TimeSpan.Zero));

    private static ReleaseProvenanceSnapshot Provenance(UpdateTransactionJournal journal) => new(DateTimeOffset.UtcNow,
        ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.Bound, ReleaseMetadataCodec.Product, ReleaseMetadataCodec.Architecture,
        ReleaseMetadataCodec.Channel, journal.TargetReleaseSequence, "2.0.0", ReleasePolicyDecision.HigherRelease, journal.TargetManifestSha256);

    private sealed class EmptyPreflight : IOfflineUpdatePreflight
    {
        public Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
    }
    private sealed class JournalAdapter(UpdateTransactionJournalStore store) : IOfflineUpdateJournal
    {
        public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token) => store.PersistAsync(journal, token);
    }
    private sealed class ServiceProbe : IOfflineUpdateServiceControl
    {
        public Task StopAsync(CancellationToken token) => Task.CompletedTask;
        public Task StartAsync(CancellationToken token) => Task.CompletedTask;
        public Task RequireStoppedAsync(CancellationToken token) => Task.CompletedTask;
    }
    private sealed class CountingFiles : IOfflineUpdateReleaseFiles
    {
        internal int RestoreCount;
        public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { RestoreCount++; return Task.CompletedTask; }
    }
    private sealed class PredecessorHealth : IOfflineUpdateHealth
    {
        private int _policyReads;
        internal int PredecessorVerifications;
        internal TaskCompletionSource SecondPolicyObservation { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { PredecessorVerifications++; return Task.CompletedTask; }
        public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            if (Interlocked.Increment(ref _policyReads) == 2) SecondPolicyObservation.TrySetResult();
            return Task.FromResult(PolicyCommitObservation.PredecessorRetained);
        }
    }
    private sealed class DurablePolicyHealth(ReleasePolicyStore policy) : IOfflineUpdateHealth
    {
        public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public async Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            var durable = await policy.ReadDurableAsync(token);
            if (durable.Record is null) return PolicyCommitObservation.Unavailable;
            if (durable.Record.HighestAcceptedReleaseSequence == journal.TargetReleaseSequence &&
                string.Equals(durable.Record.AcceptedManifestSha256, journal.TargetManifestSha256, StringComparison.Ordinal))
                return PolicyCommitObservation.TargetCommitted;
            if (durable.Record.HighestAcceptedReleaseSequence == journal.PriorReleaseSequence &&
                string.Equals(durable.Record.AcceptedManifestSha256, journal.PriorManifestSha256, StringComparison.Ordinal))
                return PolicyCommitObservation.PredecessorRetained;
            return PolicyCommitObservation.Unavailable;
        }
    }
    private sealed class Scope : IAsyncDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-policy-handoff-" + Guid.NewGuid().ToString("N"));
        internal string JournalPath => Path.Combine(Root, "Updates", "Transactions", UpdateTransactionJournalStore.JournalFileName);
        internal Scope()
        {
            Directory.CreateDirectory(Path.Combine(Root, "Updates", "Transactions"));
            File.WriteAllBytes(Path.Combine(Root, "Updates", UpdateTransactionJournalStore.LockFileName), []);
            File.WriteAllBytes(Path.Combine(Root, "Updates", OfflineUpdateOwnershipLock.OwnerLockFileName), []);
        }
        internal UpdateTransactionJournalStore Store() => new(Root, applyAcls: false);
        internal OfflineUpdateOwnershipLock OwnerLock() => new(Root, applyAcls: false);
        internal async Task<ReleasePolicyStore> PolicyWithPriorAsync()
        {
            var policy = new ReleasePolicyStore(Root, applyAcls: false);
            Assert.AreEqual(ReleasePolicyDecision.BootstrapAccepted, await policy.BootstrapVerifiedSequenceOneAsync(
                VerifiedRelease.FromVerifiedEvidence(1, Prior), CancellationToken.None));
            return policy;
        }
        public ValueTask DisposeAsync() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); return ValueTask.CompletedTask; }
    }
}
