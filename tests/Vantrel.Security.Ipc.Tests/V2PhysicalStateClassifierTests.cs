using System.Collections.Immutable;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class V2PhysicalStateClassifierTests
{
    private static readonly ReleaseIdentity Predecessor = new(ReleaseGeneration.V2, 7, new string('A', 64));
    private static readonly ReleaseIdentity Target = new(ReleaseGeneration.V2, 8, new string('B', 64));

    [TestMethod]
    public async Task Classifies_all_six_roles_from_fresh_observations()
    {
        var canonicalIsTarget = false;
        var privateCandidatePresent = false;
        var backupAvailable = false;
        var observer = new TestObserver(role => role switch
        {
            V2PhysicalRootRole.CanonicalService => Present(role, canonicalIsTarget ? Target : Predecessor),
            V2PhysicalRootRole.PreparedTarget => Present(role, Target),
            V2PhysicalRootRole.DetachedPredecessor => Present(role, Predecessor),
            V2PhysicalRootRole.AbandonedTarget => Present(role, Target),
            V2PhysicalRootRole.PrivateCandidate => privateCandidatePresent
                ? Present(role, Target) : new(role, V2PhysicalRootPresence.Absent, null),
            V2PhysicalRootRole.Backup => backupAvailable
                ? Present(role, Predecessor) : new(role, V2PhysicalRootPresence.Unavailable, null),
            _ => throw new ArgumentOutOfRangeException(nameof(role))
        });

        var first = await V2PhysicalStateClassifier.ClassifyAsync(Journal(), observer, CancellationToken.None);
        Assert.AreEqual(V2PhysicalRootState.AuthenticatedPredecessor, first.CanonicalService);
        Assert.AreEqual(V2PhysicalRootState.AuthenticatedTarget, first.PreparedTarget);
        Assert.AreEqual(V2PhysicalRootState.AuthenticatedPredecessor, first.DetachedPredecessor);
        Assert.AreEqual(V2PhysicalRootState.AuthenticatedTarget, first.AbandonedTarget);
        Assert.AreEqual(V2PhysicalRootState.Absent, first.PrivateCandidate);
        Assert.AreEqual(V2PhysicalRootState.Unavailable, first.Backup);

        canonicalIsTarget = true;
        privateCandidatePresent = true;
        backupAvailable = true;
        var second = await V2PhysicalStateClassifier.ClassifyAsync(Journal(), observer, CancellationToken.None);
        Assert.AreEqual(V2PhysicalRootState.AuthenticatedTarget, second.CanonicalService);
        Assert.AreEqual(V2PhysicalRootState.AuthenticatedTarget, second.PrivateCandidate);
        Assert.AreEqual(V2PhysicalRootState.AuthenticatedPredecessor, second.Backup);
        Assert.AreEqual(12, observer.Calls.Count);
        CollectionAssert.AreEqual(Enum.GetValues<V2PhysicalRootRole>(), observer.Calls.Take(6).ToArray());
        CollectionAssert.AreEqual(Enum.GetValues<V2PhysicalRootRole>(), observer.Calls.Skip(6).ToArray());
    }

    [TestMethod]
    public async Task Authenticated_identity_classification_is_independent_of_root_role()
    {
        foreach (var role in Enum.GetValues<V2PhysicalRootRole>())
        {
            foreach (var (identity, expected) in new[]
            {
                (Predecessor, V2PhysicalRootState.AuthenticatedPredecessor),
                (Target, V2PhysicalRootState.AuthenticatedTarget)
            })
            {
                var observer = new TestObserver(observedRole => observedRole == role
                    ? Present(observedRole, identity)
                    : new(observedRole, V2PhysicalRootPresence.Absent, null));

                var state = await V2PhysicalStateClassifier.ClassifyAsync(Journal(), observer, CancellationToken.None);
                Assert.AreEqual(expected, state.For(role), $"{role}: {identity.ReleaseSequence}");
                foreach (var otherRole in Enum.GetValues<V2PhysicalRootRole>().Where(otherRole => otherRole != role))
                    Assert.AreEqual(V2PhysicalRootState.Absent, state.For(otherRole), otherRole.ToString());
            }
        }
    }

    [TestMethod]
    public async Task Rejects_wrong_identity_and_generation_at_every_role()
    {
        var wrongHash = new ReleaseIdentity(ReleaseGeneration.V2, Target.ReleaseSequence, new string('C', 64));
        var v1 = new ReleaseIdentity(ReleaseGeneration.V1, Target.ReleaseSequence, Target.ManifestSha256);
        foreach (var identity in new[] { wrongHash, v1 })
        {
            var observer = new TestObserver(role => Present(role, identity));
            var state = await V2PhysicalStateClassifier.ClassifyAsync(Journal(), observer, CancellationToken.None);
            foreach (var role in Enum.GetValues<V2PhysicalRootRole>())
                Assert.AreEqual(V2PhysicalRootState.PartialOrInvalid, state.For(role), role.ToString());
        }
    }

    [TestMethod]
    public async Task Migration_required_with_release_evidence_is_not_authenticated()
    {
        var observer = new TestObserver(role => role == V2PhysicalRootRole.CanonicalService
            ? new(role, V2PhysicalRootPresence.Present,
                new GenerationAwareOfflineVerification(GenerationAwareOfflineVerificationResult.MigrationRequired,
                    new GenerationAwareOfflineReleaseEvidence(Target, ImmutableArray<TrustedManifestV2File>.Empty)))
            : new(role, V2PhysicalRootPresence.Absent, null));

        var state = await V2PhysicalStateClassifier.ClassifyAsync(Journal(), observer, CancellationToken.None);
        Assert.AreEqual(V2PhysicalRootState.PartialOrInvalid, state.CanonicalService);
    }

    [TestMethod]
    public async Task Absence_and_unavailability_require_unambiguous_observer_results()
    {
        var observer = new TestObserver(role => role switch
        {
            V2PhysicalRootRole.CanonicalService => new(role, V2PhysicalRootPresence.Present, null),
            V2PhysicalRootRole.PreparedTarget => new(role, V2PhysicalRootPresence.Absent,
                Verification(Target)),
            V2PhysicalRootRole.DetachedPredecessor => new(role, V2PhysicalRootPresence.Unavailable,
                Verification(Predecessor)),
            V2PhysicalRootRole.AbandonedTarget => null,
            V2PhysicalRootRole.PrivateCandidate => new(V2PhysicalRootRole.Backup,
                V2PhysicalRootPresence.Absent, null),
            V2PhysicalRootRole.Backup => new(role, V2PhysicalRootPresence.Unavailable, null),
            _ => throw new ArgumentOutOfRangeException(nameof(role))
        });

        var state = await V2PhysicalStateClassifier.ClassifyAsync(Journal(), observer, CancellationToken.None);
        Assert.AreEqual(V2PhysicalRootState.PartialOrInvalid, state.CanonicalService);
        Assert.AreEqual(V2PhysicalRootState.PartialOrInvalid, state.PreparedTarget);
        Assert.AreEqual(V2PhysicalRootState.PartialOrInvalid, state.DetachedPredecessor);
        Assert.AreEqual(V2PhysicalRootState.PartialOrInvalid, state.AbandonedTarget);
        Assert.AreEqual(V2PhysicalRootState.PartialOrInvalid, state.PrivateCandidate);
        Assert.AreEqual(V2PhysicalRootState.Unavailable, state.Backup);
    }

    [TestMethod]
    public async Task Invalid_journal_is_rejected_before_observing_any_root()
    {
        var observer = new TestObserver(role => Present(role, Target));
        var malformed = Journal() with { TransactionId = "not-a-canonical-transaction-id" };

        await Assert.ThrowsExceptionAsync<ArgumentException>(() =>
            V2PhysicalStateClassifier.ClassifyAsync(malformed, observer, CancellationToken.None));
        Assert.AreEqual(0, observer.Calls.Count);
    }

    private static V2UpdateTransactionJournal Journal() => new(
        new string('a', 32), Predecessor, Target, V2UpdateTransactionPhase.Admitted,
        new string('b', 32), new DateTimeOffset(2026, 10, 12, 0, 0, 0, TimeSpan.Zero));

    private static GenerationAwareOfflineVerification Verification(ReleaseIdentity identity) => new(
        GenerationAwareOfflineVerificationResult.Authenticated,
        new GenerationAwareOfflineReleaseEvidence(identity, ImmutableArray<TrustedManifestV2File>.Empty));

    private static V2PhysicalRootObservation Present(V2PhysicalRootRole role, ReleaseIdentity identity) =>
        new(role, V2PhysicalRootPresence.Present, Verification(identity));

    private sealed class TestObserver(Func<V2PhysicalRootRole, V2PhysicalRootObservation?> observe)
        : IV2PhysicalRootObserver
    {
        internal List<V2PhysicalRootRole> Calls { get; } = [];

        public Task<V2PhysicalRootObservation> ObserveAsync(V2PhysicalRootRole role, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Calls.Add(role);
            return Task.FromResult(observe(role)!);
        }
    }
}
