using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>Journal-bound physical roots. The observer, not this contract, resolves their locations.</summary>
internal enum V2PhysicalRootRole
{
    CanonicalService,
    PreparedTarget,
    DetachedPredecessor,
    AbandonedTarget,
    PrivateCandidate,
    Backup
}

/// <summary>
/// The trusted observer must explicitly establish absence or unavailability. Present means it
/// performed a fresh chain verification of this root for this observation.
/// </summary>
internal enum V2PhysicalRootPresence { Present, Absent, Unavailable }

internal enum V2PhysicalRootState
{
    Absent,
    AuthenticatedPredecessor,
    AuthenticatedTarget,
    PartialOrInvalid,
    Unavailable
}

/// <summary>
/// One observation from a trusted root observer. A present root carries the result of a fresh
/// GenerationAwareOfflineReleaseVerifier.VerifyChainAsync call. An absent or unavailable root
/// carries no verification. This classifier never infers either state from directory contents.
/// </summary>
internal sealed record V2PhysicalRootObservation(
    V2PhysicalRootRole Role,
    V2PhysicalRootPresence Presence,
    GenerationAwareOfflineVerification? Verification);

/// <summary>
/// A caller-owned trusted boundary that resolves each journal-bound root and observes it now.
/// It must prove absence explicitly, report inability to observe as Unavailable, and run fresh
/// chain verification for Present. It supplies no cached candidate or policy decision.
/// </summary>
internal interface IV2PhysicalRootObserver
{
    Task<V2PhysicalRootObservation> ObserveAsync(V2PhysicalRootRole role, CancellationToken token);
}

/// <summary>
/// Immutable classification of the six journal-bound roots. The observations are sequential;
/// this result does not prove that all six roots held these states at one instant.
/// </summary>
internal sealed record V2PhysicalStateSnapshot(
    V2PhysicalRootState CanonicalService,
    V2PhysicalRootState PreparedTarget,
    V2PhysicalRootState DetachedPredecessor,
    V2PhysicalRootState AbandonedTarget,
    V2PhysicalRootState PrivateCandidate,
    V2PhysicalRootState Backup)
{
    internal V2PhysicalRootState For(V2PhysicalRootRole role) => role switch
    {
        V2PhysicalRootRole.CanonicalService => CanonicalService,
        V2PhysicalRootRole.PreparedTarget => PreparedTarget,
        V2PhysicalRootRole.DetachedPredecessor => DetachedPredecessor,
        V2PhysicalRootRole.AbandonedTarget => AbandonedTarget,
        V2PhysicalRootRole.PrivateCandidate => PrivateCandidate,
        V2PhysicalRootRole.Backup => Backup,
        _ => throw new ArgumentOutOfRangeException(nameof(role))
    };
}

/// <summary>
/// Pure classification of fresh, trusted observations. It performs no root lookup, filesystem
/// operation, copy, switch, or recovery, and a result does not authorize any of those actions.
/// </summary>
internal static class V2PhysicalStateClassifier
{
    internal static async Task<V2PhysicalStateSnapshot> ClassifyAsync(
        V2UpdateTransactionJournal journal, IV2PhysicalRootObserver observer, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(observer);
        // The observer's expected identities must come from a complete canonical journal,
        // not merely from two plausible release identities on a malformed transaction.
        _ = V2UpdateTransactionJournalCodec.Serialize(journal);

        return new(
            await ClassifyRootAsync(V2PhysicalRootRole.CanonicalService, journal, observer, token),
            await ClassifyRootAsync(V2PhysicalRootRole.PreparedTarget, journal, observer, token),
            await ClassifyRootAsync(V2PhysicalRootRole.DetachedPredecessor, journal, observer, token),
            await ClassifyRootAsync(V2PhysicalRootRole.AbandonedTarget, journal, observer, token),
            await ClassifyRootAsync(V2PhysicalRootRole.PrivateCandidate, journal, observer, token),
            await ClassifyRootAsync(V2PhysicalRootRole.Backup, journal, observer, token));
    }

    private static async Task<V2PhysicalRootState> ClassifyRootAsync(V2PhysicalRootRole role,
        V2UpdateTransactionJournal journal, IV2PhysicalRootObserver observer, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var observed = await observer.ObserveAsync(role, token);
        if (observed is null || observed.Role != role)
            return V2PhysicalRootState.PartialOrInvalid;
        if (observed.Presence == V2PhysicalRootPresence.Absent && observed.Verification is null)
            return V2PhysicalRootState.Absent;
        if (observed.Presence == V2PhysicalRootPresence.Unavailable && observed.Verification is null)
            return V2PhysicalRootState.Unavailable;
        if (observed.Presence != V2PhysicalRootPresence.Present ||
            observed.Verification is not
            { Result: GenerationAwareOfflineVerificationResult.Authenticated,
              Release.Identity: { Generation: ReleaseGeneration.V2, IsValid: true } identity })
            return V2PhysicalRootState.PartialOrInvalid;

        if (identity == journal.Predecessor)
            return V2PhysicalRootState.AuthenticatedPredecessor;
        if (identity == journal.Target)
            return V2PhysicalRootState.AuthenticatedTarget;
        return V2PhysicalRootState.PartialOrInvalid;
    }
}
