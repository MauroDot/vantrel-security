using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>
/// Dormant V2-to-V2 pre-stop coordination. Each call performs at most one artifact preparation
/// and one exact-current journal transition. No public update entry point invokes this class.
/// The shared historical owner lease must remain held by the caller throughout each call.
/// </summary>
internal sealed class V2PreStopUpdateCoordinator
{
    private readonly string _updatesRoot;
    private readonly string _installedRoot;
    private readonly string _stagedRoot;
    private readonly GenerationAwareOfflineReleaseVerifier _verifier;
    private readonly ReleasePolicyStore _policy;
    private readonly UpdateTransactionJournalStore _historicalJournal;
    private readonly V2UpdateTransactionJournalStore _journal;
    private readonly V2ReleaseArtifactStorage _artifacts;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<string> _newId;
    private readonly Action<string>? _checkpoint;

    internal V2PreStopUpdateCoordinator()
        : this(FixedUpdatePaths.UpdatesRoot, FixedUpdatePaths.InstalledServiceRoot,
            Path.Combine(FixedUpdatePaths.UpdatesRoot, "StagedV2", "candidate"),
            new GenerationAwareOfflineReleaseVerifier(), new ReleasePolicyStore(),
            new UpdateTransactionJournalStore(), new V2UpdateTransactionJournalStore(),
            new V2ReleaseArtifactStorage(), () => DateTimeOffset.UtcNow,
            () => Guid.NewGuid().ToString("N"), checkpoint: null, production: true) { }

    // Disposable roots, deterministic IDs/time, and faults are test-only seams. Production
    // composition above fixes every root and never accepts caller identities or paths.
    internal V2PreStopUpdateCoordinator(string updatesRoot, string installedRoot, string stagedRoot,
        GenerationAwareOfflineReleaseVerifier verifier, ReleasePolicyStore policy,
        UpdateTransactionJournalStore v1Journal, V2UpdateTransactionJournalStore v2Journal,
        V2ReleaseArtifactStorage artifacts, Func<DateTimeOffset>? clock = null,
        Func<string>? newId = null, Action<string>? checkpoint = null)
        : this(updatesRoot, installedRoot, stagedRoot, verifier, policy, v1Journal, v2Journal,
            artifacts, clock ?? (() => DateTimeOffset.UtcNow),
            newId ?? (() => Guid.NewGuid().ToString("N")), checkpoint, production: false) { }

    private V2PreStopUpdateCoordinator(string updatesRoot, string installedRoot, string stagedRoot,
        GenerationAwareOfflineReleaseVerifier verifier, ReleasePolicyStore policy,
        UpdateTransactionJournalStore v1Journal, V2UpdateTransactionJournalStore v2Journal,
        V2ReleaseArtifactStorage artifacts, Func<DateTimeOffset> clock, Func<string> newId,
        Action<string>? checkpoint, bool production)
    {
        _updatesRoot = RequireAbsoluteRoot(updatesRoot);
        _installedRoot = RequireAbsoluteRoot(installedRoot);
        _stagedRoot = RequireAbsoluteRoot(stagedRoot);
        if (!Same(_stagedRoot, Path.Combine(_updatesRoot, "StagedV2", "candidate")))
            throw new IOException("V2 staged candidate root is not fixed beneath Updates.");
        if (production && (!Same(_updatesRoot, FixedUpdatePaths.UpdatesRoot) ||
                           !Same(_installedRoot, FixedUpdatePaths.InstalledServiceRoot)))
            throw new IOException("V2 pre-stop production roots are not fixed.");
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _historicalJournal = v1Journal ?? throw new ArgumentNullException(nameof(v1Journal));
        _journal = v2Journal ?? throw new ArgumentNullException(nameof(v2Journal));
        _artifacts = artifacts ?? throw new ArgumentNullException(nameof(artifacts));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _newId = newId ?? throw new ArgumentNullException(nameof(newId));
        _checkpoint = checkpoint;
    }

    /// <summary>Creates only the Admitted journal, from fresh installed and staged evidence.</summary>
    internal async Task<V2UpdateTransactionJournal> AdmitAsync(
        OfflineUpdateOwnershipLease lease, CancellationToken token)
    {
        RequireLease(lease, token);
        await RequireNoTransactionAsync(token);
        var predecessor = await RequireAuthenticatedV2Async(_installedRoot, token);
        var accepted = await RequirePolicyPredecessorAsync(predecessor, token);
        var target = await RequireAuthenticatedV2Async(_stagedRoot, token);
        if (GenerationAwareReleasePolicyCodec.Evaluate(
                new GenerationAwareReleasePolicyRecord(accepted), target) != ReleasePolicyDecision.HigherRelease)
            throw new IOException("Staged V2 candidate does not advance the durable predecessor policy.");

        var transactionId = _newId();
        var backupId = _newId();
        if (!V2UpdateTransactionJournalCodec.IsId(transactionId) ||
            !V2UpdateTransactionJournalCodec.IsId(backupId) || transactionId == backupId)
            throw new IOException("Generated V2 transaction identifiers are invalid.");
        var admitted = new V2UpdateTransactionJournal(transactionId, predecessor, target,
            V2UpdateTransactionPhase.Admitted, backupId, Now(), RecoveryStartNonce: null);
        _ = V2UpdateTransactionJournalCodec.Serialize(admitted);
        _checkpoint?.Invoke("BeforeAdmissionPublication");
        RequireLease(lease, token);
        await RequireNoTransactionAsync(token);
        _ = await RequirePolicyPredecessorAsync(predecessor, token);
        if (await RequireAuthenticatedV2Async(_installedRoot, token) != predecessor ||
            await RequireAuthenticatedV2Async(_stagedRoot, token) != target)
            throw new IOException("V2 admission evidence changed before publication.");
        RequireLease(lease, token);
        await RequireNoTransactionAsync(token);
        if (!await _journal.TryPersistIfExactCurrentAsync(expected: null, admitted, token))
            throw new IOException("V2 admission lost its exact-absence journal comparison.");
        return admitted;
    }

    /// <summary>Reconciles or copies one private target, then advances Admitted to PrivateReady.</summary>
    internal async Task<V2UpdateTransactionJournal> AdvancePrivateAsync(
        OfflineUpdateOwnershipLease lease, CancellationToken token)
    {
        var current = await RequireCurrentAsync(lease, V2UpdateTransactionPhase.Admitted, token);
        _ = await RequirePolicyPredecessorAsync(current.Predecessor, token);
        var observation = await _artifacts.ObservePrivateCandidateAsync(
            current.TransactionId, current.Target, token);
        if (observation.State == V2ArtifactObservationState.InvalidOrUnavailable)
            throw new IOException("V2 private candidate artifact is invalid or unavailable.");
        if (observation.State == V2ArtifactObservationState.Absent)
        {
            RequireLease(lease, token);
            await RequireV1AbsentAndExactV2Async(current, token);
            _ = await RequirePolicyPredecessorAsync(current.Predecessor, token);
            await _artifacts.CopyPrivateCandidateAsync(current.TransactionId, current.Target, token);
            _checkpoint?.Invoke("AfterPrivateCopyBeforeTransition");
        }

        await RequireArtifactAsync(await _artifacts.ObservePrivateCandidateAsync(
            current.TransactionId, current.Target, token), current.Target);
        RequireLease(lease, token);
        await RequireV1AbsentAndExactV2Async(current, token);
        _ = await RequirePolicyPredecessorAsync(current.Predecessor, token);
        _checkpoint?.Invoke("BeforePrivatePublication");
        RequireLease(lease, token);
        await RequireV1AbsentAndExactV2Async(current, token);
        _ = await RequirePolicyPredecessorAsync(current.Predecessor, token);
        await RequireArtifactAsync(await _artifacts.ObservePrivateCandidateAsync(
            current.TransactionId, current.Target, token), current.Target);
        var next = V2UpdateTransactionStateMachine.Transition(current,
            V2UpdateTransactionPhase.PrivateReady, Now());
        RequireLease(lease, token);
        await RequireV1AbsentAndExactV2Async(current, token);
        if (!await _journal.TryPersistIfExactCurrentAsync(current, next, token))
            throw new IOException("V2 private-ready transition lost its exact-current journal comparison.");
        return next;
    }

    /// <summary>Reconciles or copies one predecessor backup, then advances to BackupReady.</summary>
    internal async Task<V2UpdateTransactionJournal> AdvanceBackupAsync(
        OfflineUpdateOwnershipLease lease, CancellationToken token)
    {
        var current = await RequireCurrentAsync(lease, V2UpdateTransactionPhase.PrivateReady, token);
        _ = await RequirePolicyPredecessorAsync(current.Predecessor, token);
        await RequireArtifactAsync(await _artifacts.ObservePrivateCandidateAsync(
            current.TransactionId, current.Target, token), current.Target);
        if (await RequireAuthenticatedV2Async(_installedRoot, token) != current.Predecessor)
            throw new IOException("Installed V2 predecessor changed before backup preparation.");
        var observation = await _artifacts.ObservePredecessorBackupAsync(
            current.BackupId, current.Predecessor, token);
        if (observation.State == V2ArtifactObservationState.InvalidOrUnavailable)
            throw new IOException("V2 predecessor backup is invalid or unavailable.");
        if (observation.State == V2ArtifactObservationState.Absent)
        {
            RequireLease(lease, token);
            await RequireV1AbsentAndExactV2Async(current, token);
            _ = await RequirePolicyPredecessorAsync(current.Predecessor, token);
            await _artifacts.CopyPredecessorBackupAsync(current.BackupId, current.Predecessor, token);
            _checkpoint?.Invoke("AfterBackupCopyBeforeTransition");
        }

        await RequireBackupReadyEvidenceAsync(current, token);
        RequireLease(lease, token);
        await RequireV1AbsentAndExactV2Async(current, token);
        _ = await RequirePolicyPredecessorAsync(current.Predecessor, token);
        _checkpoint?.Invoke("BeforeBackupPublication");
        RequireLease(lease, token);
        await RequireV1AbsentAndExactV2Async(current, token);
        await RequireBackupReadyEvidenceAsync(current, token);
        _ = await RequirePolicyPredecessorAsync(current.Predecessor, token);
        var next = V2UpdateTransactionStateMachine.Transition(current,
            V2UpdateTransactionPhase.BackupReady, Now());
        RequireLease(lease, token);
        await RequireV1AbsentAndExactV2Async(current, token);
        if (!await _journal.TryPersistIfExactCurrentAsync(current, next, token))
            throw new IOException("V2 backup-ready transition lost its exact-current journal comparison.");
        return next;
    }

    /// <summary>Read-only, non-authorizing observation of a durable BackupReady state.</summary>
    internal async Task<V2UpdateTransactionJournal> ObserveBackupReadyAsync(
        OfflineUpdateOwnershipLease lease, CancellationToken token)
    {
        var current = await RequireCurrentAsync(lease, V2UpdateTransactionPhase.BackupReady, token);
        _ = await RequirePolicyPredecessorAsync(current.Predecessor, token);
        await RequireBackupReadyEvidenceAsync(current, token);
        RequireLease(lease, token);
        await RequireV1AbsentAndExactV2Async(current, token);
        _ = await RequirePolicyPredecessorAsync(current.Predecessor, token);
        return current;
    }

    private async Task RequireBackupReadyEvidenceAsync(V2UpdateTransactionJournal current,
        CancellationToken token)
    {
        if (await RequireAuthenticatedV2Async(_installedRoot, token) != current.Predecessor)
            throw new IOException("Installed V2 predecessor no longer matches the journal.");
        await RequireArtifactAsync(await _artifacts.ObservePrivateCandidateAsync(
            current.TransactionId, current.Target, token), current.Target);
        await RequireArtifactAsync(await _artifacts.ObservePredecessorBackupAsync(
            current.BackupId, current.Predecessor, token), current.Predecessor);
    }

    private static Task RequireArtifactAsync(V2ArtifactObservation observation, ReleaseIdentity expected)
    {
        if (observation.State != V2ArtifactObservationState.Authenticated ||
            observation.Evidence?.Identity != expected)
            throw new IOException("Required V2 artifact is not an exact authenticated release.");
        return Task.CompletedTask;
    }

    private async Task<V2UpdateTransactionJournal> RequireCurrentAsync(
        OfflineUpdateOwnershipLease lease, V2UpdateTransactionPhase phase, CancellationToken token)
    {
        RequireLease(lease, token);
        var v1 = await _historicalJournal.ReadAsync(token);
        var v2 = await _journal.ReadAsync(token);
        if (V1V2JournalConflictClassifier.Classify(v1, v2) != V1V2JournalPresence.V2Transaction ||
            v2.Journal is not { RecoveryStartNonce: null, Predecessor: { Generation: ReleaseGeneration.V2 },
                Target: { Generation: ReleaseGeneration.V2 } } current || current.Phase != phase)
            throw new IOException("V2 pre-stop journal state is conflicting or unavailable.");
        if (!await _journal.IsExactCurrentAsync(current, token))
            throw new IOException("V2 pre-stop journal changed before artifact preparation.");
        return current;
    }

    private async Task RequireV1AbsentAndExactV2Async(V2UpdateTransactionJournal current,
        CancellationToken token)
    {
        var v1 = await _historicalJournal.ReadAsync(token);
        var v2 = await _journal.ReadAsync(token);
        if (V1V2JournalConflictClassifier.Classify(v1, v2) != V1V2JournalPresence.V2Transaction ||
            v2.Journal != current || !await _journal.IsExactCurrentAsync(current, token))
            throw new IOException("V1/V2 journal state changed during pre-stop preparation.");
    }

    private async Task RequireNoTransactionAsync(CancellationToken token)
    {
        var v1 = await _historicalJournal.ReadAsync(token);
        var v2 = await _journal.ReadAsync(token);
        if (V1V2JournalConflictClassifier.Classify(v1, v2) != V1V2JournalPresence.NoTransaction)
            throw new IOException("V1/V2 journal absence is not established.");
    }

    private async Task<ReleaseIdentity> RequirePolicyPredecessorAsync(
        ReleaseIdentity predecessor, CancellationToken token)
    {
        var (identity, failure) = await _policy.ReadPolicyIdentityAsync(token);
        if (failure != ReleasePolicyParseFailure.None || identity is not
            { IsValid: true, Generation: ReleaseGeneration.V2 } || identity != predecessor)
            throw new IOException("Durable V2 policy does not identify the installed predecessor.");
        return identity;
    }

    private async Task<ReleaseIdentity> RequireAuthenticatedV2Async(string root, CancellationToken token)
    {
        var observed = await _verifier.VerifyChainAsync(root, token);
        if (observed is not { Result: GenerationAwareOfflineVerificationResult.Authenticated,
            Release.Identity: { IsValid: true, Generation: ReleaseGeneration.V2 } identity })
            throw new IOException("Required V2 release authentication failed.");
        return identity;
    }

    private void RequireLease(OfflineUpdateOwnershipLease lease, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(lease);
        lease.RequireHeldFor(_updatesRoot);
    }

    private DateTimeOffset Now()
    {
        var time = _clock();
        if (time.Offset != TimeSpan.Zero)
            throw new IOException("V2 pre-stop clock is not UTC.");
        return new DateTimeOffset(time.Ticks - time.Ticks % TimeSpan.TicksPerSecond, TimeSpan.Zero);
    }

    private static string RequireAbsoluteRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new IOException("V2 pre-stop root is not an absolute path.");
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }

    private static bool Same(string left, string right) =>
        string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);
}
