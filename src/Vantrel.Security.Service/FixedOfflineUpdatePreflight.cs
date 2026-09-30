using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>Fixed pre-stop verification and backup. All source and destination roots are code-owned.</summary>
internal sealed class FixedOfflineUpdatePreflight(OfflineReleaseVerifier verifier, ReleasePolicyStore policy, OfflineUpdateStorage storage) : IOfflineUpdatePreflight
{
    public async Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        var baseline = await verifier.VerifyInstalledBaselineAsync(storage.InstalledRoot, policy, token);
        if (baseline.Result != OfflineReleaseVerificationResult.Verified || baseline.Release is null ||
            baseline.Release.Sequence != journal.PriorReleaseSequence || !string.Equals(baseline.Release.ManifestSha256, journal.PriorManifestSha256, StringComparison.Ordinal))
            throw new IOException("Installed predecessor baseline is not the journal predecessor.");

        var staged = await verifier.VerifyCandidateAsync(storage.StagedCandidate, policy, token);
        if (!MatchesJournalTarget(staged, journal))
            throw new IOException("Fixed staged candidate is not the journal target.");

        await storage.CopyStagedToPrivateAsync(journal.TransactionId, token);
        var candidate = await verifier.VerifyCandidateAsync(storage.PrivateCandidate(journal.TransactionId), policy, token);
        if (!MatchesJournalTarget(candidate, journal))
            throw new IOException("Fixed private candidate is not the journal target.");
    }

    public async Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        await storage.CopyInstalledToBackupAsync(journal.BackupId, token);
        var backup = await verifier.VerifyChainAsync(storage.Backup(journal.BackupId), token);
        var durable = await policy.ReadDurableAsync(token);
        if (durable.Failure != ReleasePolicyParseFailure.None || durable.Record is null ||
            backup.Sequence != journal.PriorReleaseSequence || !string.Equals(backup.ManifestSha256, journal.PriorManifestSha256, StringComparison.Ordinal) ||
            durable.Record.HighestAcceptedReleaseSequence != backup.Sequence || !string.Equals(durable.Record.AcceptedManifestSha256, backup.ManifestSha256, StringComparison.Ordinal))
            throw new IOException("Fixed predecessor backup is not independently verified against durable policy.");
    }

    private static bool MatchesJournalTarget(VerifiedOfflineRelease candidate, UpdateTransactionJournal journal) =>
        candidate.PolicyDecision == ReleasePolicyDecision.HigherRelease && candidate.Sequence == journal.TargetReleaseSequence &&
        string.Equals(candidate.ManifestSha256, journal.TargetManifestSha256, StringComparison.Ordinal);
}

/// <summary>Fixed adapter used only by an elevated, offline transaction invocation.</summary>
internal sealed class FixedOfflineUpdateReleaseFiles : IOfflineUpdateReleaseFiles
{
    private readonly FixedReleaseFileReplacer _replacer = new();
    public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) => _replacer.ReplaceFromPrivateCandidateAsync(journal.TransactionId, token);
    public Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) => _replacer.RestoreFromBackupAsync(journal.BackupId, token);
}
