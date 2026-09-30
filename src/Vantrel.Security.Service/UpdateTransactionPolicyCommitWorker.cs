using Microsoft.Extensions.Hosting;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>LocalService-only final policy handoff. It reads a fixed journal and never writes Program Files.</summary>
public sealed class UpdateTransactionPolicyCommitWorker(UpdateTransactionJournalStore journals, ReleaseProvenanceSource provenanceSource,
    ReleasePolicyStore policyStore, ILogger<UpdateTransactionPolicyCommitWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var read = await journals.ReadAsync(stoppingToken);
            if (!IsEligibleJournal(read)) return;
            var journal = read.Journal!;
            var installed = await provenanceSource.CollectAsync(stoppingToken);
            if (installed.MetadataSignatureState != ReleaseMetadataSignatureState.Valid ||
                installed.ManifestBindingState != ReleaseManifestBindingState.Bound ||
                installed.ReleaseSequence != journal.TargetReleaseSequence ||
                !string.Equals(installed.ManifestSha256, journal.TargetManifestSha256, StringComparison.Ordinal))
            {
                logger.LogWarning("Update transaction policy handoff requires elevated recovery");
                return;
            }
            var decision = await policyStore.CommitVerifiedInstalledReleaseAsync(
                VerifiedRelease.FromVerifiedEvidence(journal.TargetReleaseSequence, journal.TargetManifestSha256), stoppingToken);
            if (decision != ReleasePolicyDecision.HigherRelease)
            {
                logger.LogWarning("Update transaction policy handoff was not eligible");
                return;
            }
            await journals.PersistAsync(journal with { Phase = UpdateTransactionPhase.PolicyCommitted, UpdatedAtUtc = DateTimeOffset.UtcNow }, stoppingToken);
            logger.LogInformation("Update transaction policy committed");
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            logger.LogWarning("Update transaction policy handoff requires trusted journal infrastructure");
        }
    }

    internal static bool IsEligibleJournal(JournalReadResult read) =>
        read.State == JournalReadState.Present && read.Journal?.Phase == UpdateTransactionPhase.PostVerified;
}
