using Microsoft.Extensions.Hosting;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>LocalService-only final policy handoff. It reads a fixed journal and never writes Program Files.</summary>
public sealed class UpdateTransactionPolicyCommitWorker : BackgroundService
{
    private readonly UpdateTransactionJournalStore _journals;
    private readonly Func<CancellationToken, Task<ReleaseProvenanceSnapshot>> _collectProvenance;
    private readonly ReleasePolicyStore _policyStore;
    private readonly ILogger<UpdateTransactionPolicyCommitWorker> _logger;

    public UpdateTransactionPolicyCommitWorker(UpdateTransactionJournalStore journals, ReleaseProvenanceSource provenanceSource,
        ReleasePolicyStore policyStore, ILogger<UpdateTransactionPolicyCommitWorker> logger)
        : this(journals, provenanceSource is null ? throw new ArgumentNullException(nameof(provenanceSource)) : provenanceSource.CollectAsync,
            policyStore, logger) { }

    internal UpdateTransactionPolicyCommitWorker(UpdateTransactionJournalStore journals,
        Func<CancellationToken, Task<ReleaseProvenanceSnapshot>> collectProvenance, ReleasePolicyStore policyStore,
        ILogger<UpdateTransactionPolicyCommitWorker> logger)
    {
        _journals = journals ?? throw new ArgumentNullException(nameof(journals));
        _collectProvenance = collectProvenance ?? throw new ArgumentNullException(nameof(collectProvenance));
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var result = await RunOnceAsync(stoppingToken);
            if (result == PostVerifiedPolicyHandoffResult.Completed) _logger.LogInformation("Update transaction policy committed");
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            _logger.LogWarning("Update transaction policy handoff requires trusted journal infrastructure");
        }
    }

    internal async Task<PostVerifiedPolicyHandoffResult> RunOnceAsync(CancellationToken token)
    {
        var read = await _journals.ReadAsync(token);
        if (!IsEligibleJournal(read)) return PostVerifiedPolicyHandoffResult.NotEligible;
        return await _journals.TryCompletePostVerifiedPolicyHandoffAsync(read.Journal!, VerifyAndCommitTargetPolicyAsync, token);
    }

    private async Task<bool> VerifyAndCommitTargetPolicyAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        var installed = await _collectProvenance(token);
        if (installed.MetadataSignatureState != ReleaseMetadataSignatureState.Valid ||
            installed.ManifestBindingState != ReleaseManifestBindingState.Bound ||
            installed.ReleaseSequence != journal.TargetReleaseSequence ||
            !string.Equals(installed.ManifestSha256, journal.TargetManifestSha256, StringComparison.Ordinal))
            return false;
        var decision = await _policyStore.CommitVerifiedInstalledReleaseAsync(
            VerifiedRelease.FromVerifiedEvidence(journal.TargetReleaseSequence, journal.TargetManifestSha256), token);
        return decision is ReleasePolicyDecision.HigherRelease or ReleasePolicyDecision.SameAcceptedRelease;
    }

    internal static bool IsEligibleJournal(JournalReadResult read) =>
        read.State == JournalReadState.Present && read.Journal?.Phase == UpdateTransactionPhase.PostVerified;
}
