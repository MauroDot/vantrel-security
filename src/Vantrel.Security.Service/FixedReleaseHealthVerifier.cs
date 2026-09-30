using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;

namespace Vantrel.Security.Service;

/// <summary>Bounded post-restart verification. It observes Status.v1 and durable policy but never sends Command.v1 or commits policy.</summary>
internal sealed class FixedReleaseHealthVerifier(WindowsVantrelServiceControl service, OfflineReleaseVerifier verifier,
    ReleasePolicyStore policy) : IOfflineUpdateHealth
{
    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    public async Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(Timeout);
        var client = new NamedPipeStatusClient(Microsoft.Extensions.Logging.Abstractions.NullLogger<NamedPipeStatusClient>.Instance);
        while (!timeout.IsCancellationRequested)
        {
            if (await service.IsRunningAsync(timeout.Token))
            {
                var provenance = await client.GetReleaseProvenanceAsync(timeout.Token);
                var integrity = await client.GetTrustedManifestIntegrityAsync(timeout.Token);
                var chain = await verifier.VerifyChainAsync(FixedUpdatePaths.InstalledServiceRoot, timeout.Token);
                if (provenance is { MetadataSignatureState: ReleaseMetadataSignatureState.Valid, ManifestBindingState: ReleaseManifestBindingState.Bound,
                    Product: ReleaseMetadataCodec.Product, Architecture: ReleaseMetadataCodec.Architecture, Channel: ReleaseMetadataCodec.Channel } &&
                    provenance.ReleaseSequence == journal.TargetReleaseSequence && integrity is { SignatureState: TrustedManifestSignatureState.Valid, Evaluation: TrustedManifestInstallationEvaluation.AllMatch } &&
                    chain.Sequence == journal.TargetReleaseSequence && string.Equals(chain.ManifestSha256, journal.TargetManifestSha256, StringComparison.Ordinal)) return;
            }
            await Task.Delay(250, timeout.Token);
        }
        throw new TimeoutException("Fixed release health verification timed out.");
    }

    public async Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        var chain = await verifier.VerifyChainAsync(FixedUpdatePaths.InstalledServiceRoot, token);
        if (chain.Sequence != journal.PriorReleaseSequence || !string.Equals(chain.ManifestSha256, journal.PriorManifestSha256, StringComparison.Ordinal) || !await service.IsRunningAsync(token))
            throw new IOException("Fixed predecessor health verification failed.");
    }

    public async Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(Timeout);
        while (!timeout.IsCancellationRequested)
        {
            var observation = await ObserveOnceAsync(journal, timeout.Token);
            if (observation == PolicyCommitObservation.TargetCommitted) return observation;
            if (observation == PolicyCommitObservation.Unavailable) return observation;
            await Task.Delay(250, timeout.Token);
        }
        return await ObserveOnceAsync(journal, token); // Final durable read closes the installer/service race.
    }

    private async Task<PolicyCommitObservation> ObserveOnceAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        var durable = await policy.ReadDurableAsync(token);
        if (durable.Failure != ReleasePolicyParseFailure.None || durable.Record is null) return PolicyCommitObservation.Unavailable;
        if (Matches(durable.Record, journal.TargetReleaseSequence, journal.TargetManifestSha256)) return PolicyCommitObservation.TargetCommitted;
        if (Matches(durable.Record, journal.PriorReleaseSequence, journal.PriorManifestSha256)) return PolicyCommitObservation.PredecessorRetained;
        return PolicyCommitObservation.Unavailable;
    }

    internal static bool Matches(ReleasePolicyRecord? policy, ulong sequence, string hash) => policy is not null && policy.HighestAcceptedReleaseSequence == sequence && string.Equals(policy.AcceptedManifestSha256, hash, StringComparison.Ordinal);
}