using Vantrel.Security.Core;

namespace Vantrel.Security.Desktop;

/// <summary>Formats bounded Status.v1 release provenance without opening Command.v1.</summary>
internal static class ReleaseProvenanceDesktopPresentation
{
    internal static (ReleaseProvenanceDisplayState DisplayState, string StateText, string SampleText, string ValueText) Create(
        ReleaseProvenanceSnapshot? value, bool connected, DateTimeOffset now, bool wasDisconnected = false)
    {
        var state = ReleaseProvenancePresentation.State(value, connected, now, wasDisconnected);
        var stateText = state switch
        {
            ReleaseProvenanceDisplayState.Disconnected => "Disconnected - service unavailable",
            ReleaseProvenanceDisplayState.Unavailable => "Unavailable - release provenance could not be read",
            ReleaseProvenanceDisplayState.Stale => "Stale - last release provenance sample is over 30 minutes old",
            ReleaseProvenanceDisplayState.Recovered => "Recovered - current release provenance and rollback policy",
            _ => "Current release provenance and rollback policy"
        };
        if (!connected || value is null)
            return (state, stateText, "Sample: unavailable", "Release metadata: unavailable.");

        var sample = $"Sample: {value.SampledAtUtc.ToLocalTime():G}";
        var details = value.MetadataSignatureState == ReleaseMetadataSignatureState.Valid &&
            value.ManifestBindingState == ReleaseManifestBindingState.Bound &&
            value.Product is not null && value.Architecture is not null && value.Channel is not null &&
            value.ReleaseSequence is not null && value.DisplayVersion is not null
            ? $"Metadata signature: Valid. Manifest binding: Bound. Release: {value.DisplayVersion} (sequence {value.ReleaseSequence}; {value.Product}/{value.Architecture}/{value.Channel}). Policy: {value.PolicyDecision}."
            : $"Metadata signature: {value.MetadataSignatureState}. Manifest binding: {value.ManifestBindingState}. Policy: {value.PolicyDecision}.";
        return (state, stateText, sample, details);
    }
}