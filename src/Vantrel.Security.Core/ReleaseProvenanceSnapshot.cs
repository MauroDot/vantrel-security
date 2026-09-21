namespace Vantrel.Security.Core;

public enum ReleaseMetadataSignatureState { Valid, MetadataUnavailable, MetadataMalformed, SignatureInvalid, UnsupportedSchema, WrongProduct, WrongArchitecture, WrongChannel, UnknownKeyId }
public enum ReleaseManifestBindingState { Bound, ManifestMismatch, ManifestUnavailable, ManifestInvalid, ComponentMismatch }
public enum ReleaseProvenanceDisplayState { Disconnected, Unavailable, Stale, Current, Recovered }

/// <summary>Read-only signed release provenance. It is supplementary to current signed-installation integrity.</summary>
public sealed record ReleaseProvenanceSnapshot(DateTimeOffset SampledAtUtc, ReleaseMetadataSignatureState MetadataSignatureState,
    ReleaseManifestBindingState ManifestBindingState, string? Product, string? Architecture, string? Channel,
    ulong? ReleaseSequence, string? DisplayVersion, ReleasePolicyDecision PolicyDecision, string? ManifestSha256);

public static class ReleaseProvenancePresentation
{
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(30);
    public static ReleaseProvenanceDisplayState State(ReleaseProvenanceSnapshot? value, bool connected, DateTimeOffset now,
        bool wasDisconnected = false) => !connected ? ReleaseProvenanceDisplayState.Disconnected : value is null ? ReleaseProvenanceDisplayState.Unavailable :
        now - value.SampledAtUtc > StaleAfter ? ReleaseProvenanceDisplayState.Stale : wasDisconnected ? ReleaseProvenanceDisplayState.Recovered : ReleaseProvenanceDisplayState.Current;
}

public interface IReleaseProvenanceClient
{
    Task<ReleaseProvenanceSnapshot?> GetReleaseProvenanceAsync(CancellationToken cancellationToken);
}