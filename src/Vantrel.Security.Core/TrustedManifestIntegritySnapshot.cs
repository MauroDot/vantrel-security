namespace Vantrel.Security.Core;

public enum TrustedManifestSignatureState { Valid, SignatureInvalid, ManifestUnavailable, ManifestMalformed, UnsupportedSchema }
public enum TrustedManifestInstallationEvaluation { AllMatch, ComponentMismatch, ObservationUnavailable, ManifestUnavailable, ManifestInvalid }
public enum TrustedManifestIntegrityDisplayState { Disconnected, Unavailable, Stale, Current, Recovered }
public enum TrustedManifestComponent { ServiceExe, ServiceAssembly, InfrastructureAssembly, CoreAssembly, Deps, RuntimeConfig, EventLogResource }

/// <summary>A signed, fixed installation comparison. It is not a malware, safety, or system-wide trust verdict.</summary>
public sealed record TrustedManifestIntegritySnapshot(DateTimeOffset SampledAtUtc, string PolicyRevision,
    TrustedManifestSignatureState SignatureState, TrustedManifestInstallationEvaluation Evaluation,
    ComponentInspectionReason? ObservationReason, TrustedManifestComponent? MismatchedComponent);

public static class TrustedManifestIntegrityPresentation
{
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(30);
    public static TrustedManifestIntegrityDisplayState State(TrustedManifestIntegritySnapshot? value, bool connected,
        DateTimeOffset now, bool wasDisconnected = false) => !connected ? TrustedManifestIntegrityDisplayState.Disconnected :
        value is null ? TrustedManifestIntegrityDisplayState.Unavailable : now - value.SampledAtUtc > StaleAfter ?
        TrustedManifestIntegrityDisplayState.Stale : wasDisconnected ? TrustedManifestIntegrityDisplayState.Recovered :
        TrustedManifestIntegrityDisplayState.Current;
}

public interface ITrustedManifestIntegrityClient
{
    Task<TrustedManifestIntegritySnapshot?> GetTrustedManifestIntegrityAsync(CancellationToken cancellationToken);
}
