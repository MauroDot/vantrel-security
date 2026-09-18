namespace Vantrel.Security.Core;

public enum ComponentIntegrityTarget { VantrelCoreAssembly }
public enum ComponentIntegrityEvaluation { Match, Mismatch, ReferenceUnavailable, ObservationUnavailable }
public enum ComponentIntegrityDisplayState { Disconnected, Unavailable, Stale, Current, Recovered }

/// <summary>Build-pinned comparison for one fixed Vantrel component; this is not a malware or system-wide trust verdict.</summary>
public sealed record ComponentIntegritySnapshot(DateTimeOffset SampledAtUtc, string PolicyRevision,
    ComponentIntegrityTarget Target, ComponentHashAlgorithm Algorithm, ComponentIntegrityEvaluation Evaluation,
    ComponentInspectionReason? ObservationReason);

public static class ComponentIntegrityPresentation
{
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(30);
    public static ComponentIntegrityDisplayState State(ComponentIntegritySnapshot? value, bool connected, DateTimeOffset now, bool wasDisconnected = false) =>
        !connected ? ComponentIntegrityDisplayState.Disconnected : value is null ? ComponentIntegrityDisplayState.Unavailable :
        now - value.SampledAtUtc > StaleAfter ? ComponentIntegrityDisplayState.Stale : wasDisconnected ? ComponentIntegrityDisplayState.Recovered : ComponentIntegrityDisplayState.Current;
}

public interface IComponentIntegrityClient
{
    Task<ComponentIntegritySnapshot?> GetComponentIntegrityAsync(CancellationToken cancellationToken);
}
