namespace Vantrel.Security.Core;

public enum ComponentInspectionTarget { VantrelServiceAssembly }
public enum ComponentInspectionOutcome { Observed, Unavailable, Incomplete }
public enum ComponentInspectionReason { None, NotInstalledService, AccessDenied, ReparsePoint, OutsideInstallRoot, NotRegularFile, SizeLimitExceeded, ChangedDuringRead, TimedOut, IoFailure }
public enum ComponentHashAlgorithm { Sha256 }
public enum ComponentInspectionDisplayState { Disconnected, Unavailable, Stale, Current, Recovered }

/// <summary>A bounded Vantrel observation. It is not a detection, verdict, or integrity decision.</summary>
public sealed record ComponentInspectionSnapshot(DateTimeOffset SampledAtUtc, string PolicyRevision,
    ComponentInspectionTarget Target, ComponentInspectionOutcome Outcome, ComponentInspectionReason Reason,
    ComponentHashAlgorithm? HashAlgorithm, string? Hash, long? ObservedByteLength);

public static class ComponentInspectionPresentation
{
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(30);
    public static ComponentInspectionDisplayState State(ComponentInspectionSnapshot? value, bool connected,
        DateTimeOffset now, bool wasDisconnected = false) => !connected ? ComponentInspectionDisplayState.Disconnected :
        value is null ? ComponentInspectionDisplayState.Unavailable : now - value.SampledAtUtc > StaleAfter ?
        ComponentInspectionDisplayState.Stale : wasDisconnected ? ComponentInspectionDisplayState.Recovered : ComponentInspectionDisplayState.Current;
}

public interface IComponentInspectionClient
{
    Task<ComponentInspectionSnapshot?> GetComponentInspectionAsync(CancellationToken cancellationToken);
}
