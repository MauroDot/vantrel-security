namespace Vantrel.Security.Core;

/// <summary>Fixed capability states for the intentionally non-operational Vantrel scan boundary.</summary>
public enum ScanCapabilityState { NotEnabled }
public enum ScanActivityState { NotRunning }
public enum ScanTargetAcceptance { None }
public enum ScheduledScanTargets { NoneConfigured }
public enum ScanFeatureAvailability { NotAvailable }

/// <summary>
/// A bounded, service-sampled statement of what Vantrel can currently do. It is not a scan job,
/// settings payload, or a target policy supplied by a client.
/// </summary>
public sealed record ScanCapabilitySnapshot(
    DateTimeOffset SampledAtUtc,
    string PolicyRevision,
    ScanCapabilityState Capability,
    ScanActivityState FileScanning,
    ScanTargetAcceptance ClientSuppliedTargets,
    ScheduledScanTargets ScheduledTargets,
    ScanFeatureAvailability Detection,
    ScanFeatureAvailability Quarantine,
    ScanFeatureAvailability Remediation,
    ScanFeatureAvailability RealTimeProtection);

public enum ScanCapabilityDisplayState { Disconnected, Unavailable, Stale, Current, Recovered }

public static class ScanCapabilityPresentation
{
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(2);

    public static ScanCapabilityDisplayState State(ScanCapabilitySnapshot? snapshot, bool connected,
        DateTimeOffset now, bool wasDisconnected = false)
    {
        if (!connected) return ScanCapabilityDisplayState.Disconnected;
        if (snapshot is null) return ScanCapabilityDisplayState.Unavailable;
        if (now - snapshot.SampledAtUtc > StaleAfter) return ScanCapabilityDisplayState.Stale;
        return wasDisconnected ? ScanCapabilityDisplayState.Recovered : ScanCapabilityDisplayState.Current;
    }
}

public interface IScanCapabilityClient
{
    Task<ScanCapabilitySnapshot?> GetScanCapabilityAsync(CancellationToken cancellationToken);
}
