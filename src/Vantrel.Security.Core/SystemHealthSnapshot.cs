namespace Vantrel.Security.Core;

/// <summary>Windows Security Center's aggregate antivirus-category state, not Vantrel protection.</summary>
public enum WindowsAntivirusHealth { Good = 0, NotMonitored = 1, Poor = 2, Snoozed = 3 }

/// <summary>Windows Security Center's aggregate firewall-category state, not a profile or rule audit.</summary>
public enum WindowsFirewallHealth { Good = 0, NotMonitored = 1, Poor = 2, Snoozed = 3 }

/// <summary>Coarse, read-only machine information. Null means that value was unavailable.</summary>
public sealed record SystemHealthSnapshot(
    DateTimeOffset CollectedAtUtc,
    string? WindowsVersion,
    long? SystemUptimeSeconds,
    long? SystemVolumeTotalBytes,
    long? SystemVolumeFreeBytes,
    WindowsAntivirusHealth? AntivirusHealth = null,
    WindowsFirewallHealth? FirewallHealth = null);

public enum SystemHealthDisplayState { Disconnected, Unavailable, Stale, Partial, Current }

public static class SystemHealthPresentation
{
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(2);

    public static SystemHealthDisplayState State(SystemHealthSnapshot? snapshot, bool connected, DateTimeOffset now)
    {
        if (!connected) return SystemHealthDisplayState.Disconnected;
        if (snapshot is null) return SystemHealthDisplayState.Unavailable;
        if (now - snapshot.CollectedAtUtc > StaleAfter) return SystemHealthDisplayState.Stale;
        if (snapshot.WindowsVersion is null && snapshot.SystemUptimeSeconds is null &&
            snapshot.SystemVolumeTotalBytes is null && snapshot.SystemVolumeFreeBytes is null &&
            snapshot.AntivirusHealth is null && snapshot.FirewallHealth is null)
            return SystemHealthDisplayState.Unavailable;
        return snapshot.WindowsVersion is null || snapshot.SystemUptimeSeconds is null ||
            snapshot.SystemVolumeTotalBytes is null || snapshot.SystemVolumeFreeBytes is null ||
            snapshot.AntivirusHealth is null || snapshot.FirewallHealth is null
            ? SystemHealthDisplayState.Partial : SystemHealthDisplayState.Current;
    }
}

public interface ISystemHealthClient
{
    Task<SystemHealthSnapshot?> GetSystemHealthAsync(CancellationToken cancellationToken);
}
