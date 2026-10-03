namespace Vantrel.Security.Desktop;

internal enum WindowsFirewallProfileObservationDisplayState { Current, Stale, Empty, Partial, Unavailable }

internal sealed record WindowsFirewallProfileObservationPresentation(
    string NoticeText,
    string StateText,
    WindowsFirewallProfileObservationDisplayState State,
    IReadOnlyList<string> ProfileText)
{
    internal const string Notice =
        "Windows-reported firewall profile observations are shown for this interactive session. They do not assess network safety, Vantrel active protection, firewall effectiveness, intrusion detection, malware, or configuration completeness.";
    internal static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(2);

    internal static WindowsFirewallProfileObservationPresentation Initial() => new(Notice,
        "Windows firewall profile observations have not been observed in this view.",
        WindowsFirewallProfileObservationDisplayState.Unavailable, []);

    internal static WindowsFirewallProfileObservationPresentation Create(WindowsFirewallProfileObservationSnapshot? snapshot,
        DateTimeOffset now)
    {
        if (snapshot is null) return Initial();
        var state = now - snapshot.ObservedAtUtc > StaleAfter ? WindowsFirewallProfileObservationDisplayState.Stale :
            snapshot.State switch
            {
                WindowsFirewallProfileObservationState.Current => WindowsFirewallProfileObservationDisplayState.Current,
                WindowsFirewallProfileObservationState.Empty => WindowsFirewallProfileObservationDisplayState.Empty,
                WindowsFirewallProfileObservationState.Partial => WindowsFirewallProfileObservationDisplayState.Partial,
                _ => WindowsFirewallProfileObservationDisplayState.Unavailable
            };
        return new(Notice, FormatStateText(state), state, snapshot.Profiles.Select(FormatProfile).ToArray());
    }

    private static string FormatStateText(WindowsFirewallProfileObservationDisplayState state) => state switch
    {
        WindowsFirewallProfileObservationDisplayState.Current => "Current Windows firewall profile observation.",
        WindowsFirewallProfileObservationDisplayState.Stale => "Stale Windows firewall profile observation; it is not refreshed automatically.",
        WindowsFirewallProfileObservationDisplayState.Empty => "Windows reported no active firewall profile in this observation.",
        WindowsFirewallProfileObservationDisplayState.Partial => "Windows firewall profile observation is partial; only listed profile observations were available.",
        _ => "Windows firewall profile observation is unavailable in this interactive session."
    };

    private static string FormatProfile(WindowsFirewallProfileObservation profile)
    {
        var name = profile.Profile switch
        {
            WindowsFirewallProfile.Domain => "Domain",
            WindowsFirewallProfile.Private => "Private",
            _ => "Public"
        };
        if (profile.Activity == WindowsFirewallProfileActivity.NotActive)
            return $"{name} profile: not active in this Windows profile observation.";
        if (profile.Activity == WindowsFirewallProfileActivity.Unknown)
            return $"{name} profile: Windows activity state unavailable.";
        return profile.LocalState switch
        {
            WindowsFirewallLocalState.Enabled => $"{name} profile: active; Windows-reported firewall enabled locally.",
            WindowsFirewallLocalState.Disabled => $"{name} profile: active; Windows-reported firewall disabled locally.",
            WindowsFirewallLocalState.Unknown => $"{name} profile: active; Windows-reported firewall state unknown.",
            _ => $"{name} profile: active; Windows-reported firewall state unavailable."
        };
    }
}
