namespace Vantrel.Security.Desktop;

internal enum WindowsSecurityProviderInventoryDisplayState { Current, Stale, Empty, Partial, Incomplete, Unavailable }

internal sealed record WindowsSecurityProviderInventoryPresentation(
    string NoticeText,
    string StateText,
    WindowsSecurityProviderInventoryDisplayState State,
    IReadOnlyList<string> EntryText)
{
    internal const string Notice =
        "Windows-reported registered providers are shown for this interactive session. This inventory does not assess Vantrel active protection, malware, detection, provider effectiveness, or firewall configuration.";
    internal static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(2);

    internal static WindowsSecurityProviderInventoryPresentation Initial() =>
        new(Notice, "Windows Security Center provider inventory has not been observed in this view.",
            WindowsSecurityProviderInventoryDisplayState.Unavailable, []);

    internal static WindowsSecurityProviderInventoryPresentation Create(WindowsSecurityProviderInventorySnapshot? snapshot, DateTimeOffset now)
    {
        if (snapshot is null) return Initial();
        var categoryStates = new[] { snapshot.Antivirus.State, snapshot.Firewall.State };
        var state = now - snapshot.CollectedAtUtc > StaleAfter ? WindowsSecurityProviderInventoryDisplayState.Stale :
            categoryStates.All(value => value == WindowsSecurityProviderCategoryState.Unavailable) ? WindowsSecurityProviderInventoryDisplayState.Unavailable :
            categoryStates.Any(value => value == WindowsSecurityProviderCategoryState.Unavailable ||
                value == WindowsSecurityProviderCategoryState.Partial) ? WindowsSecurityProviderInventoryDisplayState.Partial :
            categoryStates.Any(value => value == WindowsSecurityProviderCategoryState.Incomplete) ? WindowsSecurityProviderInventoryDisplayState.Incomplete :
            categoryStates.All(value => value == WindowsSecurityProviderCategoryState.Empty) ? WindowsSecurityProviderInventoryDisplayState.Empty :
            WindowsSecurityProviderInventoryDisplayState.Current;
        var entries = snapshot.Antivirus.Entries.Concat(snapshot.Firewall.Entries)
            .Select(entry => $"Windows-reported {CategoryName(entry.Category)} provider: {entry.DisplayName} — state reported by Windows: {entry.State}.")
            .ToArray();
        return new(Notice, BuildStateText(state, snapshot), state, entries);
    }

    private static string BuildStateText(WindowsSecurityProviderInventoryDisplayState state, WindowsSecurityProviderInventorySnapshot snapshot) => state switch
    {
        WindowsSecurityProviderInventoryDisplayState.Current => "Current Windows Security Center provider inventory.",
        WindowsSecurityProviderInventoryDisplayState.Stale => "Stale Windows Security Center provider inventory; it is not refreshed automatically.",
        WindowsSecurityProviderInventoryDisplayState.Empty => "Windows Security Center reported no registered antivirus or firewall providers.",
        WindowsSecurityProviderInventoryDisplayState.Partial => "Windows Security Center provider inventory is partial; only listed providers were observed.",
        WindowsSecurityProviderInventoryDisplayState.Incomplete => "Provider inventory incomplete; only listed providers were observed.",
        _ => UnavailableText(snapshot)
    };

    private static string UnavailableText(WindowsSecurityProviderInventorySnapshot snapshot)
    {
        var antivirus = snapshot.Antivirus.State == WindowsSecurityProviderCategoryState.Unavailable;
        var firewall = snapshot.Firewall.State == WindowsSecurityProviderCategoryState.Unavailable;
        return antivirus && firewall ? "Windows Security Center provider inventory is unavailable in this interactive session." :
            antivirus ? "Windows Security Center antivirus provider inventory is unavailable in this interactive session." :
            "Windows Security Center firewall provider inventory is unavailable in this interactive session.";
    }

    private static string CategoryName(WindowsSecurityProviderCategory category) =>
        category == WindowsSecurityProviderCategory.Antivirus ? "antivirus" : "firewall";
}
