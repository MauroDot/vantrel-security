namespace Vantrel.Security.Desktop;

internal static class DesktopSectionNavigation
{
    internal static bool IsWorkspace(string section) => section is
        "Dashboard" or "Scan" or "File inspection" or "Installation" or "Protection" or "Network" or "System Health" or "Activity";

    internal static bool RequiresStatusRefresh(string section) => section is
        "Scan" or "Installation" or "Protection" or "System Health" or "Activity";
}
