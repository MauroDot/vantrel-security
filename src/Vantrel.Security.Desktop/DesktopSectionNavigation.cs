namespace Vantrel.Security.Desktop;

internal static class DesktopSectionNavigation
{
    internal static bool IsWorkspace(string section) => section is
        "Dashboard" or "Scan" or "Installation" or "System Health" or "Activity";

    internal static bool RequiresStatusRefresh(string section) => section is
        "Scan" or "Installation" or "System Health" or "Activity";
}
