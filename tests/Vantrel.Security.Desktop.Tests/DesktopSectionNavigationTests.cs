using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class DesktopSectionNavigationTests
{
    [TestMethod]
    public void Installation_and_protection_are_workspaces_that_refresh_existing_status_data()
    {
        Assert.IsTrue(DesktopSectionNavigation.IsWorkspace("Installation"));
        Assert.IsTrue(DesktopSectionNavigation.RequiresStatusRefresh("Installation"));
        Assert.IsTrue(DesktopSectionNavigation.IsWorkspace("Protection"));
        Assert.IsTrue(DesktopSectionNavigation.RequiresStatusRefresh("Protection"));
    }

    [TestMethod]
    public void File_inspection_is_a_local_workspace_without_a_service_status_refresh()
    {
        Assert.IsTrue(DesktopSectionNavigation.IsWorkspace("File inspection"));
        Assert.IsFalse(DesktopSectionNavigation.RequiresStatusRefresh("File inspection"));
        Assert.IsTrue(DesktopSectionNavigation.IsWorkspace("Scan"));
        Assert.IsTrue(DesktopSectionNavigation.RequiresStatusRefresh("Scan"));
    }

    [DataTestMethod]
    [DataRow("Quarantine")]
    [DataRow("Settings")]
    public void Existing_future_sections_remain_placeholders_without_status_refresh(string section)
    {
        Assert.IsFalse(DesktopSectionNavigation.IsWorkspace(section));
        Assert.IsFalse(DesktopSectionNavigation.RequiresStatusRefresh(section));
    }

    [TestMethod]
    public void Network_is_a_local_workspace_without_a_service_status_refresh()
    {
        Assert.IsTrue(DesktopSectionNavigation.IsWorkspace("Network"));
        Assert.IsFalse(DesktopSectionNavigation.RequiresStatusRefresh("Network"));
    }
}
