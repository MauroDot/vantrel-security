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

    [DataTestMethod]
    [DataRow("Network")]
    [DataRow("Quarantine")]
    [DataRow("Settings")]
    public void Existing_future_sections_remain_placeholders_without_status_refresh(string section)
    {
        Assert.IsFalse(DesktopSectionNavigation.IsWorkspace(section));
        Assert.IsFalse(DesktopSectionNavigation.RequiresStatusRefresh(section));
    }
}
