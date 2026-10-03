using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class DesktopSectionNavigationTests
{
    [TestMethod]
    public void Installation_is_a_workspace_that_refreshes_existing_status_data()
    {
        Assert.IsTrue(DesktopSectionNavigation.IsWorkspace("Installation"));
        Assert.IsTrue(DesktopSectionNavigation.RequiresStatusRefresh("Installation"));
    }

    [DataTestMethod]
    [DataRow("Protection")]
    [DataRow("Network")]
    [DataRow("Quarantine")]
    [DataRow("Settings")]
    public void Existing_future_sections_remain_placeholders_without_status_refresh(string section)
    {
        Assert.IsFalse(DesktopSectionNavigation.IsWorkspace(section));
        Assert.IsFalse(DesktopSectionNavigation.RequiresStatusRefresh(section));
    }
}
