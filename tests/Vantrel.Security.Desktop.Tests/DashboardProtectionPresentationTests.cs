using Vantrel.Security.Core;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class DashboardProtectionPresentationTests
{
    [DataTestMethod]
    [DataRow(ProtectionState.Unavailable)]
    [DataRow(ProtectionState.Protected)]
    public void Every_protocol_protection_state_renders_only_the_unavailable_active_protection_presentation(ProtectionState protection)
    {
        var presentation = DashboardProtectionPresentation.Create(protection);

        Assert.AreEqual("Unavailable", presentation.StateText);
        Assert.AreEqual("Vantrel active protection is unavailable in this build.", presentation.NoticeText);
        Assert.IsFalse(presentation.StateText.Contains("Protected", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(presentation.NoticeText.Contains("Protected", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Missing_status_also_renders_only_the_unavailable_active_protection_presentation()
    {
        var presentation = DashboardProtectionPresentation.Create(null);

        Assert.AreEqual("Unavailable", presentation.StateText);
        Assert.AreEqual("Vantrel active protection is unavailable in this build.", presentation.NoticeText);
    }
}
