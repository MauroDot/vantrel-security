using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class WindowsSecurityHandoffTests
{
    [TestMethod]
    public void Explicit_handoff_uses_only_the_fixed_Windows_Security_settings_uri_once()
    {
        var launcher = new CapturingLauncher { Result = true };
        var handoff = new WindowsSecurityHandoff(launcher);

        var presentation = handoff.Open();

        Assert.AreEqual(1, launcher.Calls);
        Assert.AreEqual(WindowsSecurityHandoff.SettingsUri, launcher.Target?.OriginalString);
        Assert.AreEqual("Windows Security open request was sent to Windows.", presentation.StateText);
    }

    [TestMethod]
    public void Failed_handoff_exposes_only_the_scoped_failure_message()
    {
        var launcher = new CapturingLauncher { Result = false };
        var presentation = new WindowsSecurityHandoff(launcher).Open();

        Assert.AreEqual("Windows Security could not be opened.", presentation.StateText);
        Assert.IsFalse(presentation.StateText.Contains("exception", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(presentation.StateText.Contains("HRESULT", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(presentation.StateText.Contains("diagnostic", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Launcher_exception_maps_to_the_same_scoped_failure_message()
    {
        var presentation = new WindowsSecurityHandoff(new ThrowingLauncher()).Open();

        Assert.AreEqual("Windows Security could not be opened.", presentation.StateText);
    }

    [TestMethod]
    public void Presentation_states_the_external_scope_without_scan_or_safety_claims()
    {
        var presentation = WindowsSecurityHandoffPresentation.Initial();

        Assert.AreEqual("Windows Security manages antivirus scans and any resulting actions. Vantrel does not request, monitor, interpret, or report those scans.", presentation.NoticeText);
        Assert.IsFalse(presentation.NoticeText.Contains("safe", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(presentation.NoticeText.Contains("clean", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(presentation.NoticeText.Contains("protected", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(presentation.NoticeText.Contains("detected", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(presentation.NoticeText.Contains("remediated", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(presentation.NoticeText.Contains("quarantined", StringComparison.OrdinalIgnoreCase));
    }

    private sealed class ThrowingLauncher : IWindowsSecurityHandoffLauncher
    {
        public bool TryLaunch(Uri target) => throw new InvalidOperationException("launcher failure");
    }

    private sealed class CapturingLauncher : IWindowsSecurityHandoffLauncher
    {
        internal bool Result { get; init; }
        internal int Calls { get; private set; }
        internal Uri? Target { get; private set; }

        public bool TryLaunch(Uri target)
        {
            Calls++;
            Target = target;
            return Result;
        }
    }
}
