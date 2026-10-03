using System.Text.RegularExpressions;
using Vantrel.Security.Core;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class ProtectionOverviewPresentationTests
{
    [TestMethod]
    public void Overview_leads_with_explicit_active_protection_unavailable_wording()
    {
        var overview = Create(connected: true);
        Assert.AreEqual("Vantrel active protection is unavailable in this build. This page summarizes observed system-security and Vantrel installation status.", overview.NoticeText);
    }

    [TestMethod]
    public void Overview_keeps_service_windows_installation_provenance_and_update_states_source_scoped()
    {
        var overview = Create(connected: true, installationWasDisconnected: true);
        StringAssert.StartsWith(overview.ServiceText, "Connected - service heartbeat:");
        Assert.AreEqual("Current - Windows-reported aggregate antivirus category: Good.", overview.AntivirusText);
        Assert.AreEqual("Current - Windows-reported aggregate firewall category: Poor.", overview.FirewallText);
        StringAssert.StartsWith(overview.InstallationText, "Recovered - Signed installation integrity:");
        StringAssert.StartsWith(overview.ProvenanceText, "Current - Signed release provenance and local policy:");
        StringAssert.StartsWith(overview.UpdateText, "Current - Offline update transaction and recovery state:");
    }

    [TestMethod]
    public void Disconnected_overview_marks_each_source_unavailable_without_a_composite_verdict()
    {
        var overview = ProtectionOverviewPresentation.Create(null, null, null, null, null, false, DateTimeOffset.UtcNow);
        Assert.AreEqual("Disconnected - service connection is unavailable.", overview.ServiceText);
        Assert.IsTrue(overview.AntivirusText.StartsWith("Disconnected - Windows-reported aggregate antivirus category:", StringComparison.Ordinal));
        Assert.IsTrue(overview.FirewallText.StartsWith("Disconnected - Windows-reported aggregate firewall category:", StringComparison.Ordinal));
        Assert.IsTrue(overview.InstallationText.StartsWith("Disconnected - Signed installation integrity:", StringComparison.Ordinal));
        Assert.IsTrue(overview.ProvenanceText.StartsWith("Disconnected - Signed release provenance and local policy:", StringComparison.Ordinal));
        Assert.IsTrue(overview.UpdateText.StartsWith("Disconnected - Offline update transaction and recovery state:", StringComparison.Ordinal));
        var text = string.Join(' ', overview.NoticeText, overview.ServiceText, overview.AntivirusText, overview.FirewallText,
            overview.InstallationText, overview.ProvenanceText, overview.UpdateText);
        Assert.IsFalse(Regex.IsMatch(text, "\\b(Protected|Safe|Clean|Secure)\\b", RegexOptions.IgnoreCase));
    }

    private static ProtectionOverviewPresentation Create(bool connected, bool installationWasDisconnected = false)
    {
        var now = DateTimeOffset.UtcNow;
        var service = new SecurityServiceStatus(ProtectionState.Unavailable, new ApplicationVersion(0, 1, 0), now.AddMinutes(-2), now.AddSeconds(-5));
        var health = new SystemHealthSnapshot(now, "10.0", 10, 100, 50, WindowsAntivirusHealth.Good, WindowsFirewallHealth.Poor);
        var installation = new TrustedManifestIntegritySnapshot(now, StatusProtocol.TrustedManifestIntegrityPolicyRevision,
            TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.AllMatch, null, null);
        var provenance = new ReleaseProvenanceSnapshot(now, ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.Bound,
            "vantrel-security", "x64", "stable", 1, "0.1.0", ReleasePolicyDecision.BootstrapAccepted, null);
        var update = new UpdateTransactionSnapshot(now, UpdateTransactionPhase.Completed, false, 1, 1, UpdateTransactionResult.Completed);
        return ProtectionOverviewPresentation.Create(service, health, installation, provenance, update, connected, now,
            installationWasDisconnected);
    }
}
