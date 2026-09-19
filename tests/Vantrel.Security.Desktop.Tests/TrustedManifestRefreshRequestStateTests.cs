using System.Text.RegularExpressions;
using Vantrel.Security.Core;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class TrustedManifestRefreshRequestStateTests
{
    [TestMethod]
    public void Disconnected_or_inflight_desktop_cannot_start_another_refresh()
    {
        var state = new TrustedManifestRefreshRequestState();
        Assert.IsFalse(state.TryBegin(false, Current(), out _));
        Assert.IsTrue(state.TryBegin(true, Current(), out var id));
        Assert.IsNotNull(id);
        Assert.IsTrue(Regex.IsMatch(id, "^[0-9a-f]{32}$"));
        Assert.IsFalse(state.TryBegin(true, Current(), out _));
        state.Complete();
        Assert.IsTrue(state.TryBegin(true, Current(), out var next));
        Assert.AreNotEqual(id, next);
    }

    [TestMethod]
    public void Admission_alone_cannot_complete_refresh_and_only_newer_status_evidence_can()
    {
        var baseline = Current(); var state = new TrustedManifestRefreshRequestState();
        Assert.IsTrue(state.TryBegin(true, baseline, out _));
        Assert.IsTrue(state.IsInFlight);
        Assert.IsFalse(state.HasNewerStatusSnapshot(baseline));
        Assert.IsFalse(state.HasNewerStatusSnapshot(baseline with { SampledAtUtc = baseline.SampledAtUtc.AddTicks(-1) }));
        Assert.IsTrue(state.HasNewerStatusSnapshot(baseline with { SampledAtUtc = baseline.SampledAtUtc.AddTicks(1) }));
        state.Complete();
        Assert.IsFalse(state.IsInFlight);
    }

    [TestMethod]
    public void Refresh_control_presentation_tracks_status_connection_and_preserves_meaningful_results()
    {
        var disconnected = TrustedManifestRefreshControlPresentation.Create(false, false, string.Empty);
        Assert.IsFalse(disconnected.IsEnabled);
        Assert.AreEqual(TrustedManifestRefreshControlPresentation.DisconnectedGuidance, disconnected.StatusText);

        var connected = TrustedManifestRefreshControlPresentation.Create(true, false, disconnected.StatusText);
        Assert.IsTrue(connected.IsEnabled);
        Assert.AreEqual(string.Empty, connected.StatusText);

        var inFlight = TrustedManifestRefreshControlPresentation.Create(true, true, "Refreshing…");
        Assert.IsFalse(inFlight.IsEnabled);
        Assert.AreEqual("Refreshing…", inFlight.StatusText);

        var completed = TrustedManifestRefreshControlPresentation.Create(true, false, "Refresh completed from a newer service sample.");
        Assert.IsTrue(completed.IsEnabled);
        Assert.AreEqual("Refresh completed from a newer service sample.", completed.StatusText);

        var rejected = TrustedManifestRefreshControlPresentation.Create(true, false, "Refresh request was not accepted; the last service sample remains displayed.");
        Assert.IsTrue(rejected.IsEnabled);
        Assert.AreEqual("Refresh request was not accepted; the last service sample remains displayed.", rejected.StatusText);

        var cancelled = TrustedManifestRefreshControlPresentation.Create(true, false, "Refresh was cancelled; the last service sample remains displayed.");
        Assert.IsTrue(cancelled.IsEnabled);
        Assert.AreEqual("Refresh was cancelled; the last service sample remains displayed.", cancelled.StatusText);

        var laterDisconnect = TrustedManifestRefreshControlPresentation.Create(false, false, completed.StatusText);
        Assert.IsFalse(laterDisconnect.IsEnabled);
        Assert.AreEqual(TrustedManifestRefreshControlPresentation.DisconnectedGuidance, laterDisconnect.StatusText);
    }

    private static TrustedManifestIntegritySnapshot Current() => new(DateTimeOffset.UtcNow,
        StatusProtocol.TrustedManifestIntegrityPolicyRevision, TrustedManifestSignatureState.Valid,
        TrustedManifestInstallationEvaluation.AllMatch, null, null);
}
