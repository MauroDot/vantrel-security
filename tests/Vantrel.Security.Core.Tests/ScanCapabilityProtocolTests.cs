using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class ScanCapabilityProtocolTests
{
    private static ScanCapabilitySnapshot Valid(DateTimeOffset? sampled = null) => new(
        sampled ?? DateTimeOffset.UtcNow,
        StatusProtocol.ScanCapabilitySourcePolicyRevision,
        ScanCapabilityState.NotEnabled,
        ScanActivityState.NotRunning,
        ScanTargetAcceptance.None,
        ScheduledScanTargets.NoneConfigured,
        ScanFeatureAvailability.NotAvailable,
        ScanFeatureAvailability.NotAvailable,
        ScanFeatureAvailability.NotAvailable,
        ScanFeatureAvailability.NotAvailable);

    [TestMethod]
    public void Fixed_request_has_no_client_selected_scan_input()
    {
        Assert.AreEqual(StatusProtocol.RequestKind.ScanCapability,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateScanCapabilityRequest()));
        foreach (var request in new[]
        {
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Path\":\"C:\\\\x\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Target\":\"x\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Directory\":\"x\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"File\":\"x\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Filter\":\"x\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Schedule\":\"x\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Category\":1}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Exclusion\":\"x\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Option\":\"x\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Token\":\"x\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Payload\":{}}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_scan_capability\",\"Type\":\"get_scan_capability\"}",
            "{\"ProtocolVersion\":2,\"Type\":\"get_scan_capability\"}"
        })
        {
            Assert.AreEqual(StatusProtocol.RequestKind.Invalid,
                StatusProtocol.ReadRequestKind(Encoding.UTF8.GetBytes(request)));
        }
        Assert.AreEqual(StatusProtocol.RequestKind.Status,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateRequest()));
        Assert.AreEqual(StatusProtocol.RequestKind.SystemHealth,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateSystemHealthRequest()));
        Assert.AreEqual(StatusProtocol.RequestKind.Activity,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateActivityRequest()));
    }

    [TestMethod]
    public void Round_trip_is_bounded_and_truthfully_not_enabled()
    {
        var encoded = StatusProtocol.CreateScanCapabilityResponse(Valid());
        Assert.IsTrue(encoded.Length <= StatusProtocol.MaximumMessageBytes);
        Assert.IsTrue(StatusProtocol.TryReadScanCapabilityResponse(encoded, out var decoded, out var failure));
        Assert.AreEqual(StatusResponseFailure.None, failure);
        Assert.IsNotNull(decoded);
        Assert.AreEqual(ScanCapabilityState.NotEnabled, decoded.Capability);
        Assert.AreEqual(ScanActivityState.NotRunning, decoded.FileScanning);
        Assert.AreEqual(ScanTargetAcceptance.None, decoded.ClientSuppliedTargets);
        Assert.AreEqual(ScheduledScanTargets.NoneConfigured, decoded.ScheduledTargets);
        Assert.AreEqual(ScanFeatureAvailability.NotAvailable, decoded.Detection);
        Assert.AreEqual(ScanFeatureAvailability.NotAvailable, decoded.Quarantine);
        Assert.AreEqual(ScanFeatureAvailability.NotAvailable, decoded.Remediation);
        Assert.AreEqual(ScanFeatureAvailability.NotAvailable, decoded.RealTimeProtection);
    }

    [TestMethod]
    public void Response_rejects_malformed_oversized_unknown_extra_and_non_fixed_values()
    {
        Assert.IsFalse(StatusProtocol.TryReadScanCapabilityResponse(Encoding.UTF8.GetBytes("not json"), out _,
            out var malformed));
        Assert.AreEqual(StatusResponseFailure.MalformedJson, malformed);
        Assert.IsFalse(StatusProtocol.TryReadScanCapabilityResponse(new byte[4097], out _, out var oversized));
        Assert.AreEqual(StatusResponseFailure.Oversized, oversized);

        var response = Encoding.UTF8.GetString(StatusProtocol.CreateScanCapabilityResponse(Valid()));
        foreach (var mutated in new[]
        {
            response.Replace("\"Capability\":0", "\"Capability\":99"),
            response.Replace("\"FileScanning\":0", "\"FileScanning\":1"),
            response.Replace("\"ClientSuppliedTargets\":0", "\"ClientSuppliedTargets\":1"),
            response.Replace("\"ScheduledTargets\":0", "\"ScheduledTargets\":1"),
            response.Replace("\"Detection\":0", "\"Detection\":1"),
            response.Replace("scan-capability-v1", "client-policy"),
            response.Replace("\"PolicyRevision\":\"scan-capability-v1\",",
                "\"PolicyRevision\":\"scan-capability-v1\",\"Path\":\"x\","),
            response.Replace("\"PolicyRevision\":\"scan-capability-v1\",", "")
        })
        {
            Assert.IsFalse(StatusProtocol.TryReadScanCapabilityResponse(Encoding.UTF8.GetBytes(mutated), out _,
                out var failure));
            Assert.AreEqual(StatusResponseFailure.InvalidScanCapability, failure);
        }
    }

    [TestMethod]
    public void Presentation_distinguishes_all_capability_states()
    {
        var now = DateTimeOffset.UtcNow;
        Assert.AreEqual(ScanCapabilityDisplayState.Disconnected,
            ScanCapabilityPresentation.State(Valid(now), false, now));
        Assert.AreEqual(ScanCapabilityDisplayState.Unavailable,
            ScanCapabilityPresentation.State(null, true, now));
        Assert.AreEqual(ScanCapabilityDisplayState.Stale,
            ScanCapabilityPresentation.State(Valid(now.AddMinutes(-3)), true, now));
        Assert.AreEqual(ScanCapabilityDisplayState.Current,
            ScanCapabilityPresentation.State(Valid(now), true, now));
        Assert.AreEqual(ScanCapabilityDisplayState.Recovered,
            ScanCapabilityPresentation.State(Valid(now), true, now, wasDisconnected: true));
    }
}
