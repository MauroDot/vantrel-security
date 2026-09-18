using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class ComponentInspectionProtocolTests
{
    [TestMethod]
    public void Component_integrity_is_a_strict_fixed_v1_exchange()
    {
        var value = new ComponentIntegritySnapshot(DateTimeOffset.UtcNow, StatusProtocol.ComponentIntegrityPolicyRevision,
            ComponentIntegrityTarget.VantrelCoreAssembly, ComponentHashAlgorithm.Sha256, ComponentIntegrityEvaluation.Match, null);
        Assert.AreEqual(StatusProtocol.RequestKind.ComponentIntegrity, StatusProtocol.ReadRequestKind(StatusProtocol.CreateComponentIntegrityRequest()));
        Assert.IsTrue(StatusProtocol.TryReadComponentIntegrityResponse(StatusProtocol.CreateComponentIntegrityResponse(value), out var parsed, out var failure));
        Assert.AreEqual(StatusResponseFailure.None, failure); Assert.AreEqual(ComponentIntegrityEvaluation.Match, parsed!.Evaluation);
        Assert.AreEqual(StatusProtocol.RequestKind.Invalid, StatusProtocol.ReadRequestKind("{\"ProtocolVersion\":1,\"Type\":\"get_component_integrity\",\"Target\":\"x\"}"u8));
    }
    [TestMethod]
    public void Component_integrity_presentation_has_transient_recovered_contract()
    {
        var now = DateTimeOffset.UtcNow;
        var value = new ComponentIntegritySnapshot(now, StatusProtocol.ComponentIntegrityPolicyRevision, ComponentIntegrityTarget.VantrelCoreAssembly, ComponentHashAlgorithm.Sha256, ComponentIntegrityEvaluation.Match, null);
        Assert.AreEqual(ComponentIntegrityDisplayState.Unavailable, ComponentIntegrityPresentation.State(null, true, now));
        Assert.AreEqual(ComponentIntegrityDisplayState.Disconnected, ComponentIntegrityPresentation.State(value, false, now));
        Assert.AreEqual(ComponentIntegrityDisplayState.Stale, ComponentIntegrityPresentation.State(value with { SampledAtUtc = now.AddMinutes(-31) }, true, now));
        Assert.AreEqual(ComponentIntegrityDisplayState.Recovered, ComponentIntegrityPresentation.State(value, true, now, true));
        Assert.AreEqual(ComponentIntegrityDisplayState.Current, ComponentIntegrityPresentation.State(value, true, now));
    }
    private static ComponentInspectionSnapshot Valid() => new(DateTimeOffset.UtcNow, StatusProtocol.ComponentInspectionPolicyRevision,
        ComponentInspectionTarget.VantrelServiceAssembly, ComponentInspectionOutcome.Observed, ComponentInspectionReason.None,
        ComponentHashAlgorithm.Sha256, new string('A', 64), 12);

    [TestMethod]
    public void Fixed_request_and_bounded_observation_round_trip()
    {
        Assert.AreEqual(StatusProtocol.RequestKind.ComponentInspection, StatusProtocol.ReadRequestKind(StatusProtocol.CreateComponentInspectionRequest()));
        Assert.AreEqual(StatusProtocol.RequestKind.Invalid, StatusProtocol.ReadRequestKind(Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"get_component_inspection\",\"Path\":\"x\"}")));
        var frame = StatusProtocol.CreateComponentInspectionResponse(Valid());
        Assert.IsTrue(frame.Length <= StatusProtocol.MaximumMessageBytes);
        Assert.IsTrue(StatusProtocol.TryReadComponentInspectionResponse(frame, out var value, out var failure));
        Assert.AreEqual(StatusResponseFailure.None, failure); Assert.AreEqual(ComponentInspectionOutcome.Observed, value!.Outcome);
    }

    [TestMethod]
    public void Invalid_or_incomplete_shapes_are_rejected()
    {
        Assert.IsFalse(StatusProtocol.TryReadComponentInspectionResponse(new byte[4097], out _, out var oversized));
        Assert.AreEqual(StatusResponseFailure.Oversized, oversized);
        var text = Encoding.UTF8.GetString(StatusProtocol.CreateComponentInspectionResponse(Valid()));
        Assert.IsFalse(StatusProtocol.TryReadComponentInspectionResponse(Encoding.UTF8.GetBytes(text.Replace("\"Hash\":\"" + new string('A', 64) + "\"", "\"Hash\":null")), out _, out var failure));
        Assert.AreEqual(StatusResponseFailure.InvalidComponentInspection, failure);
    }

    [TestMethod]
    public void Presentation_distinguishes_loading_unavailable_stale_disconnected_and_recovered()
    {
        var now = DateTimeOffset.UtcNow;
        Assert.AreEqual(ComponentInspectionDisplayState.Unavailable, ComponentInspectionPresentation.State(null, true, now));
        Assert.AreEqual(ComponentInspectionDisplayState.Disconnected, ComponentInspectionPresentation.State(Valid(), false, now));
        Assert.AreEqual(ComponentInspectionDisplayState.Stale, ComponentInspectionPresentation.State(Valid() with { SampledAtUtc = now.AddMinutes(-31) }, true, now));
        Assert.AreEqual(ComponentInspectionDisplayState.Current, ComponentInspectionPresentation.State(Valid() with { SampledAtUtc = now }, true, now));
        Assert.AreEqual(ComponentInspectionDisplayState.Recovered, ComponentInspectionPresentation.State(Valid() with { SampledAtUtc = now }, true, now, true));
    }
}
