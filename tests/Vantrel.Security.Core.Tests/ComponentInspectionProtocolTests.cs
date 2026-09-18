using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class ComponentInspectionProtocolTests
{
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
