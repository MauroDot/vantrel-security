using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class ReleaseProvenanceProtocolTests
{
    private const string Hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    [TestMethod]
    public void Tenth_request_and_response_are_strict_parameter_free_and_bounded()
    {
        Assert.AreEqual(StatusProtocol.RequestKind.ReleaseMetadata, StatusProtocol.ReadRequestKind(StatusProtocol.CreateReleaseMetadataRequest()));
        Assert.AreEqual(StatusProtocol.RequestKind.Invalid, StatusProtocol.ReadRequestKind(Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"get_release_metadata\",\"path\":\"x\"}")));
        var response = StatusProtocol.CreateReleaseMetadataResponse(Valid());
        Assert.IsTrue(StatusProtocol.TryReadReleaseMetadataResponse(response, out var value, out var failure));
        Assert.AreEqual(StatusResponseFailure.None, failure);
        Assert.AreEqual((ulong)1, value!.ReleaseSequence);
        Assert.IsTrue(response.Length < StatusProtocol.MaximumMessageBytes);
    }

    [TestMethod]
    public void Release_metadata_response_rejects_invalid_shape_enums_timestamp_sequence_and_hash()
    {
        var cases = new[]
        {
            "{\"ProtocolVersion\":1,\"Type\":\"release_metadata\",\"Provenance\":{}}",
            "{\"ProtocolVersion\":1,\"Type\":\"release_metadata\",\"Provenance\":{\"SampledAtUtc\":\"2026-09-20T00:00:00+00:00\",\"MetadataSignatureState\":999,\"ManifestBindingState\":0,\"Product\":null,\"Architecture\":null,\"Channel\":null,\"ReleaseSequence\":null,\"DisplayVersion\":null,\"PolicyDecision\":5,\"ManifestSha256\":null}}",
            Encoding.UTF8.GetString(StatusProtocol.CreateReleaseMetadataResponse(Valid())).Replace(Hash, Hash.ToLowerInvariant(), StringComparison.Ordinal),
            Encoding.UTF8.GetString(StatusProtocol.CreateReleaseMetadataResponse(Valid())).Replace("\"ReleaseSequence\":1", "\"ReleaseSequence\":0", StringComparison.Ordinal),
            Encoding.UTF8.GetString(StatusProtocol.CreateReleaseMetadataResponse(Valid())).Replace("\"Type\":\"release_metadata\"", "\"Type\":\"other\"", StringComparison.Ordinal)
        };
        foreach (var value in cases) Assert.IsFalse(StatusProtocol.TryReadReleaseMetadataResponse(Encoding.UTF8.GetBytes(value), out _, out _));
    }

    [TestMethod]
    public void Maximum_valid_release_metadata_response_has_measured_headroom()
    {
        var maximum = Valid(displayVersion: new string('V', 64), sequence: ulong.MaxValue);
        var bytes = StatusProtocol.CreateReleaseMetadataResponse(maximum);
        Assert.AreEqual(464, bytes.Length);
        Assert.AreEqual(StatusProtocol.MaximumMessageBytes - bytes.Length, 3632);
        Assert.IsTrue(StatusProtocol.TryReadReleaseMetadataResponse(bytes, out _, out _));
    }

    private static ReleaseProvenanceSnapshot Valid(string? displayVersion = null, ulong sequence = 1) => new(new DateTimeOffset(new DateTime(2026, 9, 20, 12, 0, 0, DateTimeKind.Utc).AddTicks(1234567)),
        ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.Bound, ReleaseMetadataCodec.Product, ReleaseMetadataCodec.Architecture,
        ReleaseMetadataCodec.Channel, sequence, displayVersion ?? "0.1.0", ReleasePolicyDecision.SameAcceptedRelease, Hash);
}