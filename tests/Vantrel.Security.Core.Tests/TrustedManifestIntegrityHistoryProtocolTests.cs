using System.Collections.Immutable;
using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class TrustedManifestIntegrityHistoryProtocolTests
{
    [TestMethod]
    public void Ninth_request_is_parameter_free_and_response_is_strict()
    {
        Assert.AreEqual(StatusProtocol.RequestKind.TrustedManifestIntegrityHistory,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateTrustedManifestIntegrityHistoryRequest()));
        Assert.AreEqual(StatusProtocol.RequestKind.Invalid, StatusProtocol.ReadRequestKind(
            Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"get_trusted_manifest_integrity_history\",\"x\":1}")));
        Assert.IsTrue(StatusProtocol.TryReadTrustedManifestIntegrityHistoryResponse(
            StatusProtocol.CreateTrustedManifestIntegrityHistoryResponse(Snapshot(1)), out var value, out var failure));
        Assert.AreEqual(StatusResponseFailure.None, failure); Assert.AreEqual(1, value!.Entries.Length);
    }

    [TestMethod]
    public void History_rejects_extra_missing_invalid_and_oversized_values()
    {
        var invalid = Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"trusted_manifest_integrity_history\",\"History\":{\"ServiceStartedAtUtc\":\"2026-09-20T00:00:00+00:00\",\"CapturedAtUtc\":\"2026-09-20T00:01:00+00:00\",\"Entries\":[{\"SampledAtUtc\":\"2026-09-20T00:00:30+00:00\",\"SignatureState\":999,\"Evaluation\":0,\"Path\":\"x\"}]}}" );
        Assert.IsFalse(StatusProtocol.TryReadTrustedManifestIntegrityHistoryResponse(invalid, out _, out var failure));
        Assert.AreEqual(StatusResponseFailure.InvalidTrustedManifestIntegrityHistory, failure);
        Assert.IsFalse(StatusProtocol.TryReadTrustedManifestIntegrityHistoryResponse(new byte[StatusProtocol.MaximumMessageBytes + 1], out _, out failure));
        Assert.AreEqual(StatusResponseFailure.Oversized, failure);
    }

    [TestMethod]
    public void History_rejects_duplicate_missing_invalid_timestamp_and_unknown_enum_values()
    {
        var values = new[]
        {
            "{\"ProtocolVersion\":1,\"Type\":\"trusted_manifest_integrity_history\",\"History\":{\"ServiceStartedAtUtc\":\"2026-09-20T00:00:00Z\",\"CapturedAtUtc\":\"2026-09-20T00:01:00Z\",\"Entries\":[]},\"History\":{\"ServiceStartedAtUtc\":\"2026-09-20T00:00:00Z\",\"CapturedAtUtc\":\"2026-09-20T00:01:00Z\",\"Entries\":[]}}",
            "{\"ProtocolVersion\":1,\"Type\":\"trusted_manifest_integrity_history\",\"History\":{\"ServiceStartedAtUtc\":\"2026-09-20T00:00:00Z\",\"Entries\":[]}}",
            "{\"ProtocolVersion\":1,\"Type\":\"trusted_manifest_integrity_history\",\"History\":{\"ServiceStartedAtUtc\":\"not-a-time\",\"CapturedAtUtc\":\"2026-09-20T00:01:00Z\",\"Entries\":[]}}",
            "{\"ProtocolVersion\":1,\"Type\":\"trusted_manifest_integrity_history\",\"History\":{\"ServiceStartedAtUtc\":\"2026-09-20T00:00:00Z\",\"CapturedAtUtc\":\"2026-09-20T00:01:00Z\",\"Entries\":[{\"SampledAtUtc\":\"2026-09-20T00:00:30Z\",\"SignatureState\":999,\"Evaluation\":0}]}}"
        };
        for (var index = 0; index < values.Length; index++)
        {
            Assert.IsFalse(StatusProtocol.TryReadTrustedManifestIntegrityHistoryResponse(Encoding.UTF8.GetBytes(values[index]), out _, out var failure));
            Assert.IsTrue(failure is StatusResponseFailure.MalformedJson or StatusResponseFailure.InvalidTrustedManifestIntegrityHistory);
        }
    }

    [TestMethod]
    public void Maximum_twelve_record_response_fits_existing_frame()
    {
        var bytes = StatusProtocol.CreateTrustedManifestIntegrityHistoryResponse(Snapshot(12));
        Console.WriteLine($"Maximum 12-record trusted-manifest integrity history response: {bytes.Length} bytes; headroom: {StatusProtocol.MaximumMessageBytes - bytes.Length} bytes.");
        Assert.IsTrue(bytes.Length < StatusProtocol.MaximumMessageBytes);
    }

    private static TrustedManifestIntegrityHistorySnapshot Snapshot(int count)
    {
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);
        var entries = Enumerable.Range(0, count).Select(index => new TrustedManifestIntegrityHistoryRecord(
            start.AddSeconds(count - index), TrustedManifestSignatureState.Valid,
            index % 2 == 0 ? TrustedManifestInstallationEvaluation.AllMatch : TrustedManifestInstallationEvaluation.ComponentMismatch)).ToImmutableArray();
        return new TrustedManifestIntegrityHistorySnapshot(start, start.AddMinutes(2), entries);
    }
}
