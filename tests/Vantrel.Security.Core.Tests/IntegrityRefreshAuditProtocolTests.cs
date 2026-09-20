using System.Collections.Immutable;
using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class IntegrityRefreshAuditProtocolTests
{
    [TestMethod]
    public void Eighth_request_and_response_are_strictly_typed_and_parameter_free()
    {
        Assert.AreEqual(StatusProtocol.RequestKind.IntegrityRefreshAudit,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateIntegrityRefreshAuditRequest()));
        Assert.AreEqual(StatusProtocol.RequestKind.Invalid, StatusProtocol.ReadRequestKind(
            Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"get_integrity_refresh_audit\",\"requestId\":\"x\"}")));

        var bytes = StatusProtocol.CreateIntegrityRefreshAuditResponse(CreateSnapshot(1));
        Assert.IsTrue(StatusProtocol.TryReadIntegrityRefreshAuditResponse(bytes, out var read, out var failure));
        Assert.AreEqual(StatusResponseFailure.None, failure);
        Assert.AreEqual(1, read!.Entries.Length);
        Assert.AreEqual(IntegrityRefreshAuditOutcome.Accepted, read.Entries[0].Outcome);
    }

    [TestMethod]
    public void Audit_response_rejects_invalid_enum_timestamp_and_extra_safe_field()
    {
        var invalidEnum = Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"integrity_refresh_audit\",\"Audit\":{\"ServiceStartedAtUtc\":\"2026-09-19T00:00:00+00:00\",\"CapturedAtUtc\":\"2026-09-19T00:01:00+00:00\",\"Entries\":[{\"Command\":0,\"Caller\":999,\"Outcome\":0,\"OccurredAtUtc\":\"2026-09-19T00:00:30+00:00\"}]}}");
        Assert.IsFalse(StatusProtocol.TryReadIntegrityRefreshAuditResponse(invalidEnum, out _, out var enumFailure));
        Assert.AreEqual(StatusResponseFailure.InvalidIntegrityRefreshAudit, enumFailure);

        var extra = Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"integrity_refresh_audit\",\"Audit\":{\"ServiceStartedAtUtc\":\"2026-09-19T00:00:00+00:00\",\"CapturedAtUtc\":\"2026-09-19T00:01:00+00:00\",\"Entries\":[{\"Command\":0,\"Caller\":0,\"Outcome\":0,\"OccurredAtUtc\":\"2026-09-19T00:00:30+00:00\",\"RequestId\":\"x\"}]}}");
        Assert.IsFalse(StatusProtocol.TryReadIntegrityRefreshAuditResponse(extra, out _, out var extraFailure));
        Assert.AreEqual(StatusResponseFailure.InvalidIntegrityRefreshAudit, extraFailure);
    }

    [TestMethod]
    public void Maximum_safe_response_is_under_the_existing_four_kib_frame_limit()
    {
        var bytes = StatusProtocol.CreateIntegrityRefreshAuditResponse(CreateSnapshot(16));
        Console.WriteLine($"Maximum 16-record integrity refresh audit response: {bytes.Length} bytes.");
        Assert.IsTrue(bytes.Length < StatusProtocol.MaximumMessageBytes,
            $"Expected maximum safe audit response below {StatusProtocol.MaximumMessageBytes}; got {bytes.Length}.");
    }

    [TestMethod]
    public void Audit_response_rejects_more_than_sixteen_entries_and_oversized_input()
    {
        var tooMany = StatusProtocol.CreateIntegrityRefreshAuditResponse(CreateSnapshot(17));
        Assert.IsFalse(StatusProtocol.TryReadIntegrityRefreshAuditResponse(tooMany, out _, out var countFailure));
        Assert.AreEqual(StatusResponseFailure.InvalidIntegrityRefreshAudit, countFailure);
        Assert.IsFalse(StatusProtocol.TryReadIntegrityRefreshAuditResponse(new byte[StatusProtocol.MaximumMessageBytes + 1], out _, out var sizeFailure));
        Assert.AreEqual(StatusResponseFailure.Oversized, sizeFailure);
    }

    private static IntegrityRefreshAuditSnapshot CreateSnapshot(int count)
    {
        var started = DateTimeOffset.UtcNow.AddMinutes(-1);
        var entries = Enumerable.Range(0, count).Select(index => new IntegrityRefreshAuditRecord(
            IntegrityRefreshAuditCommandKind.RefreshTrustedManifestIntegrity,
            CommandCallerClassification.InteractiveUser,
            (index % 7) switch
            {
                0 => IntegrityRefreshAuditOutcome.Accepted,
                1 => IntegrityRefreshAuditOutcome.AlreadyInProgress,
                2 => IntegrityRefreshAuditOutcome.Duplicate,
                3 => IntegrityRefreshAuditOutcome.RateLimited,
                4 => IntegrityRefreshAuditOutcome.Completed,
                5 => IntegrityRefreshAuditOutcome.Failed,
                _ => IntegrityRefreshAuditOutcome.Cancelled
            }, started.AddSeconds(index))).ToImmutableArray();
        return new IntegrityRefreshAuditSnapshot(started, started.AddMinutes(1), entries);
    }
}
