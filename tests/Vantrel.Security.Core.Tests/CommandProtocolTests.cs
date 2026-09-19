using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class CommandProtocolTests
{
    private const string Id = "0123456789abcdef0123456789abcdef";

    [TestMethod]
    public void Fixed_refresh_request_round_trips_with_exact_shape()
    {
        var request = CommandProtocol.CreateRefreshRequest(Id);
        Assert.IsTrue(CommandProtocol.TryReadRequest(request, out var id));
        Assert.AreEqual(Id, id);
    }

    [TestMethod]
    public void Request_rejects_unknown_duplicate_and_invalid_identifier_fields()
    {
        foreach (var value in new[]
        {
            "{\"ProtocolVersion\":1,\"Command\":\"refresh_trusted_manifest_integrity\",\"RequestId\":\"" + Id + "\",\"Path\":\"x\"}",
            "{\"ProtocolVersion\":1,\"Command\":\"refresh_trusted_manifest_integrity\",\"Command\":\"refresh_trusted_manifest_integrity\",\"RequestId\":\"" + Id + "\"}",
            "{\"ProtocolVersion\":1,\"Command\":\"refresh_trusted_manifest_integrity\",\"RequestId\":\"ABC\"}",
            "{\"ProtocolVersion\":1,\"Command\":\"get_status\",\"RequestId\":\"" + Id + "\"}"
        }) Assert.IsFalse(CommandProtocol.TryReadRequest(Encoding.UTF8.GetBytes(value), out _));
    }

    [TestMethod]
    public void Command_response_has_no_integrity_verdict_and_is_strictly_typed()
    {
        var response = new CommandResponse(Id, CommandResult.Accepted, DateTimeOffset.UtcNow, CommandFailureReason.None);
        Assert.IsTrue(CommandProtocol.TryReadResponse(CommandProtocol.CreateResponse(response), out var read));
        Assert.AreEqual(CommandResult.Accepted, read!.Result);
        var invalid = Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"command_result\",\"RequestId\":\"" + Id + "\",\"Result\":0,\"TimestampUtc\":\"2026-01-01T00:00:00+00:00\",\"Reason\":0,\"Integrity\":\"Match\"}");
        Assert.IsFalse(CommandProtocol.TryReadResponse(invalid, out _));
    }
}
