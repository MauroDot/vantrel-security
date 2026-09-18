using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class StatusProtocolTests
{
    [TestMethod]
    public void Request_requires_exact_version_and_command()
    {
        Assert.IsTrue(StatusProtocol.IsValidRequest(StatusProtocol.CreateRequest()));
        Assert.IsFalse(StatusProtocol.IsValidRequest(Encoding.UTF8.GetBytes("{\"ProtocolVersion\":2,\"Type\":\"get_status\"}")));
        Assert.IsFalse(StatusProtocol.IsValidRequest(Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"delete\"}")));
        Assert.IsFalse(StatusProtocol.IsValidRequest(new byte[StatusProtocol.MaximumMessageBytes + 1]));
        Assert.IsFalse(StatusProtocol.IsValidRequest(Encoding.UTF8.GetBytes("not json")));
    }

    [TestMethod]
    public void Response_rejects_impossible_heartbeat_and_unknown_protection()
    {
        var now = DateTimeOffset.UtcNow;
        var valid = new SecurityServiceStatus(ProtectionState.Unavailable, new ApplicationVersion(0, 1, 0),
            now.AddMinutes(-1), now);
        Assert.IsTrue(StatusProtocol.TryReadResponse(StatusProtocol.CreateResponse(valid), out var decoded));
        Assert.AreEqual(valid, decoded);

        var future = valid with { HeartbeatAtUtc = now.AddDays(1) };
        Assert.IsFalse(StatusProtocol.TryReadResponse(StatusProtocol.CreateResponse(future), out _));

        var unknown = valid with { Protection = (ProtectionState)42 };
        Assert.IsFalse(StatusProtocol.TryReadResponse(StatusProtocol.CreateResponse(unknown), out _));
    }

    [TestMethod]
    public void Uptime_is_never_negative()
    {
        var now = DateTimeOffset.UtcNow;
        var status = new SecurityServiceStatus(ProtectionState.Unavailable, new ApplicationVersion(0, 1, 0), now, now);
        Assert.AreEqual(TimeSpan.Zero, status.UptimeAt(now.AddSeconds(-1)));
        Assert.AreEqual(TimeSpan.FromSeconds(3), status.UptimeAt(now.AddSeconds(3)));
    }

    [TestMethod]
    public void Response_diagnostics_distinguish_version_type_and_malformed_json()
    {
        Assert.IsFalse(StatusProtocol.TryReadResponse(
            Encoding.UTF8.GetBytes("{\"ProtocolVersion\":2,\"Type\":\"status\"}"), out _, out var versionFailure));
        Assert.AreEqual(StatusResponseFailure.UnsupportedVersion, versionFailure);

        Assert.IsFalse(StatusProtocol.TryReadResponse(
            Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"execute\"}"), out _, out var typeFailure));
        Assert.AreEqual(StatusResponseFailure.UnexpectedType, typeFailure);

        Assert.IsFalse(StatusProtocol.TryReadResponse(
            Encoding.UTF8.GetBytes("not json"), out _, out var jsonFailure));
        Assert.AreEqual(StatusResponseFailure.MalformedJson, jsonFailure);
    }
}
