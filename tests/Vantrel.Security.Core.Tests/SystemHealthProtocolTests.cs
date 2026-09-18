using System.Text;
using System.Text.Json;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class SystemHealthProtocolTests
{
    [TestMethod]
    public void Fixed_health_request_is_distinct_from_existing_status_request()
    {
        Assert.AreEqual(StatusProtocol.RequestKind.Status,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateRequest()));
        Assert.AreEqual(StatusProtocol.RequestKind.SystemHealth,
            StatusProtocol.ReadRequestKind(StatusProtocol.CreateSystemHealthRequest()));
        Assert.IsTrue(StatusProtocol.IsValidRequest(StatusProtocol.CreateRequest()));
        Assert.IsFalse(StatusProtocol.IsValidRequest(StatusProtocol.CreateSystemHealthRequest()));
        foreach (var invalid in new[]
        {
            "not json", "{\"ProtocolVersion\":2,\"Type\":\"get_system_health\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"execute\"}",
            "{\"ProtocolVersion\":1,\"Type\":\"get_system_health\",\"Path\":\"C:\\\\Windows\"}",
            "{\"ProtocolVersion\":1,\"ProtocolVersion\":1,\"Type\":\"get_system_health\"}"
        })
            Assert.AreEqual(StatusProtocol.RequestKind.Invalid,
                StatusProtocol.ReadRequestKind(Encoding.UTF8.GetBytes(invalid)));
        Assert.AreEqual(StatusProtocol.RequestKind.Invalid,
            StatusProtocol.ReadRequestKind(new byte[StatusProtocol.MaximumMessageBytes + 1]));
    }

    [TestMethod]
    public void Health_response_roundtrips_partial_values_and_rejects_invalid_data()
    {
        var now = DateTimeOffset.UtcNow;
        var snapshot = new SystemHealthSnapshot(now, "10.0.26100.0", 100, 1000, 200);
        var encoded = StatusProtocol.CreateSystemHealthResponse(snapshot);
        Assert.IsTrue(StatusProtocol.TryReadSystemHealthResponse(encoded, out var decoded, out _));
        Assert.AreEqual(snapshot, decoded);
        Assert.IsTrue(StatusProtocol.TryReadSystemHealthResponse(
            StatusProtocol.CreateSystemHealthResponse(snapshot with { SystemVolumeTotalBytes = null,
                SystemVolumeFreeBytes = null, WindowsVersion = null }), out _, out _));

        var invalid = new[]
        {
            snapshot with { CollectedAtUtc = default },
            snapshot with { CollectedAtUtc = now.AddDays(1) },
            snapshot with { SystemUptimeSeconds = -1 },
            snapshot with { SystemVolumeFreeBytes = 1001 },
            snapshot with { SystemVolumeFreeBytes = null },
            snapshot with { AntivirusHealth = (WindowsAntivirusHealth)99 },
            snapshot with { WindowsVersion = new string('x', 65) },
            snapshot with { WindowsVersion = "bad\nversion" }
        };
        foreach (var item in invalid)
        {
            Assert.IsFalse(StatusProtocol.TryReadSystemHealthResponse(
                StatusProtocol.CreateSystemHealthResponse(item), out _, out var failure));
            Assert.AreEqual(StatusResponseFailure.InvalidHealth, failure);
        }
        Assert.IsFalse(StatusProtocol.TryReadSystemHealthResponse(StatusProtocol.CreateResponse(
            new SecurityServiceStatus(ProtectionState.Unavailable, new ApplicationVersion(0, 1, 0), now, now)),
            out _, out var wrongType));
        Assert.AreEqual(StatusResponseFailure.UnexpectedType, wrongType);
        Assert.IsFalse(StatusProtocol.TryReadSystemHealthResponse(new byte[4097], out _, out var oversized));
        Assert.AreEqual(StatusResponseFailure.Oversized, oversized);
        Assert.IsFalse(StatusProtocol.TryReadSystemHealthResponse(Encoding.UTF8.GetBytes("not json"),
            out _, out var malformed));
        Assert.AreEqual(StatusResponseFailure.MalformedJson, malformed);
    }

    [TestMethod]
    public void Antivirus_health_is_optional_and_all_documented_states_roundtrip()
    {
        Assert.AreEqual(1, StatusProtocol.Version);
        var now = DateTimeOffset.UtcNow;
        var oldResponse = JsonSerializer.SerializeToUtf8Bytes(new
        {
            ProtocolVersion = 1,
            Type = "system_health",
            Health = new
            {
                CollectedAtUtc = now,
                WindowsVersion = "10.0.26100.0",
                SystemUptimeSeconds = 100L,
                SystemVolumeTotalBytes = 1000L,
                SystemVolumeFreeBytes = 500L
            }
        });
        Assert.IsTrue(StatusProtocol.TryReadSystemHealthResponse(oldResponse, out var old, out _));
        Assert.IsNotNull(old);
        Assert.IsNull(old.AntivirusHealth);

        foreach (var state in Enum.GetValues<WindowsAntivirusHealth>())
        {
            var snapshot = old with { AntivirusHealth = state };
            Assert.IsTrue(StatusProtocol.TryReadSystemHealthResponse(
                StatusProtocol.CreateSystemHealthResponse(snapshot), out var decoded, out _));
            Assert.AreEqual(snapshot, decoded);
        }
    }

    [TestMethod]
    public void Presentation_marks_disconnected_unavailable_stale_and_partial()
    {
        var now = DateTimeOffset.UtcNow;
        var current = new SystemHealthSnapshot(now, "10.0.26100.0", 60, 100, 50,
            WindowsAntivirusHealth.Good);
        Assert.AreEqual(SystemHealthDisplayState.Disconnected,
            SystemHealthPresentation.State(current, false, now));
        Assert.AreEqual(SystemHealthDisplayState.Unavailable,
            SystemHealthPresentation.State(null, true, now));
        Assert.AreEqual(SystemHealthDisplayState.Unavailable,
            SystemHealthPresentation.State(new SystemHealthSnapshot(now, null, null, null, null), true, now));
        Assert.AreEqual(SystemHealthDisplayState.Stale,
            SystemHealthPresentation.State(current, true, now.AddMinutes(3)));
        Assert.AreEqual(SystemHealthDisplayState.Partial,
            SystemHealthPresentation.State(current with { WindowsVersion = null }, true, now));
        Assert.AreEqual(SystemHealthDisplayState.Partial,
            SystemHealthPresentation.State(current with { AntivirusHealth = null }, true, now));
        Assert.AreEqual(SystemHealthDisplayState.Current,
            SystemHealthPresentation.State(current, true, now));
    }
}
