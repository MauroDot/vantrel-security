using System.Text.Json;

namespace Vantrel.Security.Core;

public enum StatusResponseFailure
{
    None,
    Empty,
    Oversized,
    MalformedJson,
    UnsupportedVersion,
    UnexpectedType,
    InvalidStatus
}

public static class StatusProtocol
{
    public const int Version = 1;
    public const int MaximumMessageBytes = 4096;
    public const string PipeName = "Vantrel.Security.Status.v1";
    public const string ServiceName = "VantrelSecurityService";

    private sealed record Request(int ProtocolVersion, string Type);
    private sealed record Response(int ProtocolVersion, string Type, SecurityServiceStatus Status);

    public static byte[] CreateRequest() => JsonSerializer.SerializeToUtf8Bytes(new Request(Version, "get_status"));

    public static bool IsValidRequest(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length is 0 or > MaximumMessageBytes) return false;
        try
        {
            var request = JsonSerializer.Deserialize<Request>(utf8);
            return request is { ProtocolVersion: Version, Type: "get_status" };
        }
        catch (JsonException) { return false; }
    }

    public static byte[] CreateResponse(SecurityServiceStatus status) =>
        JsonSerializer.SerializeToUtf8Bytes(new Response(Version, "status", status));

    public static bool TryReadResponse(ReadOnlySpan<byte> utf8, out SecurityServiceStatus? status) =>
        TryReadResponse(utf8, out status, out _);

    public static bool TryReadResponse(ReadOnlySpan<byte> utf8, out SecurityServiceStatus? status,
        out StatusResponseFailure failure)
    {
        status = null;
        failure = utf8.Length switch
        {
            0 => StatusResponseFailure.Empty,
            > MaximumMessageBytes => StatusResponseFailure.Oversized,
            _ => StatusResponseFailure.None
        };
        if (failure != StatusResponseFailure.None) return false;
        try
        {
            var response = JsonSerializer.Deserialize<Response>(utf8);
            if (response is null)
            {
                failure = StatusResponseFailure.MalformedJson;
                return false;
            }
            if (response.ProtocolVersion != Version)
            {
                failure = StatusResponseFailure.UnsupportedVersion;
                return false;
            }
            if (response.Type != "status")
            {
                failure = StatusResponseFailure.UnexpectedType;
                return false;
            }
            if (response.Status is null)
            {
                failure = StatusResponseFailure.InvalidStatus;
                return false;
            }
            var value = response.Status;
            if (!Enum.IsDefined(value.Protection) || value.Version is null ||
                value.Version.Major < 0 || value.Version.Minor < 0 || value.Version.Patch < 0 ||
                value.StartedAtUtc > value.HeartbeatAtUtc || value.HeartbeatAtUtc > DateTimeOffset.UtcNow.AddMinutes(1))
            {
                failure = StatusResponseFailure.InvalidStatus;
                return false;
            }
            status = value;
            return true;
        }
        catch (JsonException)
        {
            failure = StatusResponseFailure.MalformedJson;
            return false;
        }
    }
}
