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
    InvalidStatus,
    InvalidHealth
}

public static class StatusProtocol
{
    public const int Version = 1;
    public const int MaximumMessageBytes = 4096;
    public const string PipeName = "Vantrel.Security.Status.v1";
    public const string ServiceName = "VantrelSecurityService";

    private sealed record Request(int ProtocolVersion, string Type);
    private sealed record Response(int ProtocolVersion, string Type, SecurityServiceStatus Status);
    private sealed record HealthResponse(int ProtocolVersion, string Type, SystemHealthSnapshot Health);

    public enum RequestKind { Invalid, Status, SystemHealth }

    public static byte[] CreateRequest() => JsonSerializer.SerializeToUtf8Bytes(new Request(Version, "get_status"));

    public static byte[] CreateSystemHealthRequest() =>
        JsonSerializer.SerializeToUtf8Bytes(new Request(Version, "get_system_health"));

    public static bool IsValidRequest(ReadOnlySpan<byte> utf8) => ReadRequestKind(utf8) == RequestKind.Status;

    public static RequestKind ReadRequestKind(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length is 0 or > MaximumMessageBytes) return RequestKind.Invalid;
        try
        {
            var request = JsonSerializer.Deserialize<Request>(utf8);
            if (request?.ProtocolVersion != Version) return RequestKind.Invalid;
            return request.Type switch
            {
                "get_status" => RequestKind.Status,
                "get_system_health" when HasOnlyFixedRequestFields(utf8) => RequestKind.SystemHealth,
                _ => RequestKind.Invalid
            };
        }
        catch (JsonException) { return RequestKind.Invalid; }
    }

    private static bool HasOnlyFixedRequestFields(ReadOnlySpan<byte> utf8)
    {
        using var document = JsonDocument.Parse(utf8.ToArray());
        if (document.RootElement.ValueKind != JsonValueKind.Object) return false;
        var versionCount = 0;
        var typeCount = 0;
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.NameEquals("ProtocolVersion")) versionCount++;
            else if (property.NameEquals("Type")) typeCount++;
            else return false;
        }
        return versionCount == 1 && typeCount == 1;
    }

    public static byte[] CreateSystemHealthResponse(SystemHealthSnapshot health) =>
        JsonSerializer.SerializeToUtf8Bytes(new HealthResponse(Version, "system_health", health));

    public static bool TryReadSystemHealthResponse(ReadOnlySpan<byte> utf8, out SystemHealthSnapshot? health,
        out StatusResponseFailure failure)
    {
        health = null;
        failure = utf8.Length switch
        {
            0 => StatusResponseFailure.Empty,
            > MaximumMessageBytes => StatusResponseFailure.Oversized,
            _ => StatusResponseFailure.None
        };
        if (failure != StatusResponseFailure.None) return false;
        try
        {
            var response = JsonSerializer.Deserialize<HealthResponse>(utf8);
            if (response is null) { failure = StatusResponseFailure.MalformedJson; return false; }
            if (response.ProtocolVersion != Version) { failure = StatusResponseFailure.UnsupportedVersion; return false; }
            if (response.Type != "system_health") { failure = StatusResponseFailure.UnexpectedType; return false; }
            var value = response.Health;
            if (value is null || value.CollectedAtUtc == default ||
                value.CollectedAtUtc > DateTimeOffset.UtcNow.AddMinutes(1) ||
                value.WindowsVersion is { Length: > 64 } ||
                (value.WindowsVersion is not null &&
                    (string.IsNullOrWhiteSpace(value.WindowsVersion) || value.WindowsVersion.Any(char.IsControl))) ||
                value.SystemUptimeSeconds is < 0 ||
                value.SystemVolumeTotalBytes is <= 0 || value.SystemVolumeFreeBytes is < 0 ||
                (value.SystemVolumeTotalBytes is null) != (value.SystemVolumeFreeBytes is null) ||
                value.SystemVolumeFreeBytes > value.SystemVolumeTotalBytes ||
                (value.AntivirusHealth is { } antivirus && !Enum.IsDefined(antivirus)) ||
                (value.FirewallHealth is { } firewall && !Enum.IsDefined(firewall)))
            {
                failure = StatusResponseFailure.InvalidHealth;
                return false;
            }
            health = value;
            return true;
        }
        catch (JsonException) { failure = StatusResponseFailure.MalformedJson; return false; }
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
