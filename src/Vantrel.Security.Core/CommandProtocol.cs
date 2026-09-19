using System.Text.Json;
using System.Text.RegularExpressions;

namespace Vantrel.Security.Core;

public enum CommandResult { Accepted, AlreadyInProgress, Duplicate, Rejected, Unavailable }
public enum CommandFailureReason { None, Unauthorized, InvalidRequest, UnsupportedCommand, RateLimited, ServiceStopping, Unavailable }
public sealed record CommandResponse(string RequestId, CommandResult Result, DateTimeOffset TimestampUtc, CommandFailureReason Reason);
public interface ITrustedManifestRefreshCommandClient
{
    Task<CommandResponse?> RefreshTrustedManifestIntegrityAsync(string requestId, CancellationToken cancellationToken);
}

/// <summary>Strict protocol for the one authorized command endpoint. It is deliberately separate from StatusProtocol.</summary>
public static class CommandProtocol
{
    public const int Version = 1;
    public const int MaximumMessageBytes = 4096;
    public const string PipeName = "Vantrel.Security.Command.v1";
    public const string RefreshTrustedManifestIntegrity = "refresh_trusted_manifest_integrity";
    private static readonly Regex RequestIdPattern = new("^[0-9a-f]{32}$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private sealed record Request(int ProtocolVersion, string Command, string RequestId);
    private sealed record Response(int ProtocolVersion, string Type, string RequestId, CommandResult Result, DateTimeOffset TimestampUtc, CommandFailureReason Reason);

    public static bool IsValidRequestId(string? value) => value is not null && RequestIdPattern.IsMatch(value);
    public static byte[] CreateRefreshRequest(string requestId)
    {
        if (!IsValidRequestId(requestId)) throw new ArgumentException("Request ID must be 32 lowercase hexadecimal characters.", nameof(requestId));
        return JsonSerializer.SerializeToUtf8Bytes(new Request(Version, RefreshTrustedManifestIntegrity, requestId));
    }
    public static bool TryReadRequest(ReadOnlySpan<byte> utf8, out string? requestId)
    {
        requestId = null;
        if (utf8.Length is 0 or > MaximumMessageBytes) return false;
        try
        {
            var value = JsonSerializer.Deserialize<Request>(utf8);
            if (value?.ProtocolVersion != Version || value.Command != RefreshTrustedManifestIntegrity || !IsValidRequestId(value.RequestId) || !HasFields(utf8, "ProtocolVersion", "Command", "RequestId")) return false;
            requestId = value.RequestId; return true;
        }
        catch (JsonException) { return false; }
    }
    public static byte[] CreateResponse(CommandResponse value) => JsonSerializer.SerializeToUtf8Bytes(new Response(Version, "command_result", value.RequestId, value.Result, value.TimestampUtc, value.Reason));
    public static bool TryReadResponse(ReadOnlySpan<byte> utf8, out CommandResponse? response)
    {
        response = null;
        if (utf8.Length is 0 or > MaximumMessageBytes) return false;
        try
        {
            var value = JsonSerializer.Deserialize<Response>(utf8);
            if (value is null || value.ProtocolVersion != Version || value.Type != "command_result" || !IsValidRequestId(value.RequestId) || value.TimestampUtc == default || value.TimestampUtc.Offset != TimeSpan.Zero || value.TimestampUtc > DateTimeOffset.UtcNow.AddMinutes(1) || !Enum.IsDefined(value.Result) || !Enum.IsDefined(value.Reason) || (value.Result is CommandResult.Accepted or CommandResult.AlreadyInProgress or CommandResult.Duplicate && value.Reason != CommandFailureReason.None) || !HasFields(utf8, "ProtocolVersion", "Type", "RequestId", "Result", "TimestampUtc", "Reason")) return false;
            response = new CommandResponse(value.RequestId, value.Result, value.TimestampUtc, value.Reason); return true;
        }
        catch (JsonException) { return false; }
    }
    private static bool HasFields(ReadOnlySpan<byte> utf8, params string[] names)
    {
        using var document = JsonDocument.Parse(utf8.ToArray());
        if (document.RootElement.ValueKind != JsonValueKind.Object) return false;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject()) if (!seen.Add(property.Name) || !names.Contains(property.Name, StringComparer.Ordinal)) return false;
        return seen.Count == names.Length;
    }
}
