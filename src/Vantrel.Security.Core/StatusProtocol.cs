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
    InvalidHealth,
    InvalidActivity,
    InvalidScanCapability,
    InvalidComponentInspection
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
    private sealed record ActivityResponse(int ProtocolVersion, string Type, ActivitySnapshot Activity);
    private sealed record ScanCapabilityResponse(int ProtocolVersion, string Type, ScanCapabilitySnapshot Capability);
    private sealed record ComponentInspectionResponse(int ProtocolVersion, string Type, ComponentInspectionSnapshot Inspection);

    public enum RequestKind { Invalid, Status, SystemHealth, Activity, ScanCapability, ComponentInspection }

    public static byte[] CreateRequest() => JsonSerializer.SerializeToUtf8Bytes(new Request(Version, "get_status"));

    public static byte[] CreateSystemHealthRequest() =>
        JsonSerializer.SerializeToUtf8Bytes(new Request(Version, "get_system_health"));

    public static byte[] CreateActivityRequest() =>
        JsonSerializer.SerializeToUtf8Bytes(new Request(Version, "get_activity"));

    public static byte[] CreateScanCapabilityRequest() =>
        JsonSerializer.SerializeToUtf8Bytes(new Request(Version, "get_scan_capability"));
    public static byte[] CreateComponentInspectionRequest() => JsonSerializer.SerializeToUtf8Bytes(new Request(Version, "get_component_inspection"));

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
                "get_activity" when HasOnlyFixedRequestFields(utf8) => RequestKind.Activity,
                "get_scan_capability" when HasOnlyFixedRequestFields(utf8) => RequestKind.ScanCapability,
                "get_component_inspection" when HasOnlyFixedRequestFields(utf8) => RequestKind.ComponentInspection,
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

    public static byte[] CreateActivityResponse(ActivitySnapshot activity) =>
        JsonSerializer.SerializeToUtf8Bytes(new ActivityResponse(Version, "activity", activity));

    public static byte[] CreateScanCapabilityResponse(ScanCapabilitySnapshot capability) =>
        JsonSerializer.SerializeToUtf8Bytes(new ScanCapabilityResponse(Version, "scan_capability", capability));
    public static byte[] CreateComponentInspectionResponse(ComponentInspectionSnapshot inspection) =>
        JsonSerializer.SerializeToUtf8Bytes(new ComponentInspectionResponse(Version, "component_inspection", inspection));

    public static bool TryReadComponentInspectionResponse(ReadOnlySpan<byte> utf8, out ComponentInspectionSnapshot? inspection, out StatusResponseFailure failure)
    {
        inspection = null; failure = utf8.Length switch { 0 => StatusResponseFailure.Empty, > MaximumMessageBytes => StatusResponseFailure.Oversized, _ => StatusResponseFailure.None };
        if (failure != StatusResponseFailure.None) return false;
        try
        {
            var response = JsonSerializer.Deserialize<ComponentInspectionResponse>(utf8);
            var value = response?.Inspection;
            if (response is null || value is null) { failure = StatusResponseFailure.MalformedJson; return false; }
            if (response.ProtocolVersion != Version) { failure = StatusResponseFailure.UnsupportedVersion; return false; }
            if (response.Type != "component_inspection") { failure = StatusResponseFailure.UnexpectedType; return false; }
            var observed = value.Outcome == ComponentInspectionOutcome.Observed;
            if (!HasExactComponentInspectionShape(utf8) || value.SampledAtUtc == default || value.SampledAtUtc.Offset != TimeSpan.Zero || value.SampledAtUtc > DateTimeOffset.UtcNow.AddMinutes(1) ||
                value.PolicyRevision != ComponentInspectionPolicyRevision || value.Target != ComponentInspectionTarget.VantrelServiceAssembly || !Enum.IsDefined(value.Outcome) || !Enum.IsDefined(value.Reason) ||
                (observed && (value.Reason != ComponentInspectionReason.None || value.HashAlgorithm != ComponentHashAlgorithm.Sha256 || value.Hash is null || value.Hash.Length != 64 || !value.Hash.All(Uri.IsHexDigit) || value.ObservedByteLength is null or < 0)) ||
                (!observed && (value.Reason == ComponentInspectionReason.None || value.HashAlgorithm is not null || value.Hash is not null || value.ObservedByteLength is not null))) { failure = StatusResponseFailure.InvalidComponentInspection; return false; }
            inspection = value; return true;
        }
        catch (JsonException) { failure = StatusResponseFailure.MalformedJson; return false; }
    }
    public const string ComponentInspectionPolicyRevision = "component-inspection-v1";
    private static bool HasExactComponentInspectionShape(ReadOnlySpan<byte> utf8)
    {
        using var d = JsonDocument.Parse(utf8.ToArray()); var root = d.RootElement;
        return HasFields(root, "ProtocolVersion", "Type", "Inspection") && HasFields(root.GetProperty("Inspection"), "SampledAtUtc", "PolicyRevision", "Target", "Outcome", "Reason", "HashAlgorithm", "Hash", "ObservedByteLength");
    }

    public static bool TryReadScanCapabilityResponse(ReadOnlySpan<byte> utf8,
        out ScanCapabilitySnapshot? capability, out StatusResponseFailure failure)
    {
        capability = null;
        failure = utf8.Length switch
        {
            0 => StatusResponseFailure.Empty,
            > MaximumMessageBytes => StatusResponseFailure.Oversized,
            _ => StatusResponseFailure.None
        };
        if (failure != StatusResponseFailure.None) return false;
        try
        {
            var response = JsonSerializer.Deserialize<ScanCapabilityResponse>(utf8);
            if (response is null) { failure = StatusResponseFailure.MalformedJson; return false; }
            if (response.ProtocolVersion != Version) { failure = StatusResponseFailure.UnsupportedVersion; return false; }
            if (response.Type != "scan_capability") { failure = StatusResponseFailure.UnexpectedType; return false; }
            var value = response.Capability;
            if (value is null || !HasExactScanCapabilityShape(utf8) || value.SampledAtUtc == default ||
                value.SampledAtUtc.Offset != TimeSpan.Zero || value.SampledAtUtc > DateTimeOffset.UtcNow.AddMinutes(1) ||
                value.PolicyRevision is null or { Length: 0 } or { Length: > 64 } ||
                value.PolicyRevision.Any(char.IsControl) || value.PolicyRevision != ScanCapabilitySourcePolicyRevision ||
                value.Capability != ScanCapabilityState.NotEnabled ||
                value.FileScanning != ScanActivityState.NotRunning ||
                value.ClientSuppliedTargets != ScanTargetAcceptance.None ||
                value.ScheduledTargets != ScheduledScanTargets.NoneConfigured ||
                value.Detection != ScanFeatureAvailability.NotAvailable ||
                value.Quarantine != ScanFeatureAvailability.NotAvailable ||
                value.Remediation != ScanFeatureAvailability.NotAvailable ||
                value.RealTimeProtection != ScanFeatureAvailability.NotAvailable)
            {
                failure = StatusResponseFailure.InvalidScanCapability;
                return false;
            }
            capability = value;
            return true;
        }
        catch (JsonException) { failure = StatusResponseFailure.MalformedJson; return false; }
    }

    // Kept in Core so protocol validation is platform-neutral and does not depend on the service assembly.
    public const string ScanCapabilitySourcePolicyRevision = "scan-capability-v1";

    private static bool HasExactScanCapabilityShape(ReadOnlySpan<byte> utf8)
    {
        using var document = JsonDocument.Parse(utf8.ToArray());
        var root = document.RootElement;
        return HasFields(root, "ProtocolVersion", "Type", "Capability") &&
            HasFields(root.GetProperty("Capability"), "SampledAtUtc", "PolicyRevision", "Capability",
                "FileScanning", "ClientSuppliedTargets", "ScheduledTargets", "Detection", "Quarantine",
                "Remediation", "RealTimeProtection");
    }

    public static bool TryReadActivityResponse(ReadOnlySpan<byte> utf8, out ActivitySnapshot? activity,
        out StatusResponseFailure failure)
    {
        activity = null;
        failure = utf8.Length switch
        {
            0 => StatusResponseFailure.Empty,
            > MaximumMessageBytes => StatusResponseFailure.Oversized,
            _ => StatusResponseFailure.None
        };
        if (failure != StatusResponseFailure.None) return false;
        try
        {
            var response = JsonSerializer.Deserialize<ActivityResponse>(utf8);
            if (response is null) { failure = StatusResponseFailure.MalformedJson; return false; }
            if (response.ProtocolVersion != Version) { failure = StatusResponseFailure.UnsupportedVersion; return false; }
            if (response.Type != "activity") { failure = StatusResponseFailure.UnexpectedType; return false; }
            var value = response.Activity;
            if (value is null || !HasExactActivityShape(utf8) ||
                value.ServiceStartedAtUtc == default || value.SampledThroughUtc == default ||
                value.ServiceStartedAtUtc.Offset != TimeSpan.Zero ||
                value.SampledThroughUtc.Offset != TimeSpan.Zero ||
                value.ServiceStartedAtUtc > value.SampledThroughUtc ||
                value.SampledThroughUtc > DateTimeOffset.UtcNow.AddMinutes(1) ||
                value.Entries.IsDefault || value.Entries.Length > 12 ||
                value.Entries.Any(entry => entry is null || !Enum.IsDefined(entry.Category) ||
                    !Enum.IsDefined(entry.Kind) ||
                    !Enum.IsDefined(entry.CurrentState) ||
                    (entry.PreviousState is { } previous &&
                        (!Enum.IsDefined(previous) || previous == entry.CurrentState)) ||
                    (entry.Kind == ActivityObservationKind.Initial) != (entry.PreviousState is null) ||
                    entry.ObservedAtUtc == default ||
                    entry.ObservedAtUtc.Offset != TimeSpan.Zero ||
                    entry.ObservedAtUtc < value.ServiceStartedAtUtc ||
                    entry.ObservedAtUtc > value.SampledThroughUtc))
            {
                failure = StatusResponseFailure.InvalidActivity;
                return false;
            }
            activity = value;
            return true;
        }
        catch (JsonException) { failure = StatusResponseFailure.MalformedJson; return false; }
    }

    private static bool HasExactActivityShape(ReadOnlySpan<byte> utf8)
    {
        using var document = JsonDocument.Parse(utf8.ToArray());
        var root = document.RootElement;
        if (!HasFields(root, "ProtocolVersion", "Type", "Activity")) return false;
        var value = root.GetProperty("Activity");
        if (!HasFields(value, "ServiceStartedAtUtc", "SampledThroughUtc", "Entries")) return false;
        var entries = value.GetProperty("Entries");
        return entries.ValueKind == JsonValueKind.Array && entries.EnumerateArray().All(entry =>
            HasFields(entry, "Category", "Kind", "PreviousState", "CurrentState", "ObservedAtUtc"));
    }

    private static bool HasFields(JsonElement element, params string[] fields)
    {
        if (element.ValueKind != JsonValueKind.Object) return false;
        var properties = element.EnumerateObject().Select(property => property.Name).ToArray();
        return properties.Length == fields.Length && fields.All(field => properties.Count(name => name == field) == 1);
    }

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
