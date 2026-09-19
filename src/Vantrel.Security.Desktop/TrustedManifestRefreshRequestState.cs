using Vantrel.Security.Core;

namespace Vantrel.Security.Desktop;

/// <summary>Tracks only desktop command admission and newer Status.v1 evidence; it never evaluates integrity.</summary>
internal sealed class TrustedManifestRefreshRequestState
{
    internal const int PollMilliseconds = 500;
    internal const int TimeoutSeconds = 20;
    private DateTimeOffset? _previousSample;
    internal bool IsInFlight { get; private set; }
    internal string? RequestId { get; private set; }

    internal bool TryBegin(bool connected, TrustedManifestIntegritySnapshot? current, out string? requestId)
    {
        requestId = null;
        if (!connected || IsInFlight) return false;
        IsInFlight = true;
        _previousSample = current?.SampledAtUtc;
        RequestId = Guid.NewGuid().ToString("N");
        requestId = RequestId;
        return true;
    }

    internal bool HasNewerStatusSnapshot(TrustedManifestIntegritySnapshot? value) =>
        IsInFlight && value is not null && (_previousSample is null || value.SampledAtUtc > _previousSample.Value);

    internal void Complete() { IsInFlight = false; RequestId = null; _previousSample = null; }
}

/// <summary>Computes the bounded desktop presentation for the fixed refresh command without opening Command.v1.</summary>
internal static class TrustedManifestRefreshControlPresentation
{
    internal const string DisconnectedGuidance = "Service connection required.";

    internal static (bool IsEnabled, string StatusText) Create(bool statusConnected, bool isInFlight, string statusText) =>
        isInFlight
            ? (false, statusText)
            : !statusConnected
                ? (false, DisconnectedGuidance)
                : (true, statusText == DisconnectedGuidance ? string.Empty : statusText);
}
