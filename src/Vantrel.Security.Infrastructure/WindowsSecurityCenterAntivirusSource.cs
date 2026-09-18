using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Vantrel.Security.Core;

namespace Vantrel.Security.Infrastructure;

/// <summary>Reads only Windows Security Center's aggregate antivirus-category health.</summary>
public sealed class WindowsSecurityCenterAntivirusSource
{
    internal const uint AntivirusProvider = 0x4; // WSC_SECURITY_PROVIDER_ANTIVIRUS
    private static readonly TimeSpan DiagnosticInterval = TimeSpan.FromMinutes(5);
    private readonly Func<uint, (int HResult, int Health)> _query;
    private readonly ILogger<WindowsSecurityCenterAntivirusSource> _logger;
    private readonly object _diagnosticLock = new();
    private string? _lastDiagnosticKey;
    private DateTimeOffset _lastDiagnosticAtUtc = DateTimeOffset.MinValue;

    public WindowsSecurityCenterAntivirusSource(ILogger<WindowsSecurityCenterAntivirusSource> logger)
        : this(QueryNative, logger) { }

    internal WindowsSecurityCenterAntivirusSource(Func<uint, (int HResult, int Health)> query,
        ILogger<WindowsSecurityCenterAntivirusSource> logger)
    {
        _query = query;
        _logger = logger;
    }

    public WindowsAntivirusHealth? Collect()
    {
        try
        {
            var (hresult, rawHealth) = _query(AntivirusProvider);
            // S_FALSE (1) sets POOR when WSC is stopped; it is not a valid health observation.
            if (hresult != 0)
            {
                LogUnavailable(hresult == 1 ? "WscUnavailable" : "ApiFailure", hresult);
                return null;
            }
            var health = rawHealth switch
            {
                0 => WindowsAntivirusHealth.Good,
                1 => WindowsAntivirusHealth.NotMonitored,
                2 => WindowsAntivirusHealth.Poor,
                3 => WindowsAntivirusHealth.Snoozed,
                _ => (WindowsAntivirusHealth?)null
            };
            if (health is null) LogUnavailable("UnexpectedHealthValue", hresult, rawHealth);
            return health;
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            LogUnavailable("QueryException", error.HResult, exceptionType: error.GetType().FullName);
            return null;
        }
    }

    private void LogUnavailable(string reason, int hresult, int? rawHealth = null, string? exceptionType = null)
    {
        var now = DateTimeOffset.UtcNow;
        var key = $"{reason}:{hresult}:{rawHealth}:{exceptionType}";
        lock (_diagnosticLock)
        {
            if (key == _lastDiagnosticKey && now - _lastDiagnosticAtUtc < DiagnosticInterval) return;
            _lastDiagnosticKey = key;
            _lastDiagnosticAtUtc = now;
        }
        _logger.LogWarning("Windows antivirus health unavailable: {Reason}; HRESULT={HResult}; rawHealth={RawHealth}; exception={ExceptionType}; further matching reports are suppressed for five minutes",
            reason, hresult.ToString("X8"), rawHealth?.ToString() ?? "none", exceptionType ?? "none");
    }

    private static (int HResult, int Health) QueryNative(uint provider)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var hresult = WscGetSecurityProviderHealth(provider, out var health);
        return (hresult, health);
    }

    [DllImport("wscapi.dll", EntryPoint = "WscGetSecurityProviderHealth")]
    private static extern int WscGetSecurityProviderHealth(uint providers, out int health);
}
