using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Vantrel.Security.Core;

namespace Vantrel.Security.Infrastructure;

/// <summary>Reads only Vantrel's two fixed Windows Security Center categories.</summary>
public sealed class WindowsSecurityCenterHealthSource
{
    internal const uint FirewallProvider = 0x1; // WSC_SECURITY_PROVIDER_FIREWALL
    internal const uint AntivirusProvider = 0x4; // WSC_SECURITY_PROVIDER_ANTIVIRUS
    private static readonly TimeSpan DiagnosticInterval = TimeSpan.FromMinutes(5);
    private readonly Func<uint, (int HResult, int Health)> _query;
    private readonly ILogger<WindowsSecurityCenterHealthSource> _logger;
    private readonly object _diagnosticLock = new();
    private readonly Dictionary<string, (string Key, DateTimeOffset AtUtc)> _lastDiagnosticByCategory = new();

    public WindowsSecurityCenterHealthSource(ILogger<WindowsSecurityCenterHealthSource> logger)
        : this(QueryNative, logger) { }

    internal WindowsSecurityCenterHealthSource(Func<uint, (int HResult, int Health)> query,
        ILogger<WindowsSecurityCenterHealthSource> logger)
    {
        _query = query;
        _logger = logger;
    }

    public WindowsAntivirusHealth? CollectAntivirus()
    {
        var raw = ReadHealth(AntivirusProvider, "antivirus");
        return raw is int value ? (WindowsAntivirusHealth)value : null;
    }

    public WindowsFirewallHealth? CollectFirewall()
    {
        var raw = ReadHealth(FirewallProvider, "firewall");
        return raw is int value ? (WindowsFirewallHealth)value : null;
    }

    private int? ReadHealth(uint provider, string category)
    {
        try
        {
            var (hresult, rawHealth) = _query(provider);
            // S_FALSE (1) sets POOR when WSC is stopped; it is not a valid health observation.
            if (hresult != 0)
            {
                LogUnavailable(category, hresult == 1 ? "WscUnavailable" : "ApiFailure", hresult);
                return null;
            }
            if (rawHealth is >= 0 and <= 3) return rawHealth;
            LogUnavailable(category, "UnexpectedHealthValue", hresult, rawHealth);
            return null;
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            LogUnavailable(category, "QueryException", error.HResult, exceptionType: error.GetType().FullName);
            return null;
        }
    }

    private void LogUnavailable(string category, string reason, int hresult, int? rawHealth = null,
        string? exceptionType = null)
    {
        var now = DateTimeOffset.UtcNow;
        var key = $"{category}:{reason}:{hresult}:{rawHealth}:{exceptionType}";
        lock (_diagnosticLock)
        {
            if (_lastDiagnosticByCategory.TryGetValue(category, out var previous) &&
                key == previous.Key && now - previous.AtUtc < DiagnosticInterval) return;
            _lastDiagnosticByCategory[category] = (key, now);
        }
        _logger.LogWarning("Windows {Category} health unavailable: {Reason}; HRESULT={HResult}; rawHealth={RawHealth}; exception={ExceptionType}; further matching reports are suppressed for five minutes",
            category, reason, hresult.ToString("X8"), rawHealth?.ToString() ?? "none", exceptionType ?? "none");
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
