using System.Security;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;

namespace Vantrel.Security.Service;

public sealed class SystemHealthStore
{
    private SystemHealthSnapshot _snapshot = new(DateTimeOffset.UtcNow, null, null, null, null);

    public SystemHealthSnapshot Snapshot() => Volatile.Read(ref _snapshot);

    public void Update(SystemHealthSnapshot snapshot) => Volatile.Write(ref _snapshot, snapshot);
}

public sealed class WindowsSystemHealthSource
{
    private readonly Func<string> _version;
    private readonly Func<long> _uptime;
    private readonly Func<(long Total, long Free)> _volume;
    private readonly Func<WindowsAntivirusHealth?> _antivirus;
    private readonly Func<WindowsFirewallHealth?> _firewall;

    public WindowsSystemHealthSource(WindowsSecurityCenterHealthSource securityCenter) : this(
        () => Environment.OSVersion.Version.ToString(),
        () => Environment.TickCount64 / 1000,
        ReadSystemVolume,
        securityCenter.CollectAntivirus,
        securityCenter.CollectFirewall) { }

    internal WindowsSystemHealthSource(Func<string> version, Func<long> uptime,
        Func<(long Total, long Free)> volume, Func<WindowsAntivirusHealth?>? antivirus = null,
        Func<WindowsFirewallHealth?>? firewall = null)
    {
        _version = version;
        _uptime = uptime;
        _volume = volume;
        _antivirus = antivirus ?? (() => null);
        _firewall = firewall ?? (() => null);
    }

    public SystemHealthSnapshot Collect()
    {
        var collectedAt = DateTimeOffset.UtcNow;
        string? version = null;
        long? uptime = null;
        long? total = null;
        long? free = null;
        WindowsAntivirusHealth? antivirus = null;
        WindowsFirewallHealth? firewall = null;
        try
        {
            var value = _version();
            if (!string.IsNullOrWhiteSpace(value) && value.Length <= 64 && !value.Any(char.IsControl))
                version = value;
        }
        catch (Exception error) when (IsCollectionFailure(error)) { }
        try
        {
            var value = _uptime();
            if (value >= 0) uptime = value;
        }
        catch (Exception error) when (IsCollectionFailure(error)) { }
        try
        {
            var values = _volume();
            if (values.Total > 0 && values.Free >= 0 && values.Free <= values.Total)
            {
                total = values.Total;
                free = values.Free;
            }
        }
        catch (Exception error) when (IsCollectionFailure(error)) { }
        try
        {
            var value = _antivirus();
            if (value is { } state && Enum.IsDefined(state)) antivirus = state;
        }
        catch (Exception error) when (IsCollectionFailure(error)) { }
        try
        {
            var value = _firewall();
            if (value is { } state && Enum.IsDefined(state)) firewall = state;
        }
        catch (Exception error) when (IsCollectionFailure(error)) { }
        return new SystemHealthSnapshot(collectedAt, version, uptime, total, free, antivirus, firewall);
    }

    private static (long Total, long Free) ReadSystemVolume()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var root = Path.GetPathRoot(Environment.SystemDirectory)
            ?? throw new IOException("Windows system volume is unavailable.");
        var drive = new DriveInfo(root);
        if (drive.DriveType != DriveType.Fixed || !drive.IsReady)
            throw new IOException("Windows system volume is not a ready fixed drive.");
        return (drive.TotalSize, drive.TotalFreeSpace);
    }

    private static bool IsCollectionFailure(Exception error) => error is IOException or UnauthorizedAccessException or
        SecurityException or ArgumentException or PlatformNotSupportedException or InvalidOperationException;
}

public sealed class SystemHealthWorker(SystemHealthStore store, WindowsSystemHealthSource source,
    ILogger<SystemHealthWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Sampling stays outside the single-client pipe loop. A failed value remains explicit null.
        await Task.Yield();
        store.Update(source.Collect());
        logger.LogInformation("System health sampling started");
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken)) store.Update(source.Collect());
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        logger.LogInformation("System health sampling stopped");
    }
}
