using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public sealed class HeartbeatWorker(ServiceStatusStore store, ILogger<HeartbeatWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Service heartbeat started");
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        try { while (await timer.WaitForNextTickAsync(stoppingToken)) store.UpdateHeartbeat(); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        logger.LogInformation("Service heartbeat stopped");
    }
}

public sealed class ServiceStatusStore
{
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow;
    private long _heartbeatTicks = DateTimeOffset.UtcNow.UtcTicks;
    private readonly ApplicationVersion _version = GetVersion();

    private static ApplicationVersion GetVersion()
    {
        var version = typeof(ServiceStatusStore).Assembly.GetName().Version
            ?? throw new InvalidOperationException("Service assembly version is missing.");
        return new ApplicationVersion(version.Major, version.Minor, Math.Max(version.Build, 0));
    }

    public void UpdateHeartbeat() => Interlocked.Exchange(ref _heartbeatTicks, DateTimeOffset.UtcNow.UtcTicks);

    public SecurityServiceStatus Snapshot() => new(
        ProtectionState.Unavailable, _version, _started,
        new DateTimeOffset(Interlocked.Read(ref _heartbeatTicks), TimeSpan.Zero));
}
