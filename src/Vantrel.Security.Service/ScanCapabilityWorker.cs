using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public sealed class ScanCapabilityStore
{
    private ScanCapabilitySnapshot? _snapshot;

    public ScanCapabilitySnapshot? Snapshot() => Volatile.Read(ref _snapshot);

    public void Update(ScanCapabilitySnapshot snapshot) => Volatile.Write(ref _snapshot, snapshot);
}

/// <summary>Produces a fixed statement only. This component never enumerates or opens filesystem entries.</summary>
public sealed class ScanCapabilitySource
{
    public const string PolicyRevision = StatusProtocol.ScanCapabilitySourcePolicyRevision;

    public ScanCapabilitySnapshot Collect() => new(
        DateTimeOffset.UtcNow,
        PolicyRevision,
        ScanCapabilityState.NotEnabled,
        ScanActivityState.NotRunning,
        ScanTargetAcceptance.None,
        ScheduledScanTargets.NoneConfigured,
        ScanFeatureAvailability.NotAvailable,
        ScanFeatureAvailability.NotAvailable,
        ScanFeatureAvailability.NotAvailable,
        ScanFeatureAvailability.NotAvailable);
}

public sealed class ScanCapabilityWorker(ScanCapabilityStore store, ScanCapabilitySource source,
    ILogger<ScanCapabilityWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        store.Update(source.Collect());
        logger.LogInformation("Scan capability sampling started");
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken)) store.Update(source.Collect());
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        logger.LogInformation("Scan capability sampling stopped");
    }
}
