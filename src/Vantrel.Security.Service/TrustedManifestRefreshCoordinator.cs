using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>Single fixed Task 011 collection path for scheduled and authorized immediate refreshes.</summary>
public sealed class TrustedManifestRefreshCoordinator(TrustedManifestIntegrityStore store, TrustedManifestIntegritySource source,
    CommandAuditStore audit, IHostApplicationLifetime lifetime, ILogger<TrustedManifestRefreshCoordinator> logger)
{
    private readonly Func<CancellationToken, Task<TrustedManifestIntegritySnapshot>> _collect = source.CollectAsync;
    private int _busy;
    public bool IsBusy => Volatile.Read(ref _busy) != 0;
    public async Task RefreshScheduledAsync(CancellationToken token)
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0) return;
        try { store.Update(await _collect(token)); }
        finally { Volatile.Write(ref _busy, 0); }
    }
    public bool TryRefreshCommand(string requestId, CommandCallerClassification caller)
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0) return false;
        _ = Task.Run(async () =>
        {
            try
            {
                store.Update(await _collect(lifetime.ApplicationStopping));
                audit.Add(requestId, caller, CommandAuditOutcome.Completed);
                logger.LogInformation("Command refresh completed");
            }
            catch (OperationCanceledException) when (lifetime.ApplicationStopping.IsCancellationRequested) { audit.Add(requestId, caller, CommandAuditOutcome.Cancelled); }
            catch (Exception) { audit.Add(requestId, caller, CommandAuditOutcome.Failed); logger.LogWarning("Command refresh failed"); }
            finally { Volatile.Write(ref _busy, 0); }
        });
        return true;
    }
    internal TrustedManifestRefreshCoordinator(TrustedManifestIntegrityStore store, Func<CancellationToken, Task<TrustedManifestIntegritySnapshot>> collect,
        CommandAuditStore audit, IHostApplicationLifetime lifetime, ILogger<TrustedManifestRefreshCoordinator> logger) : this(store, new TrustedManifestIntegritySource(), audit, lifetime, logger) { _collect = collect; }
}
