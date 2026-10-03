using Microsoft.Extensions.Hosting;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>Projects only bounded fixed journal state. It never stages, replaces, restores, or selects files.</summary>
public sealed class UpdateTransactionStatusWorker(UpdateTransactionStore store, UpdateTransactionJournalStore journals,
    ReleaseProvenanceStore provenance, ILogger<UpdateTransactionStatusWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await SampleAsync(stoppingToken);
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
            while (await timer.WaitForNextTickAsync(stoppingToken)) await SampleAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { logger.LogInformation("Update transaction status sampling stopped"); }
    }

    private async Task SampleAsync(CancellationToken token)
    {
        JournalReadResult read;
        try { read = await journals.ReadAsync(token); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            read = new(null, UpdateTransactionJournalParseFailure.Unavailable, JournalReadState.Invalid);
        }
        var journal = read.Journal;
        var current = provenance.Snapshot()?.ReleaseSequence;
        var snapshot = journal is null
            ? new UpdateTransactionSnapshot(DateTimeOffset.UtcNow,
                read.State == JournalReadState.Absent ? UpdateTransactionPhase.Idle : UpdateTransactionPhase.Failed, false, current, null,
                read.State == JournalReadState.Absent ? UpdateTransactionResult.None : UpdateTransactionResult.RecoveryRequired)
            : new UpdateTransactionSnapshot(DateTimeOffset.UtcNow, journal.Phase, journal.Phase is UpdateTransactionPhase.Verified or UpdateTransactionPhase.Prepared,
                current, journal.TargetReleaseSequence, journal.Phase switch
                {
                    UpdateTransactionPhase.Completed => UpdateTransactionResult.Completed,
                    UpdateTransactionPhase.RolledBack => UpdateTransactionResult.RolledBack,
                    UpdateTransactionPhase.Failed => UpdateTransactionResult.Failed,
                    UpdateTransactionPhase.RollbackRequired or UpdateTransactionPhase.RollbackRestartAuthorized or UpdateTransactionPhase.RollbackRestartConsumed => UpdateTransactionResult.RecoveryRequired,
                    _ => UpdateTransactionResult.None
                });
        store.Update(snapshot);
    }
}
