using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

internal enum PolicyCommitObservation
{
    TargetCommitted,
    PredecessorRetained,
    Unavailable
}

internal interface IOfflineUpdatePreflight
{
    Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal journal, CancellationToken token);
    Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal journal, CancellationToken token);
}
internal interface IOfflineUpdateServiceControl
{
    Task StopAsync(CancellationToken token);
    Task StartAsync(CancellationToken token);
}
internal interface IOfflineUpdateReleaseFiles
{
    Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token);
    Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token);
}
internal interface IOfflineUpdateHealth
{
    Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token);
    Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token);
    Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token);
}
internal interface IOfflineUpdateJournal
{
    Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token);
}

/// <summary>Failure-injectable transaction coordinator. It has no generic command, path, service, or file inputs.</summary>
internal sealed class OfflineUpdateTransactionEngine(IOfflineUpdatePreflight preflight, IOfflineUpdateServiceControl service,
    IOfflineUpdateReleaseFiles files, IOfflineUpdateHealth health, IOfflineUpdateJournal journalStore)
{
    internal async Task<UpdateTransactionPhase> ExecuteAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        if (journal.Phase != UpdateTransactionPhase.Prepared) throw new InvalidOperationException("Forward transaction must begin Prepared.");
        try
        {
            await preflight.VerifyCandidateAndBaselineAsync(journal, token);
            await preflight.CreateAndVerifyPredecessorBackupAsync(journal, token);
            journal = await MoveAsync(journal, UpdateTransactionPhase.Verified, token);
            await service.StopAsync(token);
            journal = await MoveAsync(journal, UpdateTransactionPhase.ServiceStopped, token);
            await files.ReplaceFromVerifiedPrivateCandidateAsync(journal, token);
            journal = await MoveAsync(journal, UpdateTransactionPhase.Replaced, token);
            await service.StartAsync(token);
            journal = await MoveAsync(journal, UpdateTransactionPhase.Restarted, token);
            await health.VerifyTargetAsync(journal, token);
            journal = await MoveAsync(journal, UpdateTransactionPhase.PostVerified, token);
            return await ObserveCommitAsync(journal, token);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch when (journal.Phase is UpdateTransactionPhase.PolicyCommitted or UpdateTransactionPhase.Completed)
        {
            return await PersistFailedAsync(journal, token);
        }
        catch
        {
            // Candidate, baseline, and backup failures occur before SCM stop; never restore an untouched install.
            return journal.Phase is UpdateTransactionPhase.Prepared or UpdateTransactionPhase.Verified
                ? await PersistFailedAsync(journal, token)
                : await RollbackAsync(journal, token);
        }
    }

    internal async Task<UpdateTransactionPhase> RecoverAsync(UpdateTransactionJournal journal, CancellationToken token) => journal.Phase switch
    {
        UpdateTransactionPhase.Prepared or UpdateTransactionPhase.Verified => journal.Phase,
        UpdateTransactionPhase.ServiceStopped or UpdateTransactionPhase.RollbackRequired => await RollbackAsync(journal, token),
        UpdateTransactionPhase.Replaced => await ContinueFromReplacedAsync(journal, token),
        UpdateTransactionPhase.Restarted => await ContinueFromRestartedAsync(journal, token),
        UpdateTransactionPhase.PostVerified => await ObserveCommitAsync(journal, token),
        UpdateTransactionPhase.PolicyCommitted => await FinalizeCommittedAsync(journal, token),
        UpdateTransactionPhase.RolledBack => await VerifyRolledBackAsync(journal, token),
        UpdateTransactionPhase.Completed or UpdateTransactionPhase.Failed => journal.Phase,
        _ => throw new InvalidOperationException("Unexpected transaction recovery phase.")
    };

    private async Task<UpdateTransactionPhase> FinalizeCommittedAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        return await health.ObservePolicyCommitAsync(journal, token) == PolicyCommitObservation.TargetCommitted
            ? (await MoveAsync(journal, UpdateTransactionPhase.Completed, token)).Phase
            : await PersistFailedAsync(journal, token);
    }

    private async Task<UpdateTransactionPhase> VerifyRolledBackAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        if (await health.ObservePolicyCommitAsync(journal, token) != PolicyCommitObservation.PredecessorRetained)
            return await PersistFailedAsync(journal, token);
        await health.VerifyPredecessorAsync(journal, token);
        return journal.Phase;
    }
    private async Task<UpdateTransactionPhase> ContinueFromReplacedAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        await service.StartAsync(token);
        journal = await MoveAsync(journal, UpdateTransactionPhase.Restarted, token);
        return await ContinueFromRestartedAsync(journal, token);
    }

    private async Task<UpdateTransactionPhase> ContinueFromRestartedAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        try
        {
            await health.VerifyTargetAsync(journal, token);
            journal = await MoveAsync(journal, UpdateTransactionPhase.PostVerified, token);
            return await ObserveCommitAsync(journal, token);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch { return await RollbackAsync(journal, token); }
    }

    private async Task<UpdateTransactionPhase> ObserveCommitAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        var observation = await health.ObservePolicyCommitAsync(journal, token);
        if (observation == PolicyCommitObservation.TargetCommitted)
        {
            journal = await MoveAsync(journal, UpdateTransactionPhase.PolicyCommitted, token);
            journal = await MoveAsync(journal, UpdateTransactionPhase.Completed, token);
            return journal.Phase;
        }
        if (observation == PolicyCommitObservation.PredecessorRetained) return await RollbackAsync(journal, token);
        return await PersistFailedAsync(journal, token);
    }

    private async Task<UpdateTransactionPhase> RollbackAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        // This durable read is deliberately immediately before restore. A target high-water commit permanently forbids downgrade.
        var observation = await health.ObservePolicyCommitAsync(journal, token);
        if (journal.Phase is UpdateTransactionPhase.PolicyCommitted or UpdateTransactionPhase.Completed ||
            observation is not PolicyCommitObservation.PredecessorRetained)
        {
            // A prior restore, start, or health failure has already made this journal
            // recoverable. A later unavailable, unrelated, or target policy still
            // blocks rollback, but must not attempt the illegal terminal transition.
            if (journal.Phase == UpdateTransactionPhase.RollbackRequired) return journal.Phase;
            return await PersistFailedAsync(journal, token);
        }

        if (journal.Phase != UpdateTransactionPhase.RollbackRequired)
            journal = await MoveAsync(journal, UpdateTransactionPhase.RollbackRequired, token);

        try
        {
            await files.RestoreVerifiedPredecessorAsync(journal, token);
            await service.StartAsync(token);
            await health.VerifyPredecessorAsync(journal, token);
            journal = await MoveAsync(journal, UpdateTransactionPhase.RolledBack, token);
            return journal.Phase;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        // RollbackRequired was persisted before any restore write. Retain it after a
        // partial restore, restart, or predecessor-health failure so a later invocation
        // can reauthenticate the backup and repair the fixed set. Failed is terminal.
        catch { return journal.Phase; }
    }

    private async Task<UpdateTransactionPhase> PersistFailedAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        if (journal.Phase != UpdateTransactionPhase.Failed)
        {
            journal = journal with { Phase = UpdateTransactionPhase.Failed, UpdatedAtUtc = WholeSecondUtcNow() };
            await journalStore.PersistAsync(journal, token);
        }
        return UpdateTransactionPhase.Failed;
    }

    private async Task<UpdateTransactionJournal> MoveAsync(UpdateTransactionJournal journal, UpdateTransactionPhase target, CancellationToken token)
    {
        var next = UpdateTransactionStateMachine.Transition(journal, target, WholeSecondUtcNow());
        await journalStore.PersistAsync(next, token);
        return next;
    }

    private static DateTimeOffset WholeSecondUtcNow()
    {
        var now = DateTimeOffset.UtcNow;
        return new DateTimeOffset(now.Ticks - now.Ticks % TimeSpan.TicksPerSecond, TimeSpan.Zero);
    }
}
