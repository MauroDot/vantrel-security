using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public enum OfflineUpdateInvocationResult { Completed, Failed, AlreadyInProgress }

/// <summary>Single fixed elevated entry point. It accepts no paths, versions, identifiers, or service names.</summary>
public sealed class OfflineUpdateAdministrator
{
    private static readonly SemaphoreSlim ProductionGate = new(1, 1);
    private readonly Func<CancellationToken, Task<UpdateTransactionPhase>> _fixedOperation;
    private readonly SemaphoreSlim _gate;
    private readonly IOfflineUpdateOwnershipLock? _ownershipLock;

    public OfflineUpdateAdministrator() : this(ExecuteFixedAsync, ProductionGate, new OfflineUpdateOwnershipLock()) { }
    internal OfflineUpdateAdministrator(Func<CancellationToken, Task<UpdateTransactionPhase>> fixedOperation, SemaphoreSlim? gate = null,
        IOfflineUpdateOwnershipLock? ownershipLock = null)
    {
        _fixedOperation = fixedOperation ?? throw new ArgumentNullException(nameof(fixedOperation));
        _gate = gate ?? ProductionGate;
        _ownershipLock = ownershipLock;
    }

    public async Task<OfflineUpdateInvocationResult> ApplyFixedStagedCandidateAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!_gate.Wait(0)) return OfflineUpdateInvocationResult.AlreadyInProgress;
        IDisposable? ownership = null;
        try
        {
            ownership = _ownershipLock?.TryAcquire(token);
            if (_ownershipLock is not null && ownership is null) return OfflineUpdateInvocationResult.AlreadyInProgress;
            return await _fixedOperation(token) == UpdateTransactionPhase.Completed ? OfflineUpdateInvocationResult.Completed : OfflineUpdateInvocationResult.Failed;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch { return OfflineUpdateInvocationResult.Failed; }
        finally { ownership?.Dispose(); _gate.Release(); }
    }
    private static async Task<UpdateTransactionPhase> ExecuteFixedAsync(CancellationToken token)
    {
        var journals = new UpdateTransactionJournalStore();
        return await WithValidatedJournalAsync(journals, existing => ExecuteValidatedAsync(journals, existing, token), token);
    }

    // The continuation includes both recovery and new admission. It is unreachable
    // for missing infrastructure, malformed journals, or filesystem inspection errors.
    internal static async Task<UpdateTransactionPhase> WithValidatedJournalAsync(UpdateTransactionJournalStore journals,
        Func<UpdateTransactionJournal?, Task<UpdateTransactionPhase>> continuation, CancellationToken token)
    {
        var read = await journals.ReadAsync(token);
        if (read.State is not (JournalReadState.Present or JournalReadState.Absent))
            throw new IOException("Fixed update journal infrastructure or state is unavailable.");
        return await continuation(read.Journal);
    }

    private static async Task<UpdateTransactionPhase> ExecuteValidatedAsync(UpdateTransactionJournalStore journals,
        UpdateTransactionJournal? existing, CancellationToken token)
    {
        var verifier = new OfflineReleaseVerifier(); var policy = new ReleasePolicyStore(); var storage = new OfflineUpdateStorage();
        var control = new WindowsVantrelServiceControl(); var health = new FixedReleaseHealthVerifier(control, verifier, policy);
        var engine = new OfflineUpdateTransactionEngine(new FixedOfflineUpdatePreflight(verifier, policy, storage), control,
            new FixedOfflineUpdateReleaseFiles(verifier, policy, storage, control), health, new JournalAdapter(journals));
        if (existing is not null) return await engine.RecoverAsync(existing, token);

        var installed = await verifier.VerifyInstalledBaselineAsync(policy, token);
        if (installed.Result != OfflineReleaseVerificationResult.Verified || installed.Release is null) throw new IOException("Installed release baseline is not eligible.");
        var candidate = await verifier.VerifyCandidateAsync(storage.StagedCandidate, policy, token);
        if (candidate.PolicyDecision != ReleasePolicyDecision.HigherRelease) throw new IOException("Fixed staged candidate is not eligible.");
        var journal = new UpdateTransactionJournal(Guid.NewGuid().ToString("N"), installed.Release.Sequence, installed.Release.ManifestSha256,
            candidate.Sequence, candidate.ManifestSha256, UpdateTransactionPhase.Prepared, Guid.NewGuid().ToString("N"), WholeSecondUtcNow());
        await journals.PersistAsync(journal, token);
        return await engine.ExecuteAsync(journal, token);
    }

    private static DateTimeOffset WholeSecondUtcNow()
    {
        var now = DateTimeOffset.UtcNow;
        return new DateTimeOffset(now.Ticks - now.Ticks % TimeSpan.TicksPerSecond, TimeSpan.Zero);
    }

    private sealed class JournalAdapter(UpdateTransactionJournalStore store) : IOfflineUpdateJournal
    {
        public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token) => store.PersistAsync(journal, token);
    }
}
