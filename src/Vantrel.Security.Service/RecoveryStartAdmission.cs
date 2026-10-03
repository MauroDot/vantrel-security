using System.ServiceProcess;
using Microsoft.Extensions.Hosting;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

internal interface IRecoveryStartArgumentSource { string? Nonce { get; } }
internal sealed record RecoveryStartConsumptionLease(string TransactionId, string BackupId, ulong PriorReleaseSequence, string PriorManifestSha256);
internal interface IRecoveryStartupAdmission { Task<RecoveryStartConsumptionLease?> AdmitAsync(string[] scmArguments, CancellationToken token); Task RevokeAsync(RecoveryStartConsumptionLease lease, CancellationToken token) => Task.CompletedTask; }

internal sealed class ScmRecoveryStartArgumentSource : IRecoveryStartArgumentSource
{
    private const string Prefix = "--vantrel-recovery-start=";
    private string? _nonce;
    public string? Nonce => Volatile.Read(ref _nonce);
    internal void RecordScmStart(string[] args) => Volatile.Write(ref _nonce,
        args.Length == 1 && args[0].StartsWith(Prefix, StringComparison.Ordinal) ? args[0][Prefix.Length..] : null);
}

internal sealed class RecoveryStartupAdmission(UpdateTransactionJournalStore journals, ScmRecoveryStartArgumentSource arguments, Func<Task>? afterConsume = null) : IRecoveryStartupAdmission
{
    internal async Task<RecoveryStartConsumptionLease?> AdmitAsync(string[] scmArguments, CancellationToken token)
    {
        arguments.RecordScmStart(scmArguments);
        var read = await journals.ReadAsync(token);
        if (read.State == JournalReadState.Absent) return null;
        var journal = read.Journal;
        if (read.State != JournalReadState.Present || journal is null ||
            journal.Phase is UpdateTransactionPhase.ServiceStopped or UpdateTransactionPhase.RollbackRequired or UpdateTransactionPhase.RollbackRestartConsumed)
            throw new IOException("Unresolved update recovery blocks service startup.");
        if (journal.Phase == UpdateTransactionPhase.RollbackRestartAuthorized)
        {
            var lease = await journals.TryConsumeRecoveryStartLeaseAsync(arguments.Nonce, token) ?? throw new IOException("Unresolved update recovery blocks service startup.");
            try { if (afterConsume is not null) await afterConsume(); return lease; }
            catch { await journals.RevokeConsumedRecoveryStartAsync(lease, CancellationToken.None); throw; }
        }
        return null;
    }
    Task<RecoveryStartConsumptionLease?> IRecoveryStartupAdmission.AdmitAsync(string[] scmArguments, CancellationToken token) => AdmitAsync(scmArguments, token);
    Task IRecoveryStartupAdmission.RevokeAsync(RecoveryStartConsumptionLease lease, CancellationToken token) => journals.RevokeConsumedRecoveryStartAsync(lease, token);
}

internal sealed class RecoveryWindowsServiceLifetime(IHostApplicationLifetime application, IRecoveryStartupAdmission admission, TimeSpan? startupTimeout = null) : ServiceBase, IHostLifetime
{
    private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _startupCancellation = new();
    private readonly TimeSpan _startupTimeout = startupTimeout ?? TimeSpan.FromSeconds(30);
    private int _startupState; // 0 pending, 1 admitted, 2 cancelled or faulted
    // Generic Host starts hosted workers only after this lifetime completes this task.
    internal Task StartupAdmissionTask => _started.Task;
    internal RecoveryWindowsServiceLifetime(IHostApplicationLifetime application, IRecoveryStartupAdmission admission, string serviceName) : this(application, admission) => ServiceName = serviceName;
    public Task WaitForStartAsync(CancellationToken cancellationToken)
    {
        // Caller cancellation is an admission abort only. Once SCM has released the
        // host, a later caller token must not stop that legitimate recovery start.
        cancellationToken.Register(() => AbortPending(cancellationToken));
        new Thread(() => { try { ServiceBase.Run(this); } catch (Exception ex) { FailStartup(ex); } }) { IsBackground = true }.Start();
        return _started.Task.WaitAsync(cancellationToken);
    }
    private bool AbortPending(CancellationToken token)
    {
        if (Interlocked.CompareExchange(ref _startupState, 2, 0) != 0) return false;
        _started.TrySetCanceled(token); _startupCancellation.Cancel(); application.StopApplication(); return true;
    }
    internal void HandleStartupCancellation(CancellationToken token)
    {
        AbortPending(token);
    }
    private void RequestServiceStop(CancellationToken token)
    {
        if (!AbortPending(token)) application.StopApplication();
    }
    private void FailStartup(Exception error)
    {
        if (Interlocked.CompareExchange(ref _startupState, 2, 0) == 0) _started.TrySetException(error);
        _startupCancellation.Cancel(); application.StopApplication();
    }
    internal void HandleScmStart(string[] args)
    {
        if (Volatile.Read(ref _startupState) != 0) { application.StopApplication(); throw new OperationCanceledException("Service startup is no longer available."); }
        try
        {
            using var timeout = new CancellationTokenSource(_startupTimeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, _startupCancellation.Token);
            using var abort = linked.Token.Register(() => AbortPending(linked.Token));
            var lease = admission.AdmitAsync(args, linked.Token).GetAwaiter().GetResult();
            if (Interlocked.CompareExchange(ref _startupState, 1, 0) != 0)
            {
                if (lease is not null) admission.RevokeAsync(lease, CancellationToken.None).GetAwaiter().GetResult();
                throw new OperationCanceledException("Service startup was cancelled during admission.");
            }
            _started.TrySetResult();
        }
        catch (Exception ex) { FailStartup(ex); throw; }
    }
    protected override void OnStart(string[] args) => HandleScmStart(args);
    protected override void OnStop() => RequestServiceStop(CancellationToken.None);
    protected override void OnShutdown() => RequestServiceStop(CancellationToken.None);
    public Task StopAsync(CancellationToken cancellationToken) { RequestServiceStop(cancellationToken); Stop(); return Task.CompletedTask; }
}
