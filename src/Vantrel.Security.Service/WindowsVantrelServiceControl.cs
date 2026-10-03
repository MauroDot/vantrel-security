using System.ServiceProcess;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>Fixed SCM controller for the one Vantrel service. It accepts no service name or command input.</summary>
internal sealed class WindowsVantrelServiceControl : IOfflineUpdateServiceControl
{
    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    private readonly Func<CancellationToken, Task<ServiceControllerStatus>> _readState;

    internal WindowsVantrelServiceControl() : this(ReadFixedStateAsync) { }

    // Internal state-provider seam for tests; production always queries the fixed service.
    internal WindowsVantrelServiceControl(Func<CancellationToken, Task<ServiceControllerStatus>> readState)
        => _readState = readState ?? throw new ArgumentNullException(nameof(readState));

    public async Task RequireStoppedAsync(CancellationToken token)
    {
        if (await InspectStateAsync(token) != OfflineUpdateServiceState.Stopped)
            throw new IOException("Fixed service must be stopped before rollback restore.");
    }

    public async Task<OfflineUpdateServiceState> InspectStateAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var state = await _readState(token).WaitAsync(Timeout, token);
        token.ThrowIfCancellationRequested();
        return state switch
        {
            ServiceControllerStatus.Running => OfflineUpdateServiceState.Running,
            ServiceControllerStatus.Stopped => OfflineUpdateServiceState.Stopped,
            _ => OfflineUpdateServiceState.Unavailable
        };
    }

    private static Task<ServiceControllerStatus> ReadFixedStateAsync(CancellationToken token) => Task.Run(() =>
    {
        token.ThrowIfCancellationRequested();
        using var service = new ServiceController(StatusProtocol.ServiceName);
        service.Refresh();
        return service.Status;
    }, token);

    internal Task<bool> IsRunningAsync(CancellationToken token) => Task.Run(() =>
    {
        token.ThrowIfCancellationRequested(); using var service = new ServiceController(StatusProtocol.ServiceName); service.Refresh(); return service.Status == ServiceControllerStatus.Running;
    }, token);
    public Task StopAsync(CancellationToken token) => ChangeAsync(ServiceControllerStatus.Stopped, token);
    public Task StartAsync(CancellationToken token) => ChangeAsync(ServiceControllerStatus.Running, token);
    public Task StartRecoveryAsync(string nonce, CancellationToken token) => ChangeAsync(ServiceControllerStatus.Running, token,
        ["--vantrel-recovery-start=" + nonce]);
    private static Task ChangeAsync(ServiceControllerStatus desired, CancellationToken token, string[]? arguments = null) => Task.Run(() =>
    {
        token.ThrowIfCancellationRequested(); using var service = new ServiceController(StatusProtocol.ServiceName); service.Refresh();
        if (service.Status == desired) return;
        if (desired == ServiceControllerStatus.Stopped) service.Stop(); else if (arguments is null) service.Start(); else service.Start(arguments);
        service.WaitForStatus(desired, Timeout); service.Refresh();
        if (service.Status != desired) throw new System.TimeoutException("Fixed Vantrel service state transition timed out.");
    }, token);
}
