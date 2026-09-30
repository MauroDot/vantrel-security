using System.ServiceProcess;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>Fixed SCM controller for the one Vantrel service. It accepts no service name or command input.</summary>
internal sealed class WindowsVantrelServiceControl : IOfflineUpdateServiceControl
{
    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    internal Task<bool> IsRunningAsync(CancellationToken token) => Task.Run(() =>
    {
        token.ThrowIfCancellationRequested(); using var service = new ServiceController(StatusProtocol.ServiceName); service.Refresh(); return service.Status == ServiceControllerStatus.Running;
    }, token);
    public Task StopAsync(CancellationToken token) => ChangeAsync(ServiceControllerStatus.Stopped, token);
    public Task StartAsync(CancellationToken token) => ChangeAsync(ServiceControllerStatus.Running, token);
    private static Task ChangeAsync(ServiceControllerStatus desired, CancellationToken token) => Task.Run(() =>
    {
        token.ThrowIfCancellationRequested(); using var service = new ServiceController(StatusProtocol.ServiceName); service.Refresh();
        if (service.Status == desired) return;
        if (desired == ServiceControllerStatus.Stopped) service.Stop(); else service.Start();
        service.WaitForStatus(desired, Timeout); service.Refresh();
        if (service.Status != desired) throw new System.TimeoutException("Fixed Vantrel service state transition timed out.");
    }, token);
}
