using System.ComponentModel;
using System.IO.Pipes;
using System.Security.Principal;
using System.ServiceProcess;
using Vantrel.Security.Core;

namespace Vantrel.Security.Infrastructure;

public sealed class NamedPipeStatusClient : ISecurityServiceStatusClient
{
    private readonly string _pipeName;
    private readonly TimeSpan _timeout;
    private readonly bool _allowDevelopmentServer;

    public NamedPipeStatusClient() : this(StatusProtocol.PipeName, TimeSpan.FromSeconds(3), AllowDevelopmentServer()) { }

    internal NamedPipeStatusClient(string pipeName, TimeSpan timeout, bool allowDevelopmentServer)
    {
        _pipeName = pipeName;
        _timeout = timeout;
        _allowDevelopmentServer = allowDevelopmentServer;
    }

    private static bool AllowDevelopmentServer()
    {
#if DEBUG
        return string.Equals(Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT"),
            "Development", StringComparison.OrdinalIgnoreCase);
#else
        return false;
#endif
    }

    public async Task<SecurityServiceStatus?> GetStatusAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Status IPC requires Windows.");
        var installedServiceRunning = _pipeName == StatusProtocol.PipeName && IsInstalledServiceRunning();
        if (!installedServiceRunning && !_allowDevelopmentServer) return null;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        try
        {
            // CurrentUserOnly is retained only for an explicitly opted-in Debug development run.
            var options = PipeOptions.Asynchronous |
                (installedServiceRunning ? PipeOptions.None : PipeOptions.CurrentUserOnly);
            await using var pipe = new NamedPipeClientStream(".", _pipeName, StatusPipeServer.ClientRights,
                options, TokenImpersonationLevel.Anonymous, HandleInheritability.None);
            await pipe.ConnectAsync(timeout.Token);
            await PipeMessages.WriteAsync(pipe, StatusProtocol.CreateRequest(), timeout.Token);
            var response = await PipeMessages.ReadAsync(pipe, timeout.Token);
            if (response is null || !StatusProtocol.TryReadResponse(response, out var status)) return null;
            return installedServiceRunning && !IsInstalledServiceRunning() ? null : status;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (System.TimeoutException) { return null; }
    }

    private static bool IsInstalledServiceRunning()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var service = new ServiceController(StatusProtocol.ServiceName);
            service.Refresh();
            return service.Status == ServiceControllerStatus.Running;
        }
        catch (InvalidOperationException) { return false; }
        catch (Win32Exception) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }
}
