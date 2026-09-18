using System.ComponentModel;
using System.IO.Pipes;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Vantrel.Security.Core;

namespace Vantrel.Security.Infrastructure;

public sealed class NamedPipeStatusClient : ISecurityServiceStatusClient, ISystemHealthClient, IActivityClient,
    IScanCapabilityClient, IComponentInspectionClient,
    IStatusConnectionDiagnostics
{
    private readonly string _pipeName;
    private readonly TimeSpan _timeout;
    private readonly bool _allowDevelopmentServer;
    private readonly ILogger<NamedPipeStatusClient> _logger;
    private readonly object _diagnosticLock = new();
    private long _lastDiagnosticTicks;
    private string? _lastDiagnosticKey;
    private StatusConnectionDiagnostic? _lastDiagnostic;

    public StatusConnectionDiagnostic? LastDiagnostic => Volatile.Read(ref _lastDiagnostic);

    public NamedPipeStatusClient(ILogger<NamedPipeStatusClient> logger)
        : this(StatusProtocol.PipeName, TimeSpan.FromSeconds(3), AllowDevelopmentServer(), logger) { }

    internal NamedPipeStatusClient(string pipeName, TimeSpan timeout, bool allowDevelopmentServer,
        ILogger<NamedPipeStatusClient>? logger = null)
    {
        _pipeName = pipeName;
        _timeout = timeout;
        _allowDevelopmentServer = allowDevelopmentServer;
        _logger = logger ?? NullLogger<NamedPipeStatusClient>.Instance;
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

    public Task<SecurityServiceStatus?> GetStatusAsync(CancellationToken cancellationToken) =>
        QueryAsync(StatusProtocol.CreateRequest(), ReadStatus, cancellationToken);

    public Task<SystemHealthSnapshot?> GetSystemHealthAsync(CancellationToken cancellationToken) =>
        QueryAsync(StatusProtocol.CreateSystemHealthRequest(), ReadHealth, cancellationToken);

    public Task<ActivitySnapshot?> GetActivityAsync(CancellationToken cancellationToken) =>
        QueryAsync(StatusProtocol.CreateActivityRequest(), ReadActivity, cancellationToken);

    public Task<ScanCapabilitySnapshot?> GetScanCapabilityAsync(CancellationToken cancellationToken) =>
        QueryAsync(StatusProtocol.CreateScanCapabilityRequest(), ReadScanCapability, cancellationToken);
    public Task<ComponentInspectionSnapshot?> GetComponentInspectionAsync(CancellationToken cancellationToken) =>
        QueryAsync(StatusProtocol.CreateComponentInspectionRequest(), ReadComponentInspection, cancellationToken);

    private static (SecurityServiceStatus?, StatusResponseFailure) ReadStatus(byte[] frame)
    {
        StatusProtocol.TryReadResponse(frame, out var status, out var failure);
        return (status, failure);
    }

    private static (SystemHealthSnapshot?, StatusResponseFailure) ReadHealth(byte[] frame)
    {
        StatusProtocol.TryReadSystemHealthResponse(frame, out var health, out var failure);
        return (health, failure);
    }

    private static (ActivitySnapshot?, StatusResponseFailure) ReadActivity(byte[] frame)
    {
        StatusProtocol.TryReadActivityResponse(frame, out var activity, out var failure);
        return (activity, failure);
    }

    private static (ScanCapabilitySnapshot?, StatusResponseFailure) ReadScanCapability(byte[] frame)
    {
        StatusProtocol.TryReadScanCapabilityResponse(frame, out var capability, out var failure);
        return (capability, failure);
    }
    private static (ComponentInspectionSnapshot?, StatusResponseFailure) ReadComponentInspection(byte[] frame)
    {
        StatusProtocol.TryReadComponentInspectionResponse(frame, out var value, out var failure); return (value, failure);
    }

    private async Task<T?> QueryAsync<T>(byte[] request,
        Func<byte[], (T? Value, StatusResponseFailure Failure)> readResponse,
        CancellationToken cancellationToken) where T : class
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Status IPC requires Windows.");
        var serviceState = _pipeName == StatusProtocol.PipeName ? GetInstalledServiceState() : ServiceState.NotChecked;
        var installedServiceRunning = serviceState == ServiceState.Running;
        if (!installedServiceRunning && !_allowDevelopmentServer)
        {
            LogUnavailable(serviceState.ToString(), "ScmCheck");
            return null;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        var stage = "CreateClient";
        NamedPipeClientStream? pipe = null;
        try
        {
            // CurrentUserOnly is retained only for an explicitly opted-in Debug development run.
            var options = PipeOptions.Asynchronous |
                (installedServiceRunning ? PipeOptions.None : PipeOptions.CurrentUserOnly);
            pipe = new NamedPipeClientStream(".", _pipeName, StatusPipeServer.ClientRights,
                options, TokenImpersonationLevel.Anonymous, HandleInheritability.None);
            stage = "Connect";
            await pipe.ConnectAsync(timeout.Token);
            stage = "WriteRequest";
            await PipeMessages.WriteAsync(pipe, request, timeout.Token);
            stage = "ReadResponse";
            var frame = await PipeMessages.ReadFrameAsync(pipe, timeout.Token);
            if (frame.Message is null)
            {
                LogUnavailable(frame.Failure.ToString(), stage, bytesReceived: frame.BytesReceived);
                return null;
            }
            stage = "ValidateResponse";
            var (value, failure) = readResponse(frame.Message);
            if (value is null)
            {
                LogUnavailable(failure.ToString(), stage, bytesReceived: frame.BytesReceived);
                return null;
            }
            if (installedServiceRunning && GetInstalledServiceState() != ServiceState.Running)
            {
                LogUnavailable("ServiceStoppedAfterResponse", "ScmPostCheck");
                return null;
            }
            Volatile.Write(ref _lastDiagnostic, null);
            return value;
        }
        catch (OperationCanceledException error) when (!cancellationToken.IsCancellationRequested)
        {
            LogUnavailable("Timeout", stage, error);
            return null;
        }
        catch (IOException error)
        {
            LogUnavailable(ClassifyIoError(error), stage, error);
            return null;
        }
        catch (UnauthorizedAccessException error)
        {
            LogUnavailable("AccessDenied", stage, error);
            return null;
        }
        catch (System.TimeoutException error)
        {
            LogUnavailable("Timeout", stage, error);
            return null;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            LogUnavailable("UnexpectedFailure", stage, error);
            throw;
        }
        finally
        {
            if (pipe is not null)
            {
                try { await pipe.DisposeAsync(); }
                catch (Exception error)
                {
                    LogUnavailable("DisposeFailure", "Dispose", error);
                    throw;
                }
            }
        }
    }

    private enum ServiceState { NotChecked, Running, NotRunning, Missing, QueryFailed }

    private static ServiceState GetInstalledServiceState()
    {
        if (!OperatingSystem.IsWindows()) return ServiceState.QueryFailed;
        try
        {
            using var service = new ServiceController(StatusProtocol.ServiceName);
            service.Refresh();
            return service.Status == ServiceControllerStatus.Running ? ServiceState.Running : ServiceState.NotRunning;
        }
        catch (InvalidOperationException error) when (error.InnerException is Win32Exception { NativeErrorCode: 1060 })
        {
            return ServiceState.Missing;
        }
        catch (InvalidOperationException) { return ServiceState.QueryFailed; }
        catch (Win32Exception) { return ServiceState.QueryFailed; }
        catch (UnauthorizedAccessException) { return ServiceState.QueryFailed; }
    }

    private static string ClassifyIoError(IOException error) => (error.HResult & 0xFFFF) switch
    {
        2 or 3 => "PipeNotFound",
        5 => "AccessDenied",
        109 or 233 => "PipeDisconnected",
        231 => "PipeBusy",
        _ => "PipeIoFailure"
    };

    private void LogUnavailable(string reason, string stage, Exception? error = null, int? bytesReceived = null)
    {
        var now = DateTimeOffset.UtcNow.UtcTicks;
        var exceptionType = error?.GetType().FullName ?? "none";
        var hresult = error?.HResult;
        var diagnostic = new StatusConnectionDiagnostic(_pipeName, reason, stage, exceptionType,
            hresult?.ToString("X8") ?? "none", bytesReceived);
        Volatile.Write(ref _lastDiagnostic, diagnostic);
        var key = $"{reason}:{stage}:{exceptionType}:{hresult}:{bytesReceived}";
        lock (_diagnosticLock)
        {
            if (key == _lastDiagnosticKey && now - _lastDiagnosticTicks < TimeSpan.TicksPerMinute) return;
            _lastDiagnosticKey = key;
            _lastDiagnosticTicks = now;
        }
        _logger.LogWarning("Local status unavailable: {Reason}; stage={Stage}; pipe={PipeName}; exception={ExceptionType}; HRESULT={HResult}; bytes={BytesReceived}",
            reason, stage, _pipeName, exceptionType, diagnostic.HResult, bytesReceived?.ToString() ?? "none");
    }
}
