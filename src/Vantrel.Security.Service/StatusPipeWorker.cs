using System.IO.Pipes;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;

namespace Vantrel.Security.Service;

public sealed class StatusPipeWorker : BackgroundService
{
    private readonly ServiceStatusStore _store;
    private readonly SystemHealthStore _healthStore;
    private readonly ActivityStore _activityStore;
    private readonly ScanCapabilityStore _scanCapabilityStore;
    private readonly ComponentInspectionStore _componentInspectionStore;
    private readonly ComponentIntegrityStore _componentIntegrityStore;
    private readonly TrustedManifestIntegrityStore _trustedManifestIntegrityStore;
    private readonly ILogger<StatusPipeWorker> _logger;
    private readonly string _pipeName;
    private DateTimeOffset _lastExpectedErrorLogUtc = DateTimeOffset.MinValue;
    private string? _lastExpectedErrorKey;
    private DateTimeOffset _lastConnectedLogUtc = DateTimeOffset.MinValue;
    private DateTimeOffset _lastResponseConsumedLogUtc = DateTimeOffset.MinValue;

    public StatusPipeWorker(ServiceStatusStore store, SystemHealthStore healthStore, ActivityStore activityStore,
        ScanCapabilityStore scanCapabilityStore, ComponentInspectionStore componentInspectionStore, ComponentIntegrityStore componentIntegrityStore, TrustedManifestIntegrityStore trustedManifestIntegrityStore, ILogger<StatusPipeWorker> logger)
        : this(store, healthStore, activityStore, scanCapabilityStore, componentInspectionStore, componentIntegrityStore, trustedManifestIntegrityStore, logger, StatusProtocol.PipeName) { }

    internal StatusPipeWorker(ServiceStatusStore store, ILogger<StatusPipeWorker> logger, string pipeName)
        : this(store, new SystemHealthStore(), new ActivityStore(store), new ScanCapabilityStore(), new ComponentInspectionStore(), new ComponentIntegrityStore(), new TrustedManifestIntegrityStore(), logger, pipeName) { }

    internal StatusPipeWorker(ServiceStatusStore store, SystemHealthStore healthStore,
        ILogger<StatusPipeWorker> logger, string pipeName)
        : this(store, healthStore, new ActivityStore(store), new ScanCapabilityStore(), new ComponentInspectionStore(), new ComponentIntegrityStore(), new TrustedManifestIntegrityStore(), logger, pipeName) { }

    internal StatusPipeWorker(ServiceStatusStore store, SystemHealthStore healthStore, ActivityStore activityStore,
        ILogger<StatusPipeWorker> logger, string pipeName)
        : this(store, healthStore, activityStore, new ScanCapabilityStore(), new ComponentInspectionStore(), new ComponentIntegrityStore(), new TrustedManifestIntegrityStore(), logger, pipeName) { }

    internal StatusPipeWorker(ServiceStatusStore store, SystemHealthStore healthStore, ActivityStore activityStore,
        ScanCapabilityStore scanCapabilityStore, ILogger<StatusPipeWorker> logger, string pipeName)
        : this(store, healthStore, activityStore, scanCapabilityStore, new ComponentInspectionStore(), new ComponentIntegrityStore(), new TrustedManifestIntegrityStore(), logger, pipeName) { }

    internal StatusPipeWorker(ServiceStatusStore store, SystemHealthStore healthStore, ActivityStore activityStore,
        ScanCapabilityStore scanCapabilityStore, ComponentInspectionStore componentInspectionStore,
        ILogger<StatusPipeWorker> logger, string pipeName)
        : this(store, healthStore, activityStore, scanCapabilityStore, componentInspectionStore, new ComponentIntegrityStore(), new TrustedManifestIntegrityStore(), logger, pipeName) { }

    internal StatusPipeWorker(ServiceStatusStore store, SystemHealthStore healthStore, ActivityStore activityStore,
        ScanCapabilityStore scanCapabilityStore, ComponentInspectionStore componentInspectionStore,
        ComponentIntegrityStore componentIntegrityStore,
        ILogger<StatusPipeWorker> logger, string pipeName)
        : this(store, healthStore, activityStore, scanCapabilityStore, componentInspectionStore, componentIntegrityStore, new TrustedManifestIntegrityStore(), logger, pipeName) { }

    internal StatusPipeWorker(ServiceStatusStore store, SystemHealthStore healthStore, ActivityStore activityStore,
        ScanCapabilityStore scanCapabilityStore, ComponentInspectionStore componentInspectionStore,
        ComponentIntegrityStore componentIntegrityStore, TrustedManifestIntegrityStore trustedManifestIntegrityStore,
        ILogger<StatusPipeWorker> logger, string pipeName)
    {
        _store = store;
        _healthStore = healthStore;
        _activityStore = activityStore;
        _scanCapabilityStore = scanCapabilityStore;
        _componentInspectionStore = componentInspectionStore;
        _componentIntegrityStore = componentIntegrityStore;
        _trustedManifestIntegrityStore = trustedManifestIntegrityStore;
        _logger = logger;
        _pipeName = pipeName;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Keep the first and only pipe instance open for the whole service lifetime.
        // A pre-existing pipe causes startup to fail instead of serving a spoofed endpoint.
        NamedPipeServerStream? pipe = null;
        try
        {
            try { pipe = StatusPipeServer.Create(_pipeName); }
            catch (Exception error)
            {
                LogExpectedError("ServerCreationFailure", "CreateServer", error);
                throw;
            }
            _logger.LogInformation("Local status pipe started");
            while (!stoppingToken.IsCancellationRequested)
            {
                var accepted = false;
                var stage = "WaitForConnection";
                try
                {
                    await pipe.WaitForConnectionAsync(stoppingToken);
                    accepted = true;
                    LogProgress("ClientConnected", ref _lastConnectedLogUtc);
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    timeout.CancelAfter(TimeSpan.FromSeconds(3));
                    stage = "ReadRequest";
                    var request = await PipeMessages.ReadAsync(pipe, timeout.Token);
                    var kind = request is null ? StatusProtocol.RequestKind.Invalid :
                        StatusProtocol.ReadRequestKind(request);
                    if (kind != StatusProtocol.RequestKind.Invalid &&
                        (kind != StatusProtocol.RequestKind.Activity || _activityStore.Snapshot() is not null) &&
                        (kind != StatusProtocol.RequestKind.ScanCapability ||
                            _scanCapabilityStore.Snapshot() is not null) &&
                        (kind != StatusProtocol.RequestKind.ComponentInspection || _componentInspectionStore.Snapshot() is not null) &&
                        (kind != StatusProtocol.RequestKind.ComponentIntegrity || _componentIntegrityStore.Snapshot() is not null) &&
                        (kind != StatusProtocol.RequestKind.TrustedManifestIntegrity || _trustedManifestIntegrityStore.Snapshot() is not null))
                    {
                        stage = "WriteResponse";
                        var response = kind switch
                        {
                            StatusProtocol.RequestKind.Status => StatusProtocol.CreateResponse(_store.Snapshot()),
                            StatusProtocol.RequestKind.SystemHealth =>
                                StatusProtocol.CreateSystemHealthResponse(_healthStore.Snapshot()),
                            StatusProtocol.RequestKind.Activity =>
                                StatusProtocol.CreateActivityResponse(_activityStore.Snapshot()!),
                            StatusProtocol.RequestKind.ScanCapability => StatusProtocol.CreateScanCapabilityResponse(_scanCapabilityStore.Snapshot()!),
                            StatusProtocol.RequestKind.ComponentInspection => StatusProtocol.CreateComponentInspectionResponse(_componentInspectionStore.Snapshot()!),
                            StatusProtocol.RequestKind.ComponentIntegrity => StatusProtocol.CreateComponentIntegrityResponse(_componentIntegrityStore.Snapshot()!),
                            _ => StatusProtocol.CreateTrustedManifestIntegrityResponse(_trustedManifestIntegrityStore.Snapshot()!)
                        };
                        await PipeMessages.WriteAsync(pipe, response, timeout.Token);
                        // DisconnectNamedPipe discards bytes the client has not read yet. The
                        // client closes its end only after reading the complete response frame.
                        stage = "WaitForClientClose";
                        var trailing = new byte[1];
                        if (await pipe.ReadAsync(trailing, timeout.Token) != 0)
                            LogExpectedError("UnexpectedTrailingData", stage);
                        else LogProgress("ResponseConsumed", ref _lastResponseConsumedLogUtc);
                    }
                    else if (kind == StatusProtocol.RequestKind.Invalid) LogExpectedError("InvalidRequest", stage);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (OperationCanceledException error) { LogExpectedError("Timeout", stage, error); }
                catch (IOException error) { LogExpectedError("PipeIoFailure", stage, error); }
                catch (UnauthorizedAccessException error) { LogExpectedError("AccessDenied", stage, error); }
                catch (Exception error)
                {
                    LogExpectedError("UnexpectedFailure", stage, error);
                    throw;
                }
                finally
                {
                    // A peer that closes before sending data can put the managed stream in Broken
                    // state while its native server instance still needs DisconnectNamedPipe.
                    if (accepted)
                    {
                        try { pipe.Disconnect(); }
                        catch (Exception error)
                        {
                            LogExpectedError("DisconnectFailure", "Disconnect", error);
                            throw;
                        }
                    }
                }
            }
        }
        finally
        {
            if (pipe is not null)
            {
                try { await pipe.DisposeAsync(); }
                catch (Exception error)
                {
                    LogExpectedError("DisposeFailure", "Dispose", error);
                    throw;
                }
            }
            _logger.LogInformation("Local status pipe stopped");
        }
    }

    private void LogExpectedError(string reason, string stage, Exception? error = null)
    {
        var now = DateTimeOffset.UtcNow;
        var exceptionType = error?.GetType().FullName ?? "none";
        var hresult = error?.HResult;
        var key = $"{reason}:{stage}:{exceptionType}:{hresult}";
        if (key == _lastExpectedErrorKey && now - _lastExpectedErrorLogUtc < TimeSpan.FromMinutes(1)) return;
        _lastExpectedErrorKey = key;
        _lastExpectedErrorLogUtc = now;
        _logger.LogWarning("Status IPC {Reason} at {Stage}; exception={ExceptionType}; HRESULT={HResult}; further matching IPC errors are suppressed for one minute",
            reason, stage, exceptionType, hresult?.ToString("X8") ?? "none");
    }

    private void LogProgress(string stage, ref DateTimeOffset lastLogUtc)
    {
        var now = DateTimeOffset.UtcNow;
        if (now - lastLogUtc < TimeSpan.FromMinutes(1)) return;
        lastLogUtc = now;
        _logger.LogInformation("Status IPC {Stage}", stage);
    }
}
