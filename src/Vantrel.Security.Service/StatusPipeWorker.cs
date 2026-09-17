using System.IO.Pipes;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;

namespace Vantrel.Security.Service;

public sealed class StatusPipeWorker : BackgroundService
{
    private readonly ServiceStatusStore _store;
    private readonly ILogger<StatusPipeWorker> _logger;
    private readonly string _pipeName;
    private DateTimeOffset _lastExpectedErrorLogUtc = DateTimeOffset.MinValue;

    public StatusPipeWorker(ServiceStatusStore store, ILogger<StatusPipeWorker> logger)
        : this(store, logger, StatusProtocol.PipeName) { }

    internal StatusPipeWorker(ServiceStatusStore store, ILogger<StatusPipeWorker> logger, string pipeName)
    {
        _store = store;
        _logger = logger;
        _pipeName = pipeName;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Keep the first and only pipe instance open for the whole service lifetime.
        // A pre-existing pipe causes startup to fail instead of serving a spoofed endpoint.
        await using var pipe = StatusPipeServer.Create(_pipeName);
        _logger.LogInformation("Local status pipe started");
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await pipe.WaitForConnectionAsync(stoppingToken);
                    _logger.LogDebug("Local status client connected");
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    timeout.CancelAfter(TimeSpan.FromSeconds(3));
                    var request = await PipeMessages.ReadAsync(pipe, timeout.Token);
                    if (request is not null && StatusProtocol.IsValidRequest(request))
                        await PipeMessages.WriteAsync(pipe, StatusProtocol.CreateResponse(_store.Snapshot()), timeout.Token);
                    else LogExpectedError("Rejected invalid status request");
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (OperationCanceledException) { LogExpectedError("Status client timed out"); }
                catch (IOException) { LogExpectedError("Status pipe I/O error"); }
                catch (UnauthorizedAccessException) { LogExpectedError("Status pipe access denied"); }
                finally
                {
                    if (pipe.IsConnected) pipe.Disconnect();
                }
            }
        }
        finally { _logger.LogInformation("Local status pipe stopped"); }
    }

    private void LogExpectedError(string message)
    {
        var now = DateTimeOffset.UtcNow;
        if (now - _lastExpectedErrorLogUtc < TimeSpan.FromMinutes(1)) return;
        _lastExpectedErrorLogUtc = now;
        _logger.LogWarning("{IpcEvent}; further expected IPC errors are suppressed for one minute", message);
    }
}
