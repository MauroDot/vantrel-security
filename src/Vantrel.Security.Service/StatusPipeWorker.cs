using System.IO.Pipes;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;

namespace Vantrel.Security.Service;

public sealed class StatusPipeWorker(ServiceStatusStore store, ILogger<StatusPipeWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Local status pipe starting");
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = new NamedPipeServerStream(StatusProtocol.PipeName, PipeDirection.InOut,
                    1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await pipe.WaitForConnectionAsync(stoppingToken);
                logger.LogInformation("Local status client connected");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(3));
                var request = await PipeMessages.ReadAsync(pipe, timeout.Token);
                if (request is not null && StatusProtocol.IsValidRequest(request))
                    await PipeMessages.WriteAsync(pipe, StatusProtocol.CreateResponse(store.Snapshot()), timeout.Token);
                else logger.LogWarning("Rejected invalid status request");
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (OperationCanceledException) { logger.LogWarning("Status client timed out"); }
            catch (IOException error) { logger.LogWarning(error, "Status pipe I/O error"); }
            catch (UnauthorizedAccessException error) { logger.LogWarning(error, "Status pipe access denied"); }
            catch (Exception error)
            {
                logger.LogError(error, "Unexpected status pipe error");
                try { await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            }
        }
        logger.LogInformation("Local status pipe stopped");
    }
}
