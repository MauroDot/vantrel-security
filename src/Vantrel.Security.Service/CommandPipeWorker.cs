using System.IO.Pipes;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;

namespace Vantrel.Security.Service;

public sealed class CommandPipeWorker : BackgroundService
{
    private readonly CommandRequestRegistry registry;
    private readonly CommandAuditStore audit;
    private readonly TrustedManifestRefreshCoordinator coordinator;
    private readonly CommandRejectionLogLimiter rejectionLimiter;
    private readonly ILogger<CommandPipeWorker> logger;
    private readonly string pipeName;

    public CommandPipeWorker(CommandRequestRegistry registry, CommandAuditStore audit,
        TrustedManifestRefreshCoordinator coordinator, CommandRejectionLogLimiter rejectionLimiter, ILogger<CommandPipeWorker> logger)
        : this(registry, audit, coordinator, rejectionLimiter, logger, CommandProtocol.PipeName) { }

    internal CommandPipeWorker(CommandRequestRegistry registry, CommandAuditStore audit,
        TrustedManifestRefreshCoordinator coordinator, CommandRejectionLogLimiter rejectionLimiter, ILogger<CommandPipeWorker> logger, string pipeName)
    {
        this.registry = registry; this.audit = audit; this.coordinator = coordinator;
        this.rejectionLimiter = rejectionLimiter; this.logger = logger; this.pipeName = pipeName;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await using var pipe = CommandPipeServer.Create(pipeName);
        logger.LogInformation("Local command pipe started");
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var accepted = false;
                try
                {
                    await pipe.WaitForConnectionAsync(stoppingToken); accepted = true;
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken); timeout.CancelAfter(TimeSpan.FromSeconds(3));
                    var request = await PipeMessages.ReadAsync(pipe, timeout.Token);
                    if (request is null || !CommandProtocol.TryReadRequest(request, out var id)) { LogReject("Malformed"); continue; }
                    var requestId = id!;
                    var caller = CommandCallerAuthorizer.Classify(pipe); // RunAsClient returns before admission or collection.
                    if (!CommandCallerAuthorizer.Authorized(caller))
                    {
                        audit.Add(requestId, caller, CommandAuditOutcome.Rejected); await Reply(pipe, requestId, CommandResult.Rejected, CommandFailureReason.Unauthorized, timeout.Token); LogReject("Unauthorized"); continue;
                    }
                    // Admission and reservation are one critical section: an in-progress result never consumes capacity.
                    var result = registry.AdmitAndReserve(requestId, () => coordinator.TryRefreshCommand(requestId, caller));
                    var reason = result == CommandResult.Rejected ? CommandFailureReason.RateLimited : CommandFailureReason.None;
                    audit.Add(requestId, caller, result switch { CommandResult.Accepted => CommandAuditOutcome.Accepted, CommandResult.Duplicate => CommandAuditOutcome.Duplicate, CommandResult.Rejected => CommandAuditOutcome.RateLimited, _ => CommandAuditOutcome.Rejected });
                    await Reply(pipe, requestId, result, reason, timeout.Token);
                    if (result == CommandResult.Accepted) logger.LogInformation("Authorized command accepted");
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (OperationCanceledException) { LogReject("Timeout"); }
                catch (IOException) { LogReject("IoFailure"); }
                finally { if (accepted) try { pipe.Disconnect(); } catch { } }
            }
        }
        finally { logger.LogInformation("Local command pipe stopped"); }
    }
    private static Task Reply(NamedPipeServerStream pipe, string id, CommandResult result, CommandFailureReason reason, CancellationToken token) => PipeMessages.WriteAsync(pipe, CommandProtocol.CreateResponse(new CommandResponse(id, result, DateTimeOffset.UtcNow, reason)), token);
    private void LogReject(string reason) { if (rejectionLimiter.ShouldLog(reason)) logger.LogWarning("Command IPC rejected: {Reason}", reason); }
}
