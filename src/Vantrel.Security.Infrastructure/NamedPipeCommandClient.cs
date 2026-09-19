using System.IO.Pipes;
using System.Security.Principal;
using Vantrel.Security.Core;

namespace Vantrel.Security.Infrastructure;

public sealed class NamedPipeCommandClient : ITrustedManifestRefreshCommandClient
{
    private readonly string _pipeName;
    public NamedPipeCommandClient() : this(CommandProtocol.PipeName) { }
    internal NamedPipeCommandClient(string pipeName) { _pipeName = pipeName; }

    public async Task<CommandResponse?> RefreshTrustedManifestIntegrityAsync(string requestId, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        using var pipe = new NamedPipeClientStream(".", _pipeName, StatusPipeServer.ClientRights,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation, HandleInheritability.None);
        try
        {
            await pipe.ConnectAsync(timeout.Token);
            await PipeMessages.WriteAsync(pipe, CommandProtocol.CreateRefreshRequest(requestId), timeout.Token);
            var frame = await PipeMessages.ReadFrameAsync(pipe, timeout.Token);
            return frame.Message is not null && CommandProtocol.TryReadResponse(frame.Message, out var response) &&
                response?.RequestId == requestId ? response : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }
}
