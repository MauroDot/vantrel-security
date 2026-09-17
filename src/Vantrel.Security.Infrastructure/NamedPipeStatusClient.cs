using System.IO.Pipes;
using Vantrel.Security.Core;

namespace Vantrel.Security.Infrastructure;

public sealed class NamedPipeStatusClient : ISecurityServiceStatusClient
{
    public async Task<SecurityServiceStatus?> GetStatusAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            await using var pipe = new NamedPipeClientStream(".", StatusProtocol.PipeName, PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(timeout.Token);
            await PipeMessages.WriteAsync(pipe, StatusProtocol.CreateRequest(), timeout.Token);
            var response = await PipeMessages.ReadAsync(pipe, timeout.Token);
            return response is not null && StatusProtocol.TryReadResponse(response, out var status) ? status : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or TimeoutException or OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }
}
