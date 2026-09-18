using System.IO.Pipes;
using Vantrel.Security.Core;

namespace Vantrel.Security.Infrastructure;

public enum PipeFrameFailure { None, EndOfStream, IncompleteFrame, Oversized, TrailingData }

public readonly record struct PipeFrameReadResult(byte[]? Message, PipeFrameFailure Failure, int BytesReceived);

public static class PipeMessages
{
    public static async Task<byte[]?> ReadAsync(PipeStream pipe, CancellationToken cancellationToken) =>
        (await ReadFrameAsync(pipe, cancellationToken)).Message;

    public static async Task<PipeFrameReadResult> ReadFrameAsync(PipeStream pipe, CancellationToken cancellationToken)
    {
        using var bytes = new MemoryStream();
        var buffer = new byte[256];
        while (bytes.Length <= StatusProtocol.MaximumMessageBytes)
        {
            var count = await pipe.ReadAsync(buffer, cancellationToken);
            if (count == 0)
                return new(null, bytes.Length == 0 ? PipeFrameFailure.EndOfStream : PipeFrameFailure.IncompleteFrame,
                    checked((int)bytes.Length));
            for (var index = 0; index < count; index++)
            {
                if (buffer[index] == (byte)'\n')
                {
                    var received = checked((int)(bytes.Length + count));
                    if (index != count - 1) return new(null, PipeFrameFailure.TrailingData, received);
                    if (bytes.Length + index > StatusProtocol.MaximumMessageBytes)
                        return new(null, PipeFrameFailure.Oversized, received);
                    return new(Combine(bytes, buffer.AsSpan(0, index)), PipeFrameFailure.None, received);
                }
            }
            if (bytes.Length + count > StatusProtocol.MaximumMessageBytes)
                return new(null, PipeFrameFailure.Oversized, checked((int)(bytes.Length + count)));
            bytes.Write(buffer, 0, count);
        }
        return new(null, PipeFrameFailure.Oversized, checked((int)bytes.Length));
    }

    private static byte[] Combine(MemoryStream bytes, ReadOnlySpan<byte> tail)
    {
        bytes.Write(tail);
        return bytes.ToArray();
    }

    public static async Task WriteAsync(PipeStream pipe, byte[] message, CancellationToken cancellationToken)
    {
        if (message.Length > StatusProtocol.MaximumMessageBytes) throw new InvalidDataException("Message is too large.");
        await pipe.WriteAsync(message, cancellationToken);
        await pipe.WriteAsync(new byte[] { (byte)'\n' }, cancellationToken);
        await pipe.FlushAsync(cancellationToken);
    }
}
