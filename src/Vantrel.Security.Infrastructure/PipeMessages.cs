using System.IO.Pipes;
using Vantrel.Security.Core;

namespace Vantrel.Security.Infrastructure;

public static class PipeMessages
{
    public static async Task<byte[]?> ReadAsync(PipeStream pipe, CancellationToken cancellationToken)
    {
        using var bytes = new MemoryStream();
        var buffer = new byte[256];
        while (bytes.Length <= StatusProtocol.MaximumMessageBytes)
        {
            var count = await pipe.ReadAsync(buffer, cancellationToken);
            if (count == 0) return null;
            for (var index = 0; index < count; index++)
            {
                if (buffer[index] == (byte)'\n')
                    return index == count - 1 && bytes.Length + index <= StatusProtocol.MaximumMessageBytes
                        ? Combine(bytes, buffer.AsSpan(0, index)) : null;
            }
            if (bytes.Length + count > StatusProtocol.MaximumMessageBytes) return null;
            bytes.Write(buffer, 0, count);
        }
        return null;
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
