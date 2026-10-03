using System;
using System.IO;
using System.Security.Cryptography;

namespace Vantrel.Security.Desktop;

internal enum FileFingerprintInspectionOutcome
{
    Completed,
    Declined,
    Unavailable,
    Changed,
    AlreadyInProgress
}

internal sealed record FileFingerprintInspectionResult(
    FileFingerprintInspectionOutcome Outcome,
    string? FileName,
    long? ByteLength,
    string? Sha256)
{
    internal static FileFingerprintInspectionResult Completed(string fileName, long byteLength, string sha256) =>
        new(FileFingerprintInspectionOutcome.Completed, fileName, byteLength, sha256);

    internal static FileFingerprintInspectionResult WithoutFile(FileFingerprintInspectionOutcome outcome) =>
        new(outcome, null, null, null);
}

/// <summary>Creates a transient SHA-256 fingerprint for one validated local regular file.</summary>
internal sealed class LocalFileFingerprintInspector
{
    internal const long MaximumByteLength = LocalRegularFileLease.MaximumByteLength;
    private const int BufferSize = 64 * 1024;
    private readonly Func<CancellationToken, Task>? _afterFirstReadAsync;
    private readonly Func<CancellationToken, Task>? _afterPathValidationAsync;
    private readonly LocalFileInspectionCoordinator _coordinator;

    internal LocalFileFingerprintInspector(
        Func<CancellationToken, Task>? afterFirstReadAsync = null,
        Func<CancellationToken, Task>? afterPathValidationAsync = null,
        LocalFileInspectionCoordinator? coordinator = null)
    {
        _afterFirstReadAsync = afterFirstReadAsync;
        _afterPathValidationAsync = afterPathValidationAsync;
        _coordinator = coordinator ?? new LocalFileInspectionCoordinator();
    }

    internal async Task<FileFingerprintInspectionResult> InspectAsync(string selectedPath, CancellationToken cancellationToken)
    {
        if (!_coordinator.TryAcquire(out var operation))
            return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.AlreadyInProgress);

        using (operation)
        {
            var opened = await LocalRegularFileLease.OpenAsync(selectedPath, cancellationToken, _afterPathValidationAsync)
                .ConfigureAwait(false);
            if (opened.Outcome != LocalRegularFileLeaseOutcome.Opened)
            {
                return FileFingerprintInspectionResult.WithoutFile(opened.Outcome == LocalRegularFileLeaseOutcome.Declined
                    ? FileFingerprintInspectionOutcome.Declined
                    : FileFingerprintInspectionOutcome.Unavailable);
            }

            using var file = opened.Lease!;
            try
            {
                var buffer = new byte[BufferSize];
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                long offset = 0;
                var firstRead = true;
                while (offset < file.ByteLength)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var requested = (int)Math.Min(buffer.Length, file.ByteLength - offset);
                    var read = await RandomAccess.ReadAsync(file.Handle, buffer.AsMemory(0, requested), offset, cancellationToken)
                        .ConfigureAwait(false);
                    if (read == 0)
                        return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Changed);

                    hash.AppendData(buffer, 0, read);
                    offset += read;
                    if (firstRead)
                    {
                        firstRead = false;
                        if (_afterFirstReadAsync is not null)
                            await _afterFirstReadAsync(cancellationToken).ConfigureAwait(false);
                    }
                }

                cancellationToken.ThrowIfCancellationRequested();
                if (!file.IsUnchanged())
                    return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Changed);

                return FileFingerprintInspectionResult.Completed(
                    file.FileName, file.ByteLength, Convert.ToHexString(hash.GetHashAndReset()));
            }
            catch (UnauthorizedAccessException) { return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Unavailable); }
            catch (IOException) { return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Unavailable); }
            catch (NotSupportedException) { return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Unavailable); }
        }
    }
}
