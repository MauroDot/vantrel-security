using System.IO;
using System.Security.Cryptography;

namespace Vantrel.Security.Desktop;

internal enum FileFingerprintComparisonOutcome
{
    Match,
    Mismatch,
    InvalidExpectedValue,
    Declined,
    Unavailable,
    Changed,
    AlreadyInProgress
}

internal sealed record FileFingerprintComparisonResult(FileFingerprintComparisonOutcome Outcome)
{
    internal static FileFingerprintComparisonResult From(FileFingerprintComparisonOutcome outcome) => new(outcome);
}

/// <summary>Compares a newly computed SHA-256 fingerprint for one validated local regular file.</summary>
internal sealed class LocalFileFingerprintComparisonInspector
{
    private const int BufferSize = 64 * 1024;
    private readonly LocalFileInspectionCoordinator _coordinator;
    private readonly Func<CancellationToken, Task>? _afterFirstReadAsync;
    private readonly Func<CancellationToken, Task>? _afterPathValidationAsync;

    internal LocalFileFingerprintComparisonInspector(
        LocalFileInspectionCoordinator? coordinator = null,
        Func<CancellationToken, Task>? afterFirstReadAsync = null,
        Func<CancellationToken, Task>? afterPathValidationAsync = null)
    {
        _coordinator = coordinator ?? new LocalFileInspectionCoordinator();
        _afterFirstReadAsync = afterFirstReadAsync;
        _afterPathValidationAsync = afterPathValidationAsync;
    }

    internal async Task<FileFingerprintComparisonResult> CompareAsync(
        string selectedPath, ExpectedSha256Value expected, CancellationToken cancellationToken)
    {
        if (!_coordinator.TryAcquire(out var operation))
            return FileFingerprintComparisonResult.From(FileFingerprintComparisonOutcome.AlreadyInProgress);

        using (operation)
        {
            var opened = await LocalRegularFileLease.OpenAsync(selectedPath, cancellationToken, _afterPathValidationAsync)
                .ConfigureAwait(false);
            if (opened.Outcome != LocalRegularFileLeaseOutcome.Opened)
            {
                return FileFingerprintComparisonResult.From(opened.Outcome == LocalRegularFileLeaseOutcome.Declined
                    ? FileFingerprintComparisonOutcome.Declined
                    : FileFingerprintComparisonOutcome.Unavailable);
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
                    if (read == 0) return FileFingerprintComparisonResult.From(FileFingerprintComparisonOutcome.Changed);
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
                if (!file.IsUnchanged()) return FileFingerprintComparisonResult.From(FileFingerprintComparisonOutcome.Changed);
                return FileFingerprintComparisonResult.From(expected.Matches(Convert.ToHexString(hash.GetHashAndReset()))
                    ? FileFingerprintComparisonOutcome.Match
                    : FileFingerprintComparisonOutcome.Mismatch);
            }
            catch (UnauthorizedAccessException) { return FileFingerprintComparisonResult.From(FileFingerprintComparisonOutcome.Unavailable); }
            catch (IOException) { return FileFingerprintComparisonResult.From(FileFingerprintComparisonOutcome.Unavailable); }
            catch (NotSupportedException) { return FileFingerprintComparisonResult.From(FileFingerprintComparisonOutcome.Unavailable); }
        }
    }
}
