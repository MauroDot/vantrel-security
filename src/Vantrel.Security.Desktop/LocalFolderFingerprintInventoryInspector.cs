using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Vantrel.Security.Desktop;

internal enum FolderFingerprintInventoryOutcome { Completed, Incomplete, Declined, Unavailable, AlreadyInProgress }
internal enum FolderFingerprintEntryOutcome { Fingerprinted, Declined, Unavailable, Changed }

internal sealed record FolderFingerprintInventoryEntry(
    string RelativeName,
    FolderFingerprintEntryOutcome Outcome,
    long? ByteLength,
    string? Sha256);

internal sealed record FolderFingerprintInventoryResult(
    FolderFingerprintInventoryOutcome Outcome,
    IReadOnlyList<FolderFingerprintInventoryEntry> Entries)
{
    internal static FolderFingerprintInventoryResult WithoutEntries(FolderFingerprintInventoryOutcome outcome) => new(outcome, []);
}

internal sealed class LocalFolderFingerprintInventoryInspector
{
    internal const int MaximumProcessedFiles = 64;
    internal const long MaximumFileByteLength = 32L * 1024 * 1024;
    internal const long MaximumAggregateByteLength = 128L * 1024 * 1024;
    internal static readonly TimeSpan MaximumElapsed = TimeSpan.FromSeconds(20);
    private const int BufferSize = 64 * 1024;
    private readonly LocalFileInspectionCoordinator _coordinator;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly Func<CancellationToken, Task>? _afterFirstReadAsync;
    private readonly Func<CancellationToken, Task>? _afterRootOpenAsync;
    private readonly Func<CancellationToken, Task>? _afterRootValidationAsync;
    private readonly Func<string, CancellationToken, Task>? _afterDirectoryEntryEnumeratedAsync;
    private readonly IHandleRelativeDirectoryOperations _directoryOperations;

    internal LocalFolderFingerprintInventoryInspector(
        LocalFileInspectionCoordinator? coordinator = null,
        Func<DateTimeOffset>? utcNow = null,
        Func<CancellationToken, Task>? afterFirstReadAsync = null,
        Func<CancellationToken, Task>? afterRootOpenAsync = null,
        Func<CancellationToken, Task>? afterRootValidationAsync = null,
        Func<string, CancellationToken, Task>? afterDirectoryEntryEnumeratedAsync = null,
        IHandleRelativeDirectoryOperations? directoryOperations = null)
    {
        _coordinator = coordinator ?? new LocalFileInspectionCoordinator();
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        _afterFirstReadAsync = afterFirstReadAsync;
        _afterRootOpenAsync = afterRootOpenAsync;
        _afterRootValidationAsync = afterRootValidationAsync;
        _afterDirectoryEntryEnumeratedAsync = afterDirectoryEntryEnumeratedAsync;
        _directoryOperations = directoryOperations ?? new WindowsHandleRelativeDirectoryOperations();
    }

    internal async Task<FolderFingerprintInventoryResult> InspectAsync(string selectedPath, CancellationToken cancellationToken)
    {
        if (!_coordinator.TryAcquire(out var operation))
            return FolderFingerprintInventoryResult.WithoutEntries(FolderFingerprintInventoryOutcome.AlreadyInProgress);

        using (operation)
        {
            var opened = await LocalRegularDirectoryLease.OpenAsync(selectedPath, cancellationToken).ConfigureAwait(false);
            if (opened.Outcome != LocalRegularDirectoryLeaseOutcome.Opened)
            {
                return FolderFingerprintInventoryResult.WithoutEntries(opened.Outcome == LocalRegularDirectoryLeaseOutcome.Declined
                    ? FolderFingerprintInventoryOutcome.Declined
                    : FolderFingerprintInventoryOutcome.Unavailable);
            }

            using var root = opened.Lease!;
            if (_afterRootOpenAsync is not null)
                await _afterRootOpenAsync(cancellationToken).ConfigureAwait(false);
            var startedAt = _utcNow();
            if (!root.IsUnchanged()) return FolderFingerprintInventoryResult.WithoutEntries(FolderFingerprintInventoryOutcome.Declined);
            if (_afterRootValidationAsync is not null)
                await _afterRootValidationAsync(cancellationToken).ConfigureAwait(false);
            var entries = new List<FolderFingerprintInventoryEntry>();
            long aggregateBytes = 0;
            var processed = 0;
            try
            {
                foreach (var directoryEntry in _directoryOperations.Enumerate(root.Handle))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (directoryEntry.Name is "." or "..") continue;
                    if (IsTimedOut(startedAt) || processed >= MaximumProcessedFiles)
                        return new FolderFingerprintInventoryResult(FolderFingerprintInventoryOutcome.Incomplete, entries);
                    processed++;
                    var relativeName = directoryEntry.Name;
                    if (_afterDirectoryEntryEnumeratedAsync is not null)
                        await _afterDirectoryEntryEnumeratedAsync(relativeName, cancellationToken).ConfigureAwait(false);
                    if (string.IsNullOrEmpty(relativeName) || relativeName.Contains(Path.DirectorySeparatorChar) ||
                        relativeName.Contains(Path.AltDirectorySeparatorChar))
                    {
                        return FolderFingerprintInventoryResult.WithoutEntries(FolderFingerprintInventoryOutcome.Declined);
                    }

                    var fileOpened = await LocalRegularFileLease.OpenDirectoryEntryAsync(root, directoryEntry, _directoryOperations,
                            cancellationToken, MaximumFileByteLength)
                        .ConfigureAwait(false);
                    if (fileOpened.Outcome != LocalRegularFileLeaseOutcome.Opened)
                    {
                        entries.Add(new FolderFingerprintInventoryEntry(relativeName,
                            fileOpened.Outcome == LocalRegularFileLeaseOutcome.Declined
                                ? FolderFingerprintEntryOutcome.Declined
                                : FolderFingerprintEntryOutcome.Unavailable,
                            null, null));
                        continue;
                    }

                    using var file = fileOpened.Lease!;
                    if (file.ByteLength > MaximumAggregateByteLength - aggregateBytes || IsTimedOut(startedAt))
                        return new FolderFingerprintInventoryResult(FolderFingerprintInventoryOutcome.Incomplete, entries);

                    var hashResult = await HashAsync(file, cancellationToken).ConfigureAwait(false);
                    if (hashResult.Outcome == FolderFingerprintEntryOutcome.Fingerprinted)
                        aggregateBytes += file.ByteLength;
                    entries.Add(new FolderFingerprintInventoryEntry(relativeName, hashResult.Outcome,
                        hashResult.Outcome == FolderFingerprintEntryOutcome.Fingerprinted ? file.ByteLength : null,
                        hashResult.Sha256));
                    if (IsTimedOut(startedAt))
                        return new FolderFingerprintInventoryResult(FolderFingerprintInventoryOutcome.Incomplete, entries);
                }
            }
            catch (UnauthorizedAccessException) { return FolderFingerprintInventoryResult.WithoutEntries(FolderFingerprintInventoryOutcome.Unavailable); }
            catch (IOException) { return FolderFingerprintInventoryResult.WithoutEntries(FolderFingerprintInventoryOutcome.Unavailable); }
            catch (NotSupportedException) { return FolderFingerprintInventoryResult.WithoutEntries(FolderFingerprintInventoryOutcome.Unavailable); }

            return root.IsUnchanged()
                ? new FolderFingerprintInventoryResult(FolderFingerprintInventoryOutcome.Completed, entries)
                : FolderFingerprintInventoryResult.WithoutEntries(FolderFingerprintInventoryOutcome.Declined);
        }
    }

    private async Task<(FolderFingerprintEntryOutcome Outcome, string? Sha256)> HashAsync(
        LocalRegularFileLease file, CancellationToken cancellationToken)
    {
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
                if (read == 0) return (FolderFingerprintEntryOutcome.Changed, null);
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
            return file.IsUnchanged()
                ? (FolderFingerprintEntryOutcome.Fingerprinted, Convert.ToHexString(hash.GetHashAndReset()))
                : (FolderFingerprintEntryOutcome.Changed, null);
        }
        catch (UnauthorizedAccessException) { return (FolderFingerprintEntryOutcome.Unavailable, null); }
        catch (IOException) { return (FolderFingerprintEntryOutcome.Unavailable, null); }
        catch (NotSupportedException) { return (FolderFingerprintEntryOutcome.Unavailable, null); }
    }

    private bool IsTimedOut(DateTimeOffset startedAt) => _utcNow() - startedAt >= MaximumElapsed;
}
