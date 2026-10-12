using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

internal enum V2JournalReadState { Present, Absent, MissingInfrastructure, Invalid }

internal sealed record V2JournalReadResult(
    V2UpdateTransactionJournal? Journal,
    UpdateTransactionJournalParseFailure Failure,
    V2JournalReadState State);

/// <summary>Journal publication happened or cannot be ruled out, so callers must re-read.</summary>
internal sealed class V2JournalPostPublicationException : IOException
{
    internal V2JournalPostPublicationException(Exception inner)
        : base("V2 update journal may have been published; re-read durable state before acting.", inner) { }
}

/// <summary>
/// Fixed V2 journal storage. The production constructor has no caller-controlled paths;
/// the root-taking constructor is internal and rejects protected production overlap.
/// Infrastructure is provisioned separately and is never created or repaired here.
/// </summary>
internal sealed class V2UpdateTransactionJournalStore
{
    internal const string JournalFileName = "current-update-v2";
    internal const string LockFileName = ".current-update-v2.lock";

    private readonly string _productRoot;
    private readonly string _updatesRoot;
    private readonly string _transactionsRoot;
    private readonly string _journalPath;
    private readonly string _lockPath;
    private readonly bool _applyAcls;
    private readonly Func<CancellationToken, Task>? _afterPublicationForTest;
    private readonly Func<CancellationToken, Task>? _beforePublicationForTest;
    private readonly Action<string, string, bool>? _publicationAttemptForTest;
    private readonly SemaphoreSlim _gate = new(1, 1);

    internal V2UpdateTransactionJournalStore()
        : this(FixedUpdatePaths.VantrelRoot, applyAcls: true, afterPublicationForTest: null,
            beforePublicationForTest: null, publicationAttemptForTest: null, productionRoot: true) { }

    // Only tests in the friend assembly can inject a disposable root or a publication fault.
    internal V2UpdateTransactionJournalStore(string disposableProductRoot, bool applyAcls = true,
        Func<CancellationToken, Task>? afterPublicationForTest = null,
        Func<CancellationToken, Task>? beforePublicationForTest = null,
        Action<string, string, bool>? publicationAttemptForTest = null)
        : this(disposableProductRoot, applyAcls, afterPublicationForTest, beforePublicationForTest,
            publicationAttemptForTest,
            productionRoot: false) { }

    private V2UpdateTransactionJournalStore(string productRoot, bool applyAcls,
        Func<CancellationToken, Task>? afterPublicationForTest,
        Func<CancellationToken, Task>? beforePublicationForTest,
        Action<string, string, bool>? publicationAttemptForTest, bool productionRoot)
    {
        _productRoot = ValidateRoot(productRoot, productionRoot);
        _updatesRoot = Path.Combine(_productRoot, "Updates");
        _transactionsRoot = Path.Combine(_updatesRoot, "TransactionsV2");
        _journalPath = Path.Combine(_transactionsRoot, JournalFileName);
        _lockPath = Path.Combine(_updatesRoot, LockFileName);
        _applyAcls = applyAcls;
        _afterPublicationForTest = afterPublicationForTest;
        _beforePublicationForTest = beforePublicationForTest;
        _publicationAttemptForTest = publicationAttemptForTest;
    }

    internal async Task<V2JournalReadResult> ReadAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!InspectProvisionedInfrastructure()) return MissingInfrastructure();
        await using var interprocess = await AcquireInterprocessLockAsync(token);
        await _gate.WaitAsync(token);
        try { return await ReadLockedAsync(token); }
        finally { _gate.Release(); }
    }

    internal async Task PersistAsync(V2UpdateTransactionJournal journal, CancellationToken token)
    {
        var bytes = V2UpdateTransactionJournalCodec.Serialize(journal);
        token.ThrowIfCancellationRequested();
        RequireProvisionedInfrastructure();
        await using var interprocess = await AcquireInterprocessLockAsync(token);
        await _gate.WaitAsync(token);
        try
        {
            var current = await ReadLockedAsync(token);
            RequireReadable(current);
            if (current.State != V2JournalReadState.Absent)
                throw new InvalidOperationException("Existing V2 update journals require an exact-current transition.");
            await PersistLockedAsync(current, journal, bytes, token);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Checks the complete canonical journal view while holding both store locks.</summary>
    internal async Task<bool> IsExactCurrentAsync(V2UpdateTransactionJournal expected, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(expected);
        V2UpdateTransactionJournalCodec.Serialize(expected);
        token.ThrowIfCancellationRequested();
        RequireProvisionedInfrastructure();
        await using var interprocess = await AcquireInterprocessLockAsync(token);
        await _gate.WaitAsync(token);
        try
        {
            var current = await ReadLockedAsync(token);
            RequireReadable(current);
            return current.State == V2JournalReadState.Present && current.Journal == expected;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Compares and publishes under one lock, including admission from exact absence.</summary>
    internal async Task<bool> TryPersistIfExactCurrentAsync(V2UpdateTransactionJournal? expected,
        V2UpdateTransactionJournal next, CancellationToken token)
    {
        if (expected is not null) V2UpdateTransactionJournalCodec.Serialize(expected);
        var bytes = V2UpdateTransactionJournalCodec.Serialize(next);
        token.ThrowIfCancellationRequested();
        RequireProvisionedInfrastructure();
        await using var interprocess = await AcquireInterprocessLockAsync(token);
        await _gate.WaitAsync(token);
        try
        {
            var current = await ReadLockedAsync(token);
            RequireReadable(current);
            if (current.Journal != expected) return false;
            await PersistLockedAsync(current, next, bytes, token);
            return true;
        }
        finally { _gate.Release(); }
    }

    private async Task<V2JournalReadResult> ReadLockedAsync(CancellationToken token)
    {
        if (!InspectProvisionedInfrastructure()) return MissingInfrastructure();
        FileAttributes attributes;
        try { attributes = File.GetAttributes(_journalPath); }
        catch (FileNotFoundException)
        {
            EnsureOnlyExpectedEntries(journalPresent: false);
            return new(null, UpdateTransactionJournalParseFailure.Unavailable, V2JournalReadState.Absent);
        }
        catch (DirectoryNotFoundException)
        {
            // The transaction directory vanished after the infrastructure check.
            return MissingInfrastructure();
        }
        RejectRegularFile(attributes, "V2 update journal");
        EnsureOnlyExpectedEntries(journalPresent: true);
        ValidateMutableFileAcl(_journalPath);
        var bytes = await ReadBoundedJournalBytesAsync(token);
        return V2UpdateTransactionJournalCodec.TryParse(bytes, out var journal, out var failure)
            ? new(journal, failure, V2JournalReadState.Present)
            : new(null, failure, V2JournalReadState.Invalid);
    }

    private async Task PersistLockedAsync(V2JournalReadResult current, V2UpdateTransactionJournal next,
        byte[] bytes, CancellationToken token)
    {
        RequireReadable(current);
        var existing = current.Journal;
        if (existing is not null)
        {
            if (existing == next) return;
            if (!HasSameImmutableIdentity(existing, next) ||
                (existing.Phase == V2UpdateTransactionPhase.PolicyCommitPending &&
                 next.Phase == V2UpdateTransactionPhase.PolicyCommitted) ||
                !V2UpdateTransactionStateMachine.CanTransition(existing.Phase, next.Phase) ||
                next.UpdatedAtUtc < existing.UpdatedAtUtc)
                throw new InvalidOperationException("Illegal V2 update transaction journal mutation.");
        }
        else if (next.Phase != V2UpdateTransactionPhase.Admitted)
            throw new InvalidOperationException("A new V2 update journal must begin Admitted.");

        var temporary = Path.Combine(_transactionsRoot, ".transaction-v2-" + Guid.NewGuid().ToString("N") + ".tmp");
        var publicationAttempted = false;
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                RejectRegularFile(File.GetAttributes(temporary), "Temporary V2 update journal");
                ApplyMutableFileAcl(temporary);
                ValidateMutableFileAcl(temporary);
                await stream.WriteAsync(bytes, token);
                await stream.FlushAsync(token);
                stream.Flush(flushToDisk: true);
            }

            RejectRegularFile(File.GetAttributes(temporary), "Temporary V2 update journal");
            EnsureOnlyExpectedEntries(journalPresent: existing is not null, temporary);
            RequireProvisionedInfrastructure();
            if (_beforePublicationForTest is not null)
                await _beforePublicationForTest(token);
            if (existing is null)
            {
                publicationAttempted = true;
                if (_publicationAttemptForTest is null) File.Move(temporary, _journalPath, overwrite: false);
                else _publicationAttemptForTest(temporary, _journalPath, false);
            }
            else
            {
                RejectRegularFile(File.GetAttributes(_journalPath), "V2 update journal");
                var currentBytes = await ReadBoundedJournalBytesAsync(token);
                if (!V2UpdateTransactionJournalCodec.TryParse(currentBytes, out var justBeforePublish, out _) ||
                    justBeforePublish != existing)
                    throw new IOException("V2 update journal changed before replacement.");
                publicationAttempted = true;
                if (_publicationAttemptForTest is null) File.Replace(temporary, _journalPath, destinationBackupFileName: null);
                else _publicationAttemptForTest(temporary, _journalPath, true);
            }
            RequireTemporaryConsumed(temporary);

            // Cancellation after this boundary cannot turn a committed journal into an
            // apparent aborted operation. Failures here are explicitly publication failures.
            if (_afterPublicationForTest is not null)
                await _afterPublicationForTest(CancellationToken.None);
            RequireProvisionedInfrastructure();
            RejectRegularFile(File.GetAttributes(_journalPath), "V2 update journal");
            ApplyMutableFileAcl(_journalPath);
            ValidateMutableFileAcl(_journalPath);
            EnsureOnlyExpectedEntries(journalPresent: true);
            var readback = await ReadBoundedJournalBytesAsync(CancellationToken.None);
            if (!readback.AsSpan().SequenceEqual(bytes) ||
                !V2UpdateTransactionJournalCodec.TryParse(readback, out var parsed, out _) || parsed != next)
                throw new IOException("V2 update journal canonical readback failed.");
        }
        catch (Exception error) when (publicationAttempted)
        { throw new V2JournalPostPublicationException(error); }
        finally
        {
            // Once a final filesystem operation was attempted, its result is ambiguous.
            // Preserve any remaining temporary file as durable evidence for a blocking read.
            if (!publicationAttempted) DeleteOwnTemporaryIfPresent(temporary);
        }
    }

    private bool InspectProvisionedInfrastructure()
    {
        if (!InspectDirectoryAncestors(_transactionsRoot)) return false;
        FileAttributes lockAttributes;
        try { lockAttributes = File.GetAttributes(_lockPath); }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
        RejectRegularFile(lockAttributes, "V2 update journal lock");
        if (_applyAcls && OperatingSystem.IsWindows())
        {
            RequireDirectoryAcl(_productRoot, UpdateDirectoryRole.ProductRoot);
            RequireDirectoryAcl(_updatesRoot, UpdateDirectoryRole.UpdatesRoot);
            RequireDirectoryAcl(_transactionsRoot, UpdateDirectoryRole.TransactionsRoot);
            var validation = UpdateFilesystemSecurity.ValidateProvisionedMutableFileOnDisk(new FileInfo(_lockPath));
            if (!validation.IsMatch)
                throw new IOException("V2 update journal lock descriptor verification failed: " + validation.Mismatch);
        }
        return true;
    }

    private void RequireProvisionedInfrastructure()
    {
        if (!InspectProvisionedInfrastructure())
            throw new IOException("Protected V2 update journal infrastructure is unavailable.");
    }

    private static bool InspectDirectoryAncestors(string path)
    {
        var ancestors = new Stack<string>();
        for (var directory = new DirectoryInfo(path); directory is not null; directory = directory.Parent)
            ancestors.Push(directory.FullName);
        while (ancestors.TryPop(out var ancestor))
        {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(ancestor); }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
            ReleasePolicyStore.RejectReparseAttributes(attributes);
            if ((attributes & FileAttributes.Directory) == 0)
                throw new IOException("V2 update journal ancestor is not a directory.");
        }
        return true;
    }

    private void EnsureOnlyExpectedEntries(bool journalPresent, string? temporary = null)
    {
        var journalSeen = false;
        var temporarySeen = temporary is null;
        var temporaryName = temporary is null ? null : Path.GetFileName(temporary);
        foreach (var entry in Directory.EnumerateFileSystemEntries(_transactionsRoot))
        {
            var name = Path.GetFileName(entry);
            if (string.Equals(name, JournalFileName, StringComparison.Ordinal)) journalSeen = true;
            else if (temporaryName is not null && string.Equals(name, temporaryName, StringComparison.Ordinal)) temporarySeen = true;
            else throw new IOException("Unexpected entry in V2 update journal directory.");
        }
        if (journalSeen != journalPresent || !temporarySeen)
            throw new IOException("V2 update journal directory changed during inspection.");
    }

    private async Task<FileStream> AcquireInterprocessLockAsync(CancellationToken token)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(_lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None,
                    1, FileOptions.WriteThrough);
            }
            catch (IOException error) when (IsSharingViolation(error) && DateTime.UtcNow < deadline)
            { await Task.Delay(50, token); }
        }
    }

    private static bool IsSharingViolation(IOException error) =>
        unchecked((uint)error.HResult) is 0x80070020 or 0x80070021;

    private async Task<byte[]> ReadBoundedJournalBytesAsync(CancellationToken token)
    {
        await using var stream = new FileStream(_journalPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var buffer = new byte[V2UpdateTransactionJournalCodec.MaximumBytes + 1];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), token);
            if (read == 0) break;
            length += read;
        }
        if (stream.Length != length)
        {
            if (stream.Length <= buffer.Length)
                throw new IOException("V2 update journal changed during bounded read.");
            // The codec rejects MaximumBytes + 1 without ever allocating the file size.
        }
        return buffer.AsSpan(0, length).ToArray();
    }

    private static void RequireReadable(V2JournalReadResult result)
    {
        if (result.State == V2JournalReadState.MissingInfrastructure)
            throw new IOException("Protected V2 update journal infrastructure is unavailable.");
        if (result.State == V2JournalReadState.Invalid)
            throw new IOException("Existing V2 update journal is invalid: " + result.Failure);
    }

    private static bool HasSameImmutableIdentity(V2UpdateTransactionJournal left, V2UpdateTransactionJournal right) =>
        left.TransactionId == right.TransactionId && left.BackupId == right.BackupId &&
        left.Predecessor == right.Predecessor && left.Target == right.Target;

    private static void RejectRegularFile(FileAttributes attributes, string description)
    {
        ReleasePolicyStore.RejectReparseAttributes(attributes);
        if ((attributes & FileAttributes.Directory) != 0)
            throw new IOException(description + " is not a regular file.");
    }

    private static void RequireDirectoryAcl(string path, UpdateDirectoryRole role)
    {
        var validation = UpdateFilesystemSecurity.ValidateDirectoryOnDisk(role, new DirectoryInfo(path));
        if (!validation.IsMatch)
            throw new IOException("V2 update journal directory descriptor verification failed: " + validation.Mismatch);
    }

    private void ValidateMutableFileAcl(string path)
    {
        if (!_applyAcls || !OperatingSystem.IsWindows()) return;
        var file = new FileInfo(path);
        var provisioned = UpdateFilesystemSecurity.ValidateProvisionedMutableFileOnDisk(file);
        if (provisioned.IsMatch) return;
        var replaced = UpdateFilesystemSecurity.ValidateLocalServiceReplacedMutableFileOnDisk(file);
        if (!replaced.IsMatch)
            throw new IOException("V2 update journal file descriptor verification failed: " + replaced.Mismatch);
    }

    private void ApplyMutableFileAcl(string path)
    {
        if (!_applyAcls || !OperatingSystem.IsWindows()) return;
        using var identity = WindowsIdentity.GetCurrent();
        var localService = new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null);
        var descriptor = identity.User?.Equals(localService) == true
            ? UpdateFilesystemSecurity.CreateMutableFileDaclDescriptor()
            : UpdateFilesystemSecurity.CreateProvisionedMutableFileDescriptor();
        new FileInfo(path).SetAccessControl(descriptor);
    }

    private static void DeleteOwnTemporaryIfPresent(string path)
    {
        FileAttributes attributes;
        try { attributes = File.GetAttributes(path); }
        catch (FileNotFoundException) { return; }
        catch (DirectoryNotFoundException) { return; }
        RejectRegularFile(attributes, "Temporary V2 update journal");
        File.Delete(path);
    }

    private static void RequireTemporaryConsumed(string path)
    {
        try { _ = File.GetAttributes(path); }
        catch (FileNotFoundException) { return; }
        catch (DirectoryNotFoundException) { return; }
        throw new IOException("Temporary V2 update journal remains after publication.");
    }

    private static V2JournalReadResult MissingInfrastructure() =>
        new(null, UpdateTransactionJournalParseFailure.Unavailable, V2JournalReadState.MissingInfrastructure);

    private static bool PathsEqual(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private static string ValidateRoot(string root, bool productionRoot)
    {
        if (string.IsNullOrWhiteSpace(root) || !Path.IsPathFullyQualified(root))
            throw new ArgumentException("V2 update product root must be fully qualified.", nameof(root));
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (PathsEqual(full, Path.GetPathRoot(full)!))
            throw new ArgumentException("V2 update product root cannot be a filesystem root.", nameof(root));
        if (productionRoot)
        {
            if (!PathsEqual(full, FixedUpdatePaths.VantrelRoot))
                throw new IOException("Fixed production V2 update root rejected.");
        }
        else if (PathsOverlap(full, FixedUpdatePaths.VantrelRoot) ||
                 PathsOverlap(full, FixedUpdatePaths.InstalledServiceRoot))
            throw new ArgumentException("Disposable V2 update root overlaps protected production storage.", nameof(root));
        return full;
    }

    private static bool PathsOverlap(string left, string right) =>
        IsAtOrBelow(left, right) || IsAtOrBelow(right, left);

    private static bool IsAtOrBelow(string path, string parent)
    {
        path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        parent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent));
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return string.Equals(path, parent, comparison) ||
            path.StartsWith(parent + Path.DirectorySeparatorChar, comparison);
    }
}
