using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

internal enum JournalReadState { Present, Absent, MissingInfrastructure, Invalid }

internal sealed record JournalReadResult(UpdateTransactionJournal? Journal,
    UpdateTransactionJournalParseFailure Failure, JournalReadState State)
{
    internal void Deconstruct(out UpdateTransactionJournal? journal, out UpdateTransactionJournalParseFailure failure)
        => (journal, failure) = (Journal, Failure);
}

public sealed class UpdateTransactionStore
{
    private UpdateTransactionSnapshot? _snapshot;
    public UpdateTransactionSnapshot? Snapshot() => Volatile.Read(ref _snapshot);
    public void Update(UpdateTransactionSnapshot snapshot) => Volatile.Write(ref _snapshot, snapshot);
}

/// <summary>Fixed protected journal location. No runtime caller supplies a root, file, or transaction identifier.</summary>
public sealed class UpdateTransactionJournalStore
{
    internal const string JournalFileName = "current-update-v1";
    internal const string LockFileName = ".current-update-v1.lock";
    private readonly string _updatesRoot;
    private readonly string _transactionsRoot;
    private readonly string _journalPath;
    private readonly bool _applyAcls;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _lockPath;

    public UpdateTransactionJournalStore() : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Vantrel Security"), true) { }
    internal UpdateTransactionJournalStore(string vantrelRoot, bool applyAcls = true)
    {
        var root = Path.GetFullPath(vantrelRoot);
        _updatesRoot = Path.Combine(root, "Updates");
        _transactionsRoot = Path.Combine(_updatesRoot, "Transactions");
        _journalPath = Path.Combine(_transactionsRoot, JournalFileName);
        _applyAcls = applyAcls;
        _lockPath = Path.Combine(_updatesRoot, LockFileName);
    }

    internal async Task<JournalReadResult> ReadAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        // Reads never create update infrastructure. A journal is absent only in a
        // provisioned root that contains the fixed synchronization object.
        if (!Directory.Exists(_updatesRoot) || !Directory.Exists(_transactionsRoot) || !File.Exists(_lockPath))
            return new(null, UpdateTransactionJournalParseFailure.Unavailable, JournalReadState.MissingInfrastructure);
        RejectRegularFile(_lockPath);
        await using var interprocess = await AcquireInterprocessLockAsync(token);
        await _gate.WaitAsync(token);
        try
        {
            // Inspect ancestors from the filesystem root without creating or changing
            // anything. Missing infrastructure is never permission to admit a transaction.
            var ancestors = new Stack<string>();
            for (var directory = new DirectoryInfo(_transactionsRoot); directory is not null; directory = directory.Parent)
                ancestors.Push(directory.FullName);
            while (ancestors.TryPop(out var path))
            {
                FileAttributes attributes;
                try { attributes = File.GetAttributes(path); }
                catch (FileNotFoundException) { return new(null, UpdateTransactionJournalParseFailure.Unavailable, JournalReadState.MissingInfrastructure); }
                catch (DirectoryNotFoundException) { return new(null, UpdateTransactionJournalParseFailure.Unavailable, JournalReadState.MissingInfrastructure); }
                RejectReparseAttributes(attributes);
                if ((attributes & FileAttributes.Directory) == 0) throw new IOException("Journal ancestor is not a directory.");
            }
            FileAttributes journalAttributes;
            try { journalAttributes = File.GetAttributes(_journalPath); }
            catch (FileNotFoundException)
            {
                // Enumerating must succeed: do not mistake inaccessible infrastructure,
                // an orphaned transaction, or a conflicting temporary journal for absence.
                if (Directory.EnumerateFileSystemEntries(_transactionsRoot).Any())
                    throw new IOException("Journal absence conflicts with transaction entries.");
                RejectReparse(_transactionsRoot);
                return new(null, UpdateTransactionJournalParseFailure.Unavailable, JournalReadState.Absent);
            }
            RejectReparseAttributes(journalAttributes);
            if ((journalAttributes & FileAttributes.Directory) != 0) throw new IOException("Journal is not a regular file.");
            var bytes = await File.ReadAllBytesAsync(_journalPath, token);
            return UpdateTransactionJournalCodec.TryParse(bytes, out var journal, out var failure)
                ? new(journal, failure, JournalReadState.Present)
                : new(null, failure, JournalReadState.Invalid);
        }
        finally { _gate.Release(); }
    }

    internal async Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(journal);
        token.ThrowIfCancellationRequested();
        RequireProvisionedInfrastructure();
        await using var interprocess = await AcquireInterprocessLockAsync(token);
        await _gate.WaitAsync(token);
        try
        {
            await PersistLockedAsync(journal, token);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Consumes the one fixed recovery-start capability before any hosted worker is admitted.</summary>
    internal async Task<bool> TryConsumeRecoveryStartAsync(string? nonce, CancellationToken token)
        => await TryConsumeRecoveryStartLeaseAsync(nonce, token) is not null;

    internal async Task<RecoveryStartConsumptionLease?> TryConsumeRecoveryStartLeaseAsync(string? nonce, CancellationToken token)
    {
        if (!UpdateTransactionJournalCodec.IsNonce(nonce)) return null;
        token.ThrowIfCancellationRequested();
        if (!HasProvisionedInfrastructure()) return null;
        await using var interprocess = await AcquireInterprocessLockAsync(token);
        // The same instance gate serializes every journal mutation. SCM permits one service process.
        await _gate.WaitAsync(token);
        try
        {
            if (!File.Exists(_journalPath)) return null;
            var bytes = File.ReadAllBytes(_journalPath);
            if (!UpdateTransactionJournalCodec.TryParse(bytes, out var journal, out _) || journal?.Phase != UpdateTransactionPhase.RollbackRestartAuthorized ||
                !string.Equals(journal.RecoveryStartNonce, nonce, StringComparison.Ordinal)) return null;
            var now = DateTimeOffset.UtcNow; now = new DateTimeOffset(now.Ticks - now.Ticks % TimeSpan.TicksPerSecond, TimeSpan.Zero);
            var next = UpdateTransactionStateMachine.Transition(journal with { RecoveryStartNonce = null }, UpdateTransactionPhase.RollbackRestartConsumed, now);
            // Once the compare has selected this authorization, complete the durable
            // consume without a cancellation gap so the caller always receives a lease
            // it can release or revoke.
            await PersistLockedAsync(next, CancellationToken.None);
            return new(journal.TransactionId, journal.BackupId, journal.PriorReleaseSequence, journal.PriorManifestSha256);
        }
        finally { _gate.Release(); }
    }

    internal async Task RevokeConsumedRecoveryStartAsync(RecoveryStartConsumptionLease lease, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(lease);
        RequireProvisionedInfrastructure();
        await using var interprocess = await AcquireInterprocessLockAsync(token);
        await _gate.WaitAsync(token);
        try
        {
            if (!File.Exists(_journalPath)) return;
            var bytes = await File.ReadAllBytesAsync(_journalPath, token);
            if (!UpdateTransactionJournalCodec.TryParse(bytes, out var journal, out _) || journal is null ||
                journal.TransactionId != lease.TransactionId || journal.BackupId != lease.BackupId || journal.PriorReleaseSequence != lease.PriorReleaseSequence ||
                journal.PriorManifestSha256 != lease.PriorManifestSha256 || journal.Phase != UpdateTransactionPhase.RollbackRestartConsumed) return;
            var now = DateTimeOffset.UtcNow; now = new DateTimeOffset(now.Ticks - now.Ticks % TimeSpan.TicksPerSecond, TimeSpan.Zero);
            await PersistLockedAsync(UpdateTransactionStateMachine.Transition(journal, UpdateTransactionPhase.RollbackRequired, now), token);
        }
        finally { _gate.Release(); }
    }

    internal static void RejectReparseAttributes(FileAttributes attributes) => ReleasePolicyStore.RejectReparseAttributes(attributes);
    private static void RejectReparse(string path) => RejectReparseAttributes(File.GetAttributes(path));
    private static void RejectRegularFile(string path)
    {
        var attributes = File.GetAttributes(path); RejectReparseAttributes(attributes);
        if ((attributes & FileAttributes.Directory) != 0) throw new IOException("Journal synchronization object is not a regular file.");
    }
    private bool HasProvisionedInfrastructure()
    {
        try { RequireProvisionedInfrastructure(); return true; }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }
    private void RequireProvisionedInfrastructure()
    {
        if (!Directory.Exists(_updatesRoot) || !Directory.Exists(_transactionsRoot) || !File.Exists(_lockPath))
            throw new IOException("Protected update journal infrastructure is unavailable.");
        RejectReparse(_updatesRoot); RejectReparse(_transactionsRoot); RejectRegularFile(_lockPath);
    }
    private async Task<FileStream> AcquireInterprocessLockAsync(CancellationToken token)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(_lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough);
            }
            catch (IOException) when (DateTime.UtcNow < deadline) { await Task.Delay(50, token); }
        }
    }
    private async Task PersistLockedAsync(UpdateTransactionJournal journal, CancellationToken token)
    {
        if (File.Exists(_journalPath))
        {
            RejectReparse(_journalPath);
            var existingBytes = await File.ReadAllBytesAsync(_journalPath, token);
            if (!UpdateTransactionJournalCodec.TryParse(existingBytes, out var existing, out var failure) || existing is null)
                throw new IOException("Existing update transaction journal is invalid: " + failure);
            if (existing.TransactionId != journal.TransactionId || existing.BackupId != journal.BackupId ||
                existing.PriorReleaseSequence != journal.PriorReleaseSequence || existing.PriorManifestSha256 != journal.PriorManifestSha256 ||
                existing.TargetReleaseSequence != journal.TargetReleaseSequence || existing.TargetManifestSha256 != journal.TargetManifestSha256 ||
                (existing.RecoveryStartNonce != journal.RecoveryStartNonce && !((existing.Phase == UpdateTransactionPhase.RollbackRequired && existing.RecoveryStartNonce is null && journal.Phase == UpdateTransactionPhase.RollbackRestartAuthorized && UpdateTransactionJournalCodec.IsNonce(journal.RecoveryStartNonce)) || (existing.Phase == UpdateTransactionPhase.RollbackRestartAuthorized && journal.RecoveryStartNonce is null && journal.Phase is UpdateTransactionPhase.RollbackRestartConsumed or UpdateTransactionPhase.RollbackRequired))) ||
                (existing.Phase != journal.Phase && !UpdateTransactionStateMachine.CanTransition(existing.Phase, journal.Phase)))
                throw new InvalidOperationException("Illegal update transaction journal mutation.");
        }
        else if (journal.Phase != UpdateTransactionPhase.Prepared) throw new InvalidOperationException("A new update transaction journal must begin Prepared.");
        var temporary = Path.Combine(_transactionsRoot, ".transaction-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var bytes = UpdateTransactionJournalCodec.Serialize(journal);
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { RejectReparse(temporary); if (_applyAcls) ApplyFileAcl(temporary); await stream.WriteAsync(bytes, token); await stream.FlushAsync(token); stream.Flush(flushToDisk: true); }
            RejectReparse(temporary); var replaced = File.Exists(_journalPath);
            if (replaced) { RejectReparse(_journalPath); File.Replace(temporary, _journalPath, null); } else File.Move(temporary, _journalPath, false);
            RejectReparse(_journalPath);
            if (_applyAcls) { ApplyFileAcl(_journalPath); if (replaced) { var validation = UpdateFilesystemSecurity.ValidateLocalServiceReplacedMutableFileOnDisk(new FileInfo(_journalPath)); if (!validation.IsMatch) throw new IOException("LocalService-replaced journal descriptor verification failed: " + validation.Mismatch); } }
            var check = await File.ReadAllBytesAsync(_journalPath, token);
            if (!UpdateTransactionJournalCodec.TryParse(check, out var parsed, out var failure) || parsed != journal) throw new IOException("Update transaction journal verification failed: " + failure);
        }
        finally { if (File.Exists(temporary)) { try { RejectReparse(temporary); File.Delete(temporary); } catch { } } }
    }
    private static void ApplyDirectoryAcl(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null), FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }
    private static void ApplyFileAcl(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        new FileInfo(path).SetAccessControl(UpdateFilesystemSecurity.CreateMutableFileDaclDescriptor());
    }
}
