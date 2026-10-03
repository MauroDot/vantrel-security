using System.Security.AccessControl;

namespace Vantrel.Security.Service;

/// <summary>
/// Fixed cross-process ownership boundary for an elevated offline update operation.
/// It is deliberately distinct from the short-lived journal lock: SCM startup must
/// remain able to consume a recovery authorization while the administrator owns this.
/// </summary>
internal interface IOfflineUpdateOwnershipLock
{
    IDisposable? TryAcquire(CancellationToken token);
}

internal sealed class OfflineUpdateOwnershipLock : IOfflineUpdateOwnershipLock
{
    internal const string OwnerLockFileName = ".offline-update-owner-v1.lock";
    private readonly string _updatesRoot;
    private readonly string _ownerLockPath;
    private readonly bool _applyAcls;

    internal OfflineUpdateOwnershipLock() : this(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Vantrel Security"), applyAcls: true) { }

    internal OfflineUpdateOwnershipLock(string vantrelRoot, bool applyAcls = true)
    {
        var root = Path.GetFullPath(vantrelRoot);
        _updatesRoot = Path.Combine(root, "Updates");
        _ownerLockPath = Path.Combine(_updatesRoot, OwnerLockFileName);
        _applyAcls = applyAcls;
    }

    public IDisposable? TryAcquire(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        RequireProvisionedInfrastructure();
        try
        {
            return new FileStream(_ownerLockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough);
        }
        catch (IOException error) when (IsContention(error))
        {
            return null;
        }
    }

    private void RequireProvisionedInfrastructure()
    {
        if (!Directory.Exists(_updatesRoot) || !File.Exists(_ownerLockPath))
            throw new IOException("Protected offline update ownership infrastructure is unavailable.");
        var rootAttributes = File.GetAttributes(_updatesRoot);
        UpdateTransactionJournalStore.RejectReparseAttributes(rootAttributes);
        if ((rootAttributes & FileAttributes.Directory) == 0) throw new IOException("Update ownership root is not a directory.");
        var lockAttributes = File.GetAttributes(_ownerLockPath);
        UpdateTransactionJournalStore.RejectReparseAttributes(lockAttributes);
        if ((lockAttributes & FileAttributes.Directory) != 0) throw new IOException("Update ownership synchronization object is not a regular file.");
        if (_applyAcls)
        {
            var validation = UpdateFilesystemSecurity.ValidateProvisionedMutableFileOnDisk(new FileInfo(_ownerLockPath));
            if (!validation.IsMatch) throw new IOException("Offline update ownership descriptor verification failed: " + validation.Mismatch);
        }
    }

    private static bool IsContention(IOException error) => unchecked((uint)error.HResult) is 0x80070020 or 0x80070021;
}
