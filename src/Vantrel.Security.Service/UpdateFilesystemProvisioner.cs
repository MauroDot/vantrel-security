using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

internal sealed record ProvisionedUpdateFilesystem(
    string ProductRoot,
    string UpdatesRoot,
    string TransactionsRoot,
    string TransactionRoot,
    string PrivateCandidateRoot,
    string BackupsRoot,
    string FixedBackupRoot,
    string ReleasePolicyRoot,
    string JournalLockFile,
    string OwnerLockFile,
    string JournalFile,
    string PolicyFile);

/// <summary>Administrator-only descriptor provisioning. No production caller activates it.</summary>
internal sealed class UpdateFilesystemProvisioner
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier AuthenticatedUsers = new(WellKnownSidType.AuthenticatedUserSid, null);
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);
    private readonly string _productRoot;
    private readonly bool _disposableBoundary;
    private readonly Func<bool> _isAdministrator;

    internal UpdateFilesystemProvisioner() : this(FixedUpdatePaths.VantrelRoot, false, HasEnabledAdministratorToken) { }

    internal UpdateFilesystemProvisioner(string disposableProductRoot, Func<bool>? isAdministrator = null) :
        this(ValidateDisposableRoot(disposableProductRoot), true, isAdministrator ?? HasEnabledAdministratorToken) { }

    private UpdateFilesystemProvisioner(string productRoot, bool disposableBoundary, Func<bool> isAdministrator)
    {
        _productRoot = productRoot;
        _disposableBoundary = disposableBoundary;
        _isAdministrator = isAdministrator;
    }

    internal ProvisionedUpdateFilesystem ProvisionDisposableFixture(string transactionId, string backupId)
        => ProvisionDisposableFixtureCore(transactionId, backupId, null, null);

    // Internal test-only operation-boundary faults. Production has no construction
    // path, configuration, environment, or command-line route to these callbacks.
    internal ProvisionedUpdateFilesystem ProvisionDisposableFixtureForTest(string transactionId, string backupId,
        Func<int, bool>? failDirectoryCreation, Func<int, bool>? failAclApplication) =>
        ProvisionDisposableFixtureCore(transactionId, backupId, failDirectoryCreation, failAclApplication);

    private ProvisionedUpdateFilesystem ProvisionDisposableFixtureCore(string transactionId, string backupId,
        Func<int, bool>? failDirectoryCreation, Func<int, bool>? failAclApplication)
    {
        if (!_isAdministrator()) throw new UnauthorizedAccessException("An enabled Administrator token is required.");
        if (!_disposableBoundary) throw new InvalidOperationException("Disposable provisioning requires the validated test boundary.");
        if (!UpdateTransactionJournalCodec.IsId(transactionId) || !UpdateTransactionJournalCodec.IsId(backupId))
            throw new ArgumentException("Fixed transaction identity is invalid.");
        if (Directory.Exists(_productRoot) || File.Exists(_productRoot))
            throw new IOException("Disposable product root already exists.");

        var paths = Paths(transactionId, backupId);
        var createdDirectories = new List<string>();
        var createdFiles = new List<string>();
        try
        {
            var index = 0;
            CreateDirectory(paths.ProductRoot, UpdateDirectoryRole.ProductRoot, createdDirectories, index++, failDirectoryCreation, failAclApplication);
            CreateDirectory(paths.UpdatesRoot, UpdateDirectoryRole.UpdatesRoot, createdDirectories, index++, failDirectoryCreation, failAclApplication);
            CreateMutableFixture(paths.JournalLockFile, createdFiles);
            CreateMutableFixture(paths.OwnerLockFile, createdFiles);
            CreateDirectory(paths.TransactionsRoot, UpdateDirectoryRole.TransactionsRoot, createdDirectories, index++, failDirectoryCreation, failAclApplication);
            CreateDirectory(paths.TransactionRoot, UpdateDirectoryRole.TransactionDirectory, createdDirectories, index++, failDirectoryCreation, failAclApplication);
            CreateDirectory(paths.PrivateCandidateRoot, UpdateDirectoryRole.PrivateCandidateDirectory, createdDirectories, index++, failDirectoryCreation, failAclApplication);
            CreateDirectory(paths.BackupsRoot, UpdateDirectoryRole.BackupsRoot, createdDirectories, index++, failDirectoryCreation, failAclApplication);
            CreateDirectory(paths.FixedBackupRoot, UpdateDirectoryRole.FixedBackupDirectory, createdDirectories, index++, failDirectoryCreation, failAclApplication);
            CreateDirectory(paths.ReleasePolicyRoot, UpdateDirectoryRole.ReleasePolicyRoot, createdDirectories, index, failDirectoryCreation, failAclApplication);
            CreateMutableFixture(paths.JournalFile, createdFiles);
            CreateMutableFixture(paths.PolicyFile, createdFiles);
            return paths;
        }
        catch
        {
            CleanupKnownEntries(createdFiles, createdDirectories);
            throw;
        }
    }

    internal void CleanupDisposableFixture(ProvisionedUpdateFilesystem paths)
    {
        if (!_isAdministrator()) throw new UnauthorizedAccessException("An enabled Administrator token is required.");
        if (!_disposableBoundary || !PathsEqual(paths.ProductRoot, _productRoot))
            throw new InvalidOperationException("Disposable cleanup boundary rejected.");
        CleanupKnownEntries([paths.JournalFile, paths.PolicyFile, paths.OwnerLockFile, paths.JournalLockFile],
            [paths.ProductRoot, paths.UpdatesRoot, paths.TransactionsRoot, paths.TransactionRoot,
             paths.PrivateCandidateRoot, paths.BackupsRoot, paths.FixedBackupRoot, paths.ReleasePolicyRoot]);
        if (Directory.Exists(_productRoot) || File.Exists(_productRoot))
            throw new IOException("Disposable update security fixture cleanup was incomplete.");
    }

    private static string ValidateDisposableRoot(string root)
    {
        if (string.IsNullOrWhiteSpace(root) || !Path.IsPathFullyQualified(root))
            throw new ArgumentException("Disposable product root must be fully qualified.", nameof(root));
        root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var programFiles = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
        if (!string.Equals(Path.GetDirectoryName(root), programFiles, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(root).StartsWith("Kestermere Security ACL Provision-", StringComparison.Ordinal))
            throw new ArgumentException("Disposable product root must be a dedicated Program Files test child.", nameof(root));
        if (PathsOverlap(root, FixedUpdatePaths.InstalledServiceRoot) || PathsOverlap(root, FixedUpdatePaths.UpdatesRoot) ||
            PathsOverlap(root, Path.Combine(FixedUpdatePaths.VantrelRoot, "ReleasePolicy")) ||
            PathsOverlap(root, Environment.CurrentDirectory))
            throw new ArgumentException("Disposable product root overlaps a protected location.", nameof(root));
        if (Directory.Exists(root) || File.Exists(root)) throw new IOException("Disposable product root already exists.");
        var parent = Directory.GetParent(root) ?? throw new IOException("Disposable product root parent is unavailable.");
        if (!parent.Exists) throw new IOException("Disposable product root parent is unavailable.");
        InspectAncestors(parent);
        return root;
    }

    private static void InspectAncestors(DirectoryInfo start)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var immediateParent = true;
        for (var current = start; current is not null; current = current.Parent)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Disposable product root reparse ancestor rejected.");
            var security = current.GetAccessControl(AccessControlSections.Access);
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow ||
                    rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly) ||
                    rule.IdentityReference is not SecurityIdentifier sid ||
                    (!sid.Equals(Users) && !sid.Equals(AuthenticatedUsers) && !sid.Equals(Everyone) &&
                     (identity.User is null || !sid.Equals(identity.User)))) continue;
                var unsafeRights = (immediateParent ? FileSystemRights.CreateDirectories : 0) | FileSystemRights.Delete |
                    FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
                if ((rule.FileSystemRights & unsafeRights) != 0)
                    throw new IOException("Disposable product root has a user-writable ancestor.");
            }
            immediateParent = false;
        }
    }

    private ProvisionedUpdateFilesystem Paths(string transactionId, string backupId)
    {
        var updates = Path.Combine(_productRoot, "Updates");
        var transactions = Path.Combine(updates, "Transactions");
        var transaction = Path.Combine(transactions, transactionId);
        var backups = Path.Combine(updates, "Backups");
        var releasePolicy = Path.Combine(_productRoot, "ReleasePolicy");
        return new(_productRoot, updates, transactions, transaction, Path.Combine(transaction, "candidate"), backups,
            Path.Combine(backups, backupId), releasePolicy, Path.Combine(updates, UpdateTransactionJournalStore.LockFileName), Path.Combine(updates, OfflineUpdateOwnershipLock.OwnerLockFileName), Path.Combine(transactions, UpdateTransactionJournalStore.JournalFileName),
            Path.Combine(releasePolicy, ReleasePolicyStore.PolicyFileName));
    }

    private static void CreateDirectory(string path, UpdateDirectoryRole role, ICollection<string> created, int index,
        Func<int, bool>? failDirectoryCreation, Func<int, bool>? failAclApplication)
    {
        if (Directory.Exists(path) || File.Exists(path)) throw new IOException("Required structural identity already exists.");
        if (failDirectoryCreation?.Invoke(index) == true) throw new IOException("Test-only directory creation failure.");
        Directory.CreateDirectory(path);
        created.Add(path);
        RejectReparse(path);
        if (failAclApplication?.Invoke(index) == true) throw new UnauthorizedAccessException("Test-only ACL application failure.");
        new DirectoryInfo(path).SetAccessControl(UpdateFilesystemSecurity.CreateDirectoryDescriptor(role));
        var validation = UpdateFilesystemSecurity.ValidateDirectoryOnDisk(role, new DirectoryInfo(path));
        if (!validation.IsMatch) throw new IOException("Provisioned directory descriptor verification failed: " + validation.Mismatch);
    }

    private static void CreateMutableFixture(string path, ICollection<string> created)
    {
        if (Directory.Exists(path) || File.Exists(path)) throw new IOException("Required mutable-file identity already exists.");
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            stream.Write("kestermere-update-security-fixture-v1"u8);
            stream.Flush(flushToDisk: true);
        }
        created.Add(path);
        RejectReparse(path);
        new FileInfo(path).SetAccessControl(UpdateFilesystemSecurity.CreateProvisionedMutableFileDescriptor());
        var validation = UpdateFilesystemSecurity.ValidateProvisionedMutableFileOnDisk(new FileInfo(path));
        if (!validation.IsMatch) throw new IOException("Provisioned mutable-file descriptor verification failed: " + validation.Mismatch);
    }

    private static void CleanupKnownEntries(IEnumerable<string> files, IEnumerable<string> directories)
    {
        foreach (var file in files.Reverse())
        {
            if (!File.Exists(file)) continue;
            RejectReparse(file);
            File.Delete(file);
        }
        foreach (var directory in directories.Reverse())
        {
            if (!Directory.Exists(directory)) continue;
            RejectReparse(directory);
            Directory.Delete(directory, recursive: false);
        }
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Provisioning reparse point rejected.");
    }

    private static bool HasEnabledAdministratorToken() => OperatingSystem.IsWindows() &&
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    private static bool PathsOverlap(string left, string right) => IsSameOrChild(left, right) || IsSameOrChild(right, left);
    private static bool IsSameOrChild(string path, string root)
    {
        path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return PathsEqual(path, root) || path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
    private static bool PathsEqual(string left, string right) => string.Equals(
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)), Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
        StringComparison.OrdinalIgnoreCase);
}
