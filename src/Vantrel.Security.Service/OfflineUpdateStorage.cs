using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>Fixed update storage operations. Production uses only code-owned roots; root injection is internal and test-only.</summary>
internal sealed class OfflineUpdateStorage
{
    private readonly string _updatesRoot;
    private readonly string _installedRoot;
    private readonly string _stagedCandidate;
    private readonly string _transactionsRoot;
    private readonly string _backupsRoot;
    private readonly bool _applyAcls;
    private readonly IOfflineUpdateFileOperations _operations;

    internal OfflineUpdateStorage() : this(FixedUpdatePaths.UpdatesRoot, FixedUpdatePaths.InstalledServiceRoot, applyAcls: true, WindowsOfflineUpdateFileOperations.Instance, productionRoots: true) { }

    internal OfflineUpdateStorage(string updatesRoot, string installedRoot, bool applyAcls, IOfflineUpdateFileOperations operations) :
        this(updatesRoot, installedRoot, applyAcls, operations, productionRoots: false) { }

    private OfflineUpdateStorage(string updatesRoot, string installedRoot, bool applyAcls, IOfflineUpdateFileOperations operations, bool productionRoots)
    {
        _operations = operations ?? throw new ArgumentNullException(nameof(operations));
        _updatesRoot = ValidateRoot(updatesRoot, nameof(updatesRoot));
        _installedRoot = ValidateRoot(installedRoot, nameof(installedRoot));
        if (productionRoots)
        {
            if (!PathsEqual(_updatesRoot, FixedUpdatePaths.UpdatesRoot) || !PathsEqual(_installedRoot, FixedUpdatePaths.InstalledServiceRoot))
                throw new IOException("Fixed production update roots rejected.");
        }
        else
        {
            RejectProtectedProductionOverlap(_updatesRoot);
            RejectProtectedProductionOverlap(_installedRoot);
            if (PathsOverlap(_updatesRoot, _installedRoot)) throw new ArgumentException("Disposable update roots must be distinct.");
        }
        _stagedCandidate = Path.Combine(_updatesRoot, "Staged", "candidate");
        _transactionsRoot = Path.Combine(_updatesRoot, "Transactions");
        _backupsRoot = Path.Combine(_updatesRoot, "Backups");
        _applyAcls = applyAcls;
    }
    internal string StagedCandidate => _stagedCandidate;
    internal string PrivateCandidate(string transactionId) => Child(_transactionsRoot, transactionId, "candidate");
    internal string Backup(string backupId) => Child(_backupsRoot, backupId);

    internal async Task CopyStagedToPrivateAsync(string transactionId, CancellationToken token)
    {
        EnsureRoot(_updatesRoot, false); EnsureRoot(_transactionsRoot, true);
        await CopyExactReleaseAsync(_stagedCandidate, PrivateCandidate(transactionId), token, _applyAcls, allowLocalService: false, _operations);
    }

    internal async Task CopyInstalledToBackupAsync(string backupId, CancellationToken token)
    {
        EnsureRoot(_updatesRoot, false); EnsureRoot(_backupsRoot, false);
        await CopyExactReleaseAsync(_installedRoot, Backup(backupId), token, _applyAcls, allowLocalService: false, _operations);
    }

    // Internal test-only fault callback; production paths always pass null.
    internal static Task CopyExactReleaseForTestAsync(string source, string destination, Func<int, bool>? failBeforeCopy, CancellationToken token) =>
        CopyExactReleaseAsync(source, destination, token, applyAcls: false, allowLocalService: false, WindowsOfflineUpdateFileOperations.Instance, fault: failBeforeCopy);

    private static async Task CopyExactReleaseAsync(string source, string destination, CancellationToken token, bool applyAcls, bool allowLocalService, IOfflineUpdateFileOperations operations, Func<int, bool>? fault = null)
    {
        OfflineReleaseVerifier.ValidateExactSet(source);
        source = Path.GetFullPath(source); destination = Path.GetFullPath(destination);
        if (Directory.Exists(destination)) throw new IOException("Fixed update destination already exists.");
        EnsureContained(Path.GetDirectoryName(destination)!, destination);
        Directory.CreateDirectory(destination); RejectReparseAncestors(destination);
        if (applyAcls) operations.ApplyProtectedDirectoryAcl(destination, allowLocalService);
        try
        {
            var index = 0;
            foreach (var name in FixedServiceReleaseFiles.AllNames)
            {
                token.ThrowIfCancellationRequested();
                if (fault?.Invoke(index++) == true) throw new IOException("Test-only fixed copy fault.");
                var from = Path.Combine(source, name); var to = Path.Combine(destination, name);
                EnsureContained(source, from); EnsureContained(destination, to); RejectReparseAncestors(from);
                await using var input = new FileStream(from, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
                await using var output = new FileStream(to, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough);
                await operations.CopyFixedFileContentsAsync(input, output, token);
                await operations.FlushFixedFileToDiskAsync(output, token);
                RejectReparseAncestors(to); if (applyAcls) operations.ApplyProtectedFileAcl(to, allowLocalService);
            }
            OfflineReleaseVerifier.ValidateExactSet(destination);
        }
        catch
        {
            DeletePartialFixedRelease(destination);
            throw;
        }
    }

    private void EnsureRoot(string path, bool allowLocalService)
    {
        if (!Directory.Exists(path)) _operations.CreateFixedDirectory(path);
        if ((_operations.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Release reparse point rejected.");
        RejectReparseAncestors(path);
        if (_applyAcls) _operations.ApplyProtectedDirectoryAcl(path, allowLocalService);
    }

    private static void DeletePartialFixedRelease(string destination)
    {
        if (!Directory.Exists(destination)) return;
        RejectReparseAncestors(destination);
        var expected = new HashSet<string>(FixedServiceReleaseFiles.AllNames, StringComparer.Ordinal);
        foreach (var entry in Directory.EnumerateFileSystemEntries(destination))
        {
            RejectReparseAncestors(entry);
            if (!File.Exists(entry) || !expected.Contains(Path.GetFileName(entry)))
                throw new IOException("Unsafe fixed update cleanup rejected.");
            File.Delete(entry);
        }
        Directory.Delete(destination, recursive: false);
    }

    private static string ValidateRoot(string path, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Fixed disposable root is required.", parameterName);
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Fixed disposable root must be fully qualified.", parameterName);
        try
        {
            var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            if (string.IsNullOrEmpty(fullPath) || PathsEqual(fullPath, Path.GetPathRoot(fullPath)!))
                throw new ArgumentException("Fixed disposable root is invalid.", parameterName);
            RejectExistingReparsePath(fullPath);
            return fullPath;
        }
        catch (ArgumentException) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new IOException("Fixed disposable root inspection failed.", exception);
        }
    }

    private static void RejectProtectedProductionOverlap(string path)
    {
        var policyRoot = Path.Combine(FixedUpdatePaths.VantrelRoot, "ReleasePolicy");
        if (PathsOverlap(path, FixedUpdatePaths.InstalledServiceRoot) ||
            PathsOverlap(path, FixedUpdatePaths.UpdatesRoot) ||
            PathsOverlap(path, policyRoot))
            throw new ArgumentException("Fixed disposable root overlaps a protected production root.");
    }

    private static void RejectExistingReparsePath(string path)
    {
        var current = path;
        while (!File.Exists(current) && !Directory.Exists(current))
        {
            var parent = Directory.GetParent(current);
            if (parent is null) throw new IOException("Fixed disposable root inspection failed.");
            current = parent.FullName;
        }
        for (; ; )
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Fixed disposable root reparse point rejected.");
            var parent = Directory.GetParent(current);
            if (parent is null) return;
            current = parent.FullName;
        }
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)), Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);

    private static bool PathsOverlap(string left, string right) =>
        IsSameOrContained(left, right) || IsSameOrContained(right, left);

    private static bool IsSameOrContained(string path, string root)
    {
        path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return PathsEqual(path, root) || path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
    private static string Child(string root, string id, params string[] tail)
    {
        if (!UpdateTransactionJournalCodec.IsId(id)) throw new ArgumentException("Fixed transaction identifier is invalid.", nameof(id));
        root = Path.GetFullPath(root); var path = Path.Combine([root, id, .. tail]); EnsureContained(root, path); return path;
    }
    private static void EnsureContained(string root, string path)
    {
        root = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        path = Path.GetFullPath(path);
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new IOException("Fixed update containment rejected.");
    }
    private static void RejectReparseAncestors(string path) => OfflineReleaseVerifier.RejectReparseAncestors(path);

}
