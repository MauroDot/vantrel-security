using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Service;

/// <summary>
/// Dormant, shared admission/retirement boundary for both update generations. Future callers
/// must acquire OfflineUpdateOwnershipLease, then this lease, then the generation-specific
/// journal lock, then the policy lock where required. While the first two are held, both
/// journals can be inspected and one absent-to-present publication can be completed atomically
/// with respect to the other generation. No production update path acquires this lock yet.
/// A future installer/provisioner must create the fixed lock file with its exact descriptor;
/// acquisition never creates or repairs infrastructure.
/// </summary>
internal sealed class CrossGenerationUpdateLock
{
    internal const string LockFileName = ".offline-update-generation.lock";
    private const string DisposablePrefix = "vantrel-cross-generation-";
    private static readonly TimeSpan ProductionWait = TimeSpan.FromSeconds(30);
    private readonly string _updatesRoot;
    private readonly bool _enforceAcl;
    private readonly TimeSpan _maximumWait;

    internal CrossGenerationUpdateLock() : this(FixedUpdatePaths.UpdatesRoot, true, ProductionWait, production: true) { }

    // Disposable-root seam only. It cannot weaken ACL validation at the production path.
    internal CrossGenerationUpdateLock(string disposableUpdatesRoot, bool enforceAcl = false,
        TimeSpan? maximumWait = null) : this(disposableUpdatesRoot, enforceAcl,
        maximumWait ?? ProductionWait, production: false) { }

    private CrossGenerationUpdateLock(string updatesRoot, bool enforceAcl, TimeSpan maximumWait, bool production)
    {
        if (string.IsNullOrWhiteSpace(updatesRoot) || !Path.IsPathFullyQualified(updatesRoot))
            throw new ArgumentException("Updates root must be fully qualified.", nameof(updatesRoot));
        _updatesRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(updatesRoot));
        if (string.Equals(_updatesRoot, Path.GetPathRoot(_updatesRoot), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Updates root cannot be a volume root.", nameof(updatesRoot));
        if (production)
        {
            if (!PathsEqual(_updatesRoot, FixedUpdatePaths.UpdatesRoot) || !enforceAcl || maximumWait != ProductionWait)
                throw new IOException("Fixed production cross-generation lock configuration rejected.");
        }
        else if (!IsCanonicalDisposableUpdatesRoot(updatesRoot))
            throw new ArgumentException("Disposable lock root must be an isolated Temp fixture.", nameof(updatesRoot));
        if (maximumWait < TimeSpan.Zero || maximumWait > ProductionWait)
            throw new ArgumentOutOfRangeException(nameof(maximumWait));
        _enforceAcl = enforceAcl;
        _maximumWait = maximumWait;
    }

    internal Task<CrossGenerationUpdateLease> AcquireAsync(CancellationToken token) =>
        CrossGenerationUpdateLease.AcquireAsync(_updatesRoot, _enforceAcl, _maximumWait, token);

    internal static bool PathsEqual(string left, string right) => string.Equals(
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);

    internal static bool PathsOverlap(string left, string right)
    {
        left = Path.TrimEndingDirectorySeparator(Path.GetFullPath(left));
        right = Path.TrimEndingDirectorySeparator(Path.GetFullPath(right));
        return PathsEqual(left, right) || left.StartsWith(right + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase) || right.StartsWith(left + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);
    }

    internal static bool OverlapsProductionStorage(string root) =>
        PathsOverlap(root, FixedUpdatePaths.VantrelRoot) ||
        PathsOverlap(root, FixedUpdatePaths.UpdatesRoot) ||
        PathsOverlap(root, FixedUpdatePaths.InstalledServiceRoot) ||
        PathsOverlap(root, Path.GetDirectoryName(FixedUpdatePaths.InstalledServiceRoot)!);

    // Internal test seam: a canonical, GUID-named direct Temp child only. The physical
    // Temp handle rejects reparse/8.3 aliases before any test lock path can be opened.
    internal static bool IsCanonicalDisposableUpdatesRoot(string root)
    {
        if (string.IsNullOrEmpty(root) || !Path.IsPathFullyQualified(root) ||
            root.StartsWith(@"\\", StringComparison.Ordinal) || root.Contains('/') ||
            !string.Equals(root, Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase))
            return false;
        var temp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
        if (temp.StartsWith(@"\\", StringComparison.Ordinal) || temp.Contains('/') ||
            OverlapsProductionStorage(temp) || OverlapsProductionStorage(root) ||
            !string.Equals(Path.GetFileName(root), "Updates", StringComparison.Ordinal))
            return false;
        var fixture = Path.GetDirectoryName(root);
        if (fixture is null || !PathsEqual(Path.GetDirectoryName(fixture)!, temp)) return false;
        var label = Path.GetFileName(fixture);
        if (!label.StartsWith(DisposablePrefix, StringComparison.Ordinal)) return false;
        var suffix = label[DisposablePrefix.Length..];
        if (!Guid.TryParseExact(suffix, "N", out var id) ||
            !string.Equals(suffix, id.ToString("N"), StringComparison.Ordinal)) return false;
        using var tempHandle = ComponentInspectionNative.OpenProtected(temp, directory: true);
        CrossGenerationLockFileSystemSecurity.RequireDirectory(tempHandle, temp, role: null);
        return true;
    }
}

/// <summary>A non-forgeable in-assembly capability for the retained, exclusively opened file.</summary>
internal sealed class CrossGenerationUpdateLease : IDisposable
{
    private FileStream? _stream;
    private SafeFileHandle? _updatesHandle;
    private SafeFileHandle? _productHandle;
    private readonly string _updatesRoot;
    private readonly string _lockPath;
    private readonly ComponentInspectionNative.Metadata _updatesIdentity;
    private readonly ComponentInspectionNative.Metadata _productIdentity;
    private readonly ComponentInspectionNative.Metadata _lockIdentity;
    private readonly bool _enforceAcl;

    private CrossGenerationUpdateLease(FileStream stream, SafeFileHandle updatesHandle,
        SafeFileHandle productHandle, string updatesRoot, bool enforceAcl)
    {
        _stream = stream;
        _updatesHandle = updatesHandle;
        _productHandle = productHandle;
        _updatesRoot = updatesRoot;
        _lockPath = Path.Combine(updatesRoot, CrossGenerationUpdateLock.LockFileName);
        _updatesIdentity = ComponentInspectionNative.GetMetadata(updatesHandle);
        _productIdentity = ComponentInspectionNative.GetMetadata(productHandle);
        _lockIdentity = ComponentInspectionNative.GetMetadata(stream.SafeFileHandle);
        _enforceAcl = enforceAcl;
    }

    internal static async Task<CrossGenerationUpdateLease> AcquireAsync(string updatesRoot, bool enforceAcl,
        TimeSpan maximumWait, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (string.IsNullOrWhiteSpace(updatesRoot) || !Path.IsPathFullyQualified(updatesRoot) ||
            !string.Equals(updatesRoot, Path.TrimEndingDirectorySeparator(Path.GetFullPath(updatesRoot)),
                StringComparison.OrdinalIgnoreCase) ||
            (CrossGenerationUpdateLock.PathsEqual(updatesRoot, FixedUpdatePaths.UpdatesRoot)
                ? !enforceAcl || maximumWait != TimeSpan.FromSeconds(30)
                : !CrossGenerationUpdateLock.IsCanonicalDisposableUpdatesRoot(updatesRoot)) ||
            maximumWait < TimeSpan.Zero || maximumWait > TimeSpan.FromSeconds(30))
            throw new IOException("Cross-generation lease root rejected.");
        token.ThrowIfCancellationRequested();
        var productRoot = Path.GetDirectoryName(updatesRoot) ?? throw new IOException("Updates parent is unavailable.");
        var lockPath = Path.Combine(updatesRoot, CrossGenerationUpdateLock.LockFileName);
        var contentionTime = Stopwatch.StartNew();
        while (true)
        {
            token.ThrowIfCancellationRequested();
            SafeFileHandle? product = null;
            SafeFileHandle? updates = null;
            FileStream? stream = null;
            try
            {
                // Retain both parent handles, then bind them with final-path, identity,
                // reparse, and descriptor rechecks before granting the lease.
                CrossGenerationLockFileSystemSecurity.RequireNoReparseAncestors(productRoot);
                product = ComponentInspectionNative.OpenProtected(productRoot, directory: true);
                CrossGenerationLockFileSystemSecurity.RequireDirectory(product, productRoot,
                    enforceAcl ? UpdateDirectoryRole.ProductRoot : null);
                updates = ComponentInspectionNative.OpenProtected(updatesRoot, directory: true);
                CrossGenerationLockFileSystemSecurity.RequireDirectory(updates, updatesRoot,
                    enforceAcl ? UpdateDirectoryRole.UpdatesRoot : null);
                var attributes = File.GetAttributes(lockPath); // Missing is an infrastructure failure.
                if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory | FileAttributes.Device)) != 0)
                    throw new IOException("Cross-generation lock is not an ordinary file.");
                stream = new FileStream(lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None,
                    1, FileOptions.WriteThrough);
                CrossGenerationLockFileSystemSecurity.RequireLockFile(stream.SafeFileHandle, lockPath, enforceAcl);
                CrossGenerationLockFileSystemSecurity.RequireDirectory(updates, updatesRoot,
                    enforceAcl ? UpdateDirectoryRole.UpdatesRoot : null);
                CrossGenerationLockFileSystemSecurity.RequireDirectory(product, productRoot,
                    enforceAcl ? UpdateDirectoryRole.ProductRoot : null);
                var lease = new CrossGenerationUpdateLease(stream, updates, product, updatesRoot, enforceAcl);
                stream = null; updates = null; product = null;
                return lease;
            }
            catch (IOException error) when (IsSharingViolation(error))
            {
                if (contentionTime.Elapsed >= maximumWait)
                    throw new TimeoutException("Cross-generation update lock contention timed out.", error);
            }
            finally
            {
                stream?.Dispose();
                updates?.Dispose();
                product?.Dispose();
            }
            await Task.Delay(TimeSpan.FromMilliseconds(50), token);
        }
    }

    internal void RequireHeldFor(string updatesRoot)
    {
        var stream = Volatile.Read(ref _stream);
        var updates = Volatile.Read(ref _updatesHandle);
        var product = Volatile.Read(ref _productHandle);
        if (stream is null || updates is null || product is null ||
            !string.Equals(_updatesRoot, Path.TrimEndingDirectorySeparator(Path.GetFullPath(updatesRoot)),
                StringComparison.OrdinalIgnoreCase))
            throw new IOException("Cross-generation update lease is not held for this Updates root.");
        try
        {
            CrossGenerationLockFileSystemSecurity.RequireLockFile(stream.SafeFileHandle, _lockPath, _enforceAcl);
            CrossGenerationLockFileSystemSecurity.RequireDirectory(updates, _updatesRoot,
                _enforceAcl ? UpdateDirectoryRole.UpdatesRoot : null);
            CrossGenerationLockFileSystemSecurity.RequireDirectory(product, Path.GetDirectoryName(_updatesRoot)!,
                _enforceAcl ? UpdateDirectoryRole.ProductRoot : null);
            if (ComponentInspectionNative.GetMetadata(stream.SafeFileHandle) != _lockIdentity ||
                ComponentInspectionNative.GetMetadata(updates) != _updatesIdentity ||
                ComponentInspectionNative.GetMetadata(product) != _productIdentity)
                throw new IOException("Cross-generation lease object identity changed.");
        }
        catch (ObjectDisposedException error)
        { throw new IOException("Cross-generation update lease is no longer held.", error); }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _stream, null)?.Dispose();
        Interlocked.Exchange(ref _updatesHandle, null)?.Dispose();
        Interlocked.Exchange(ref _productHandle, null)?.Dispose();
    }

    private static bool IsSharingViolation(IOException error) =>
        unchecked((uint)error.HResult) is 0x80070020 or 0x80070021;
}

/// <summary>Exact, Administrator/SYSTEM-only descriptor and handle-bound lock validation.</summary>
internal static class CrossGenerationLockFileSystemSecurity
{
    private const int SeFileObject = 1;
    private const uint OwnerSecurityInformation = 1;
    private const uint DaclSecurityInformation = 4;
    private const int MaximumDescriptorBytes = 64 * 1024;
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr securityDescriptor);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSecurityDescriptor(IntPtr descriptor);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    internal static FileSecurity CreateLockDescriptor()
    {
        var descriptor = new FileSecurity();
        descriptor.SetOwner(Administrators);
        descriptor.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        descriptor.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, AccessControlType.Allow));
        descriptor.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
        return descriptor;
    }

    internal static UpdateDescriptorValidation ValidateLockDescriptor(FileSecurity descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (!descriptor.AreAccessRulesProtected ||
            descriptor.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            !owner.Equals(Administrators))
            return UpdateDescriptorValidation.Reject("Cross-generation lock owner or DACL protection differs.");
        var rules = descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        if (rules.Length != 2 || rules.Any(rule => rule.IsInherited))
            return UpdateDescriptorValidation.Reject("Cross-generation lock ACE count or inheritance differs.");
        foreach (var sid in new[] { Administrators, System })
            if (rules.Count(rule => rule.IdentityReference.Equals(sid) &&
                    rule.AccessControlType == AccessControlType.Allow &&
                    rule.FileSystemRights == FileSystemRights.FullControl &&
                    rule.InheritanceFlags == InheritanceFlags.None &&
                    rule.PropagationFlags == PropagationFlags.None) != 1)
                return UpdateDescriptorValidation.Reject("Cross-generation lock ACE differs.");
        return UpdateDescriptorValidation.Match;
    }

    internal static void RequireDirectory(SafeFileHandle handle, string expected, UpdateDirectoryRole? role)
    {
        RequireObject(handle, expected, directory: true);
        if (role is not null)
        {
            var descriptor = new DirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(ReadDescriptor(handle));
            var result = UpdateFilesystemSecurity.ValidateDirectoryDescriptor(role.Value, descriptor);
            if (!result.IsMatch) throw new IOException("Cross-generation lock parent ACL rejected: " + result.Mismatch);
        }
    }

    internal static void RequireLockFile(SafeFileHandle handle, string expected, bool enforceAcl)
    {
        RequireObject(handle, expected, directory: false);
        if (enforceAcl)
        {
            var descriptor = new FileSecurity();
            descriptor.SetSecurityDescriptorBinaryForm(ReadDescriptor(handle));
            var result = ValidateLockDescriptor(descriptor);
            if (!result.IsMatch) throw new IOException("Cross-generation lock ACL rejected: " + result.Mismatch);
        }
    }

    private static void RequireObject(SafeFileHandle handle, string expected, bool directory)
    {
        var before = ComponentInspectionNative.GetMetadata(handle);
        if (before.IsReparsePoint || before.IsDirectory != directory)
            throw new IOException("Cross-generation lock object type rejected.");
        RequireFinalPath(handle, expected);
        if (!directory && (ComponentInspectionNative.GetHardLinkCount(handle) != 1 ||
                           !ComponentInspectionNative.HasOnlyDefaultDataStream(handle)))
            throw new IOException("Cross-generation lock hard link or named stream rejected.");
        RequireNoReparseAncestors(expected);
        if (ComponentInspectionNative.GetMetadata(handle) != before)
            throw new IOException("Cross-generation lock object identity changed.");
        RequireFinalPath(handle, expected);
        if (!directory && !ComponentInspectionNative.HasOnlyDefaultDataStream(handle))
            throw new IOException("Cross-generation lock data streams changed.");
    }

    private static void RequireFinalPath(SafeFileHandle handle, string expected)
    {
        var final = Path.TrimEndingDirectorySeparator(Path.GetFullPath(ComponentInspectionNative.FinalPath(handle)));
        if (!string.Equals(final, expected, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Cross-generation lock final path rejected.");
    }

    internal static void RequireNoReparseAncestors(string path)
    {
        for (var directory = Directory.GetParent(path); directory is not null; directory = directory.Parent)
        {
            var attributes = File.GetAttributes(directory.FullName);
            if ((attributes & FileAttributes.ReparsePoint) != 0 || (attributes & FileAttributes.Directory) == 0)
                throw new IOException("Cross-generation lock reparse ancestor rejected.");
        }
    }

    private static byte[] ReadDescriptor(SafeFileHandle handle)
    {
        var status = GetSecurityInfo(handle, SeFileObject, OwnerSecurityInformation | DaclSecurityInformation,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var native);
        if (status != 0 || native == IntPtr.Zero)
        {
            if (native != IntPtr.Zero) _ = LocalFree(native);
            throw new IOException("Cross-generation lock descriptor is unavailable.");
        }
        try
        {
            if (!IsValidSecurityDescriptor(native)) throw new IOException("Cross-generation lock descriptor is malformed.");
            var length = GetSecurityDescriptorLength(native);
            if (length is < 20 or > MaximumDescriptorBytes) throw new IOException("Cross-generation lock descriptor length rejected.");
            var bytes = new byte[checked((int)length)];
            Marshal.Copy(native, bytes, 0, bytes.Length);
            return bytes;
        }
        finally { _ = LocalFree(native); }
    }
}
