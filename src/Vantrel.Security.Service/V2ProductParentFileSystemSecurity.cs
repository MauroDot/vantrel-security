using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Service;

/// <summary>
/// Dormant descriptor and retained-handle validator for the installed product parent.
/// A future clean V2 installer must create this descriptor; update execution may only
/// validate it and must never repair it. No production caller acquires this handle yet.
/// </summary>
internal static class V2ProductParentFileSystemSecurity
{
    private const int SeFileObject = 1;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const int MaximumSecurityDescriptorBytes = 64 * 1024;
    private const string DisposablePrefix = "Vantrel.ParentAclTest.";
    private const FileSystemRights ReadAndExecute = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;
    private const InheritanceFlags ChildInheritance =
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier LocalService =
        new(WellKnownSidType.LocalServiceSid, null);
    private static readonly SecurityIdentifier Users =
        new(WellKnownSidType.BuiltinUsersSid, null);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public uint Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryWithSecurity(string path, ref SecurityAttributes attributes);

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryWithDefaultSecurity(string path, IntPtr attributes);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSecurityDescriptor(IntPtr securityDescriptor);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    // The production path is derived solely from the fixed installed Service root.
    internal static string ProductParentPath =>
        Path.GetDirectoryName(FixedUpdatePaths.InstalledServiceRoot)
        ?? throw new IOException("Fixed installed Service parent is unavailable.");

    internal static DirectorySecurity CreateDirectoryDescriptor()
    {
        var descriptor = new DirectorySecurity();
        descriptor.SetOwner(Administrators);
        descriptor.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        descriptor.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl,
            ChildInheritance, PropagationFlags.None, AccessControlType.Allow));
        descriptor.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl,
            ChildInheritance, PropagationFlags.None, AccessControlType.Allow));
        // LocalService needs to list/traverse this parent to reach protected Service. It has
        // no inherited parent ACE: Service supplies its own exact read/execute descriptor.
        descriptor.AddAccessRule(new FileSystemAccessRule(LocalService, ReadAndExecute,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        // Desktop and OfflineUpdateTool must remain launchable by ordinary users. New child
        // directories and files inherit RX; the protected Service DACL blocks that inheritance.
        descriptor.AddAccessRule(new FileSystemAccessRule(Users, ReadAndExecute,
            ChildInheritance, PropagationFlags.None, AccessControlType.Allow));
        return descriptor;
    }

    internal static UpdateDescriptorValidation ValidateDirectoryDescriptor(DirectorySecurity descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (!descriptor.AreAccessRulesProtected)
            return UpdateDescriptorValidation.Reject("Product-parent DACL inheritance is not protected.");
        if (descriptor.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            !owner.Equals(Administrators))
            return UpdateDescriptorValidation.Reject("Product-parent owner differs.");

        var rules = descriptor.GetAccessRules(includeExplicit: true, includeInherited: true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        if (rules.Length != 4 || rules.Any(static rule => rule.IsInherited))
            return UpdateDescriptorValidation.Reject("Product-parent ACE count or inheritance differs.");

        foreach (var (sid, rights, inheritance) in new[]
        {
            (Administrators, FileSystemRights.FullControl, ChildInheritance),
            (System, FileSystemRights.FullControl, ChildInheritance),
            (LocalService, ReadAndExecute, InheritanceFlags.None),
            (Users, ReadAndExecute, ChildInheritance)
        })
        {
            if (rules.Count(rule => rule.IdentityReference.Equals(sid) &&
                    rule.AccessControlType == AccessControlType.Allow &&
                    rule.FileSystemRights == rights &&
                    rule.InheritanceFlags == inheritance &&
                    rule.PropagationFlags == PropagationFlags.None) != 1)
                return UpdateDescriptorValidation.Reject("Product-parent ACE differs.");
        }
        return UpdateDescriptorValidation.Match;
    }

    /// <summary>Open only the fixed production parent, retaining its exact object binding.</summary>
    internal static SafeFileHandle OpenValidatedProductParent() =>
        OpenValidated(ProductParentPath, enforceAcl: true);

    /// <summary>Recheck the fixed parent while the caller retains its write/delete-denying handle.</summary>
    internal static void RequireValidatedProductParentHandle(SafeFileHandle handle) =>
        RequireValidatedHandle(handle, RequireCanonicalFullPath(ProductParentPath), enforceAcl: true);

    /// <summary>
    /// Test-only seam for a GUID-named direct child of Temp or Program Files. Production has
    /// no path parameter. Disabling ACL checks is for disposable normal-user path tests.
    /// </summary>
    internal static SafeFileHandle OpenValidatedDisposableDirectory(string path, bool enforceAcl = true) =>
        OpenValidated(RequireDisposablePath(path), enforceAcl);

    internal static void RequireValidatedDisposableHandle(SafeFileHandle handle, string path,
        bool enforceAcl = true) =>
        RequireValidatedHandle(handle, RequireDisposablePath(path), enforceAcl);

    /// <summary>Create a disposable fixture atomically with the parent descriptor.</summary>
    internal static SafeFileHandle CreateNewDisposableDirectory(string path, bool enforceAcl = true)
    {
        RequireWindows();
        var expected = RequireDisposablePath(path);
        RequireNoReparseAncestors(expected);
        bool created;
        if (enforceAcl)
        {
            var bytes = CreateDirectoryDescriptor().GetSecurityDescriptorBinaryForm();
            var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                var attributes = new SecurityAttributes
                {
                    Length = checked((uint)Marshal.SizeOf<SecurityAttributes>()),
                    SecurityDescriptor = pinned.AddrOfPinnedObject(),
                    InheritHandle = false
                };
                created = CreateDirectoryWithSecurity(expected, ref attributes);
            }
            finally { pinned.Free(); }
        }
        else created = CreateDirectoryWithDefaultSecurity(expected, IntPtr.Zero);
        if (!created) throw new IOException("Disposable product-parent create-new directory failed.");
        return OpenValidated(expected, enforceAcl);
    }

    internal static void RequireDirectoryAcl(SafeFileHandle handle)
    {
        RequireWindows();
        var descriptor = new DirectorySecurity();
        descriptor.SetSecurityDescriptorBinaryForm(ReadDescriptor(handle));
        var result = ValidateDirectoryDescriptor(descriptor);
        if (!result.IsMatch)
            throw new IOException("Product-parent descriptor rejected: " + result.Mismatch);
    }

    private static SafeFileHandle OpenValidated(string path, bool enforceAcl)
    {
        RequireWindows();
        var expected = RequireCanonicalFullPath(path);
        RequireNoReparseAncestors(expected);
        var handle = ComponentInspectionNative.OpenProtected(expected, directory: true);
        try
        {
            RequireValidatedHandle(handle, expected, enforceAcl);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void RequireValidatedHandle(SafeFileHandle handle, string expected, bool enforceAcl)
    {
        if (handle is null || handle.IsInvalid || handle.IsClosed)
            throw new IOException("Product-parent retained handle is unavailable.");
        var before = ComponentInspectionNative.GetMetadata(handle);
        if (before.IsReparsePoint || !before.IsDirectory)
            throw new IOException("Product-parent object type rejected.");
        RequireExpectedFinalPath(handle, expected);
        if (!ComponentInspectionNative.HasOnlyDefaultDataStream(handle, directory: true))
            throw new IOException("Product-parent named data stream rejected.");
        if (enforceAcl) RequireDirectoryAcl(handle);
        RequireNoReparseAncestors(expected);
        if (ComponentInspectionNative.GetMetadata(handle) != before)
            throw new IOException("Product-parent retained identity changed.");
        RequireExpectedFinalPath(handle, expected);
        if (!ComponentInspectionNative.HasOnlyDefaultDataStream(handle, directory: true))
            throw new IOException("Product-parent data streams changed.");
    }

    private static byte[] ReadDescriptor(SafeFileHandle handle)
    {
        var status = GetSecurityInfo(handle, SeFileObject,
            OwnerSecurityInformation | DaclSecurityInformation,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var native);
        if (status != 0 || native == IntPtr.Zero)
        {
            if (native != IntPtr.Zero) _ = LocalFree(native);
            throw new IOException("Product-parent descriptor is unavailable.");
        }
        try
        {
            if (!IsValidSecurityDescriptor(native))
                throw new IOException("Product-parent descriptor is malformed.");
            var length = GetSecurityDescriptorLength(native);
            if (length is < 20 or > MaximumSecurityDescriptorBytes)
                throw new IOException("Product-parent descriptor length rejected.");
            var bytes = new byte[checked((int)length)];
            Marshal.Copy(native, bytes, 0, bytes.Length);
            return bytes;
        }
        finally
        {
            if (LocalFree(native) != IntPtr.Zero)
                throw new IOException("Product-parent descriptor release failed.");
        }
    }

    private static string RequireDisposablePath(string path)
    {
        var full = RequireCanonicalFullPath(path);
        var leaf = Path.GetFileName(full);
        if (!leaf.StartsWith(DisposablePrefix, StringComparison.Ordinal) ||
            leaf.Length != DisposablePrefix.Length + 32 ||
            !leaf[DisposablePrefix.Length..].All(Uri.IsHexDigit))
            throw new IOException("Disposable product-parent leaf rejected.");
        var parent = Path.GetDirectoryName(full);
        if (!string.Equals(parent, Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath())),
                StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(parent, Path.TrimEndingDirectorySeparator(Path.GetFullPath(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles))),
                StringComparison.OrdinalIgnoreCase))
            throw new IOException("Disposable product-parent location rejected.");
        return full;
    }

    private static string RequireCanonicalFullPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            path.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            path.StartsWith("\\\\.\\", StringComparison.Ordinal))
            throw new IOException("Product-parent path rejected.");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!string.Equals(path, full, StringComparison.OrdinalIgnoreCase) ||
            full.AsSpan(Path.GetPathRoot(full)!.Length).Contains(':'))
            throw new IOException("Product-parent path is noncanonical.");
        return full;
    }

    private static void RequireNoReparseAncestors(string path)
    {
        for (var directory = Directory.GetParent(path); directory is not null; directory = directory.Parent)
        {
            var attributes = File.GetAttributes(directory.FullName);
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                (attributes & FileAttributes.Directory) == 0)
                throw new IOException("Product-parent ancestor rejected.");
        }
    }

    private static void RequireExpectedFinalPath(SafeFileHandle handle, string expected)
    {
        var final = Path.TrimEndingDirectorySeparator(Path.GetFullPath(ComponentInspectionNative.FinalPath(handle)));
        if (!string.Equals(final, expected, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Product-parent final path rejected.");
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Product-parent inspection requires Windows.");
    }
}
