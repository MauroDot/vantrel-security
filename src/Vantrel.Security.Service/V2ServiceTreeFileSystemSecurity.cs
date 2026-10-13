using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Service;

/// <summary>
/// Installed V2 Service-tree descriptors and retained-handle checks. Directories and files
/// grant LocalService only read/execute; they never grant it write, delete, or ACL control.
/// These descriptors are separate from private V2 artifacts and mutable ProgramData storage.
/// Callers must retain and recheck parent-directory bindings during copy or rename.
/// </summary>
internal static class V2ServiceTreeFileSystemSecurity
{
    private const int SeFileObject = 1;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const int MaximumSecurityDescriptorBytes = 64 * 1024;
    // Allow ACE construction adds Synchronize. Keep that exact semantic mask in validation.
    private const FileSystemRights RuntimeRead = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public uint Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryWithSecurity(string path, ref SecurityAttributes attributes);

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
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

    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier LocalService =
        new(WellKnownSidType.LocalServiceSid, null);

    internal static DirectorySecurity CreateDirectoryDescriptor()
    {
        var descriptor = new DirectorySecurity();
        descriptor.SetOwner(Administrators);
        descriptor.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        descriptor.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        descriptor.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        descriptor.AddAccessRule(new FileSystemAccessRule(LocalService, RuntimeRead,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        return descriptor;
    }

    internal static FileSecurity CreateFileDescriptor()
    {
        var descriptor = new FileSecurity();
        descriptor.SetOwner(Administrators);
        descriptor.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        descriptor.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl,
            AccessControlType.Allow));
        descriptor.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl,
            AccessControlType.Allow));
        descriptor.AddAccessRule(new FileSystemAccessRule(LocalService, RuntimeRead,
            AccessControlType.Allow));
        return descriptor;
    }

    /// <summary>
    /// Create one final directory with the protected descriptor at creation time. It fails if
    /// the leaf exists. The returned write/delete-denying handle belongs to the caller.
    /// Disabling ACL enforcement is an internal disposable-fixture seam only.
    /// </summary>
    internal static SafeFileHandle CreateNewDirectory(string path, bool enforceAcl = true)
    {
        RequireWindows();
        var expected = RequireCanonicalFullPath(path);
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
        if (!created) throw new IOException("Protected V2 Service tree create-new directory failed.");
        // A validation failure leaves the new directory as visible residue for the caller.
        return OpenValidatedDirectory(expected, enforceAcl);
    }

    /// <summary>
    /// Create one final file with its protected descriptor atomically. The returned stream
    /// and its SafeFileHandle remain owned by the caller through copy, flush and inspection.
    /// Disabling ACL enforcement is an internal disposable-fixture seam only.
    /// </summary>
    internal static FileStream CreateNewFile(string path, bool enforceAcl = true)
    {
        RequireWindows();
        var expected = RequireCanonicalFullPath(path);
        RequireNoReparseAncestors(expected);
        FileStream stream;
        try
        {
            stream = enforceAcl
                ? new FileInfo(expected).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                    FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough,
                    CreateFileDescriptor())
                : new FileStream(expected, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                    65536, FileOptions.Asynchronous | FileOptions.WriteThrough);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { throw new IOException("Protected V2 Service tree create-new file failed."); }
        try
        {
            RequireValidatedHandle(stream.SafeFileHandle, expected, directory: false, enforceAcl);
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    internal static UpdateDescriptorValidation ValidateDirectoryDescriptor(DirectorySecurity descriptor) =>
        ValidateDescriptor(descriptor, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);

    internal static UpdateDescriptorValidation ValidateFileDescriptor(FileSecurity descriptor) =>
        ValidateDescriptor(descriptor, InheritanceFlags.None);

    internal static void RequireDirectoryAcl(string path)
    {
        RequireWindows();
        using var handle = OpenValidatedDirectory(path, enforceAcl: false);
        RequireDirectoryAcl(handle);
    }

    internal static void RequireFileAcl(string path)
    {
        RequireWindows();
        using var handle = OpenValidatedFile(path, enforceAcl: false);
        RequireFileAcl(handle);
    }

    /// <summary>
    /// Return a caller-owned, write-and-delete-denying handle for an exact ordinary directory.
    /// The test seam disables only ACL checks for disposable normal-user fixtures; native path,
    /// reparse, stream, and identity checks remain mandatory. Production always passes true.
    /// </summary>
    internal static SafeFileHandle OpenValidatedDirectory(string path, bool enforceAcl = true) =>
        OpenValidated(path, directory: true, enforceAcl);

    /// <summary>
    /// Return a caller-owned, write-and-delete-denying handle for an exact ordinary file with
    /// one hard link and no named streams. Production always passes true for ACL enforcement.
    /// </summary>
    internal static SafeFileHandle OpenValidatedFile(string path, bool enforceAcl = true) =>
        OpenValidated(path, directory: false, enforceAcl);

    /// <summary>
    /// Recheck a caller-retained directory handle, including one opened for a guarded rename.
    /// A path check alone cannot authorize a move; callers must also compare the handle's
    /// volume/file identity with their earlier authenticated binding.
    /// </summary>
    internal static void RequireValidatedDirectoryHandle(SafeFileHandle handle, string expectedPath,
        bool enforceAcl = true)
    {
        RequireWindows();
        RequireValidatedHandle(handle, RequireCanonicalFullPath(expectedPath), directory: true, enforceAcl);
    }

    /// <summary>Recheck a retained ordinary file against its expected pathname and descriptor.</summary>
    internal static void RequireValidatedFileHandle(SafeFileHandle handle, string expectedPath,
        bool enforceAcl = true)
    {
        RequireWindows();
        RequireValidatedHandle(handle, RequireCanonicalFullPath(expectedPath), directory: false, enforceAcl);
    }

    private static SafeFileHandle OpenValidated(string path, bool directory, bool enforceAcl)
    {
        RequireWindows();
        var expected = RequireCanonicalFullPath(path);
        RequireNoReparseAncestors(expected);
        var handle = ComponentInspectionNative.OpenProtected(expected, directory);
        try
        {
            RequireValidatedHandle(handle, expected, directory, enforceAcl);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void RequireValidatedHandle(SafeFileHandle handle, string expected,
        bool directory, bool enforceAcl)
    {
        var before = ComponentInspectionNative.GetMetadata(handle);
        if (before.IsReparsePoint || before.IsDirectory != directory)
            throw new IOException("Protected V2 Service tree object type rejected.");
        RequireExpectedFinalPath(handle, expected);
        if (!ComponentInspectionNative.HasOnlyDefaultDataStream(handle, directory))
            throw new IOException("Protected V2 Service tree named data stream rejected.");
        if (!directory && ComponentInspectionNative.GetHardLinkCount(handle) != 1)
            throw new IOException("Protected V2 Service tree hard-link count rejected.");
        if (enforceAcl)
        {
            if (directory) RequireDirectoryAcl(handle);
            else RequireFileAcl(handle);
        }
        RequireNoReparseAncestors(expected);
        if (ComponentInspectionNative.GetMetadata(handle) != before)
            throw new IOException("Protected V2 Service tree identity changed.");
        RequireExpectedFinalPath(handle, expected);
        if (!ComponentInspectionNative.HasOnlyDefaultDataStream(handle, directory))
            throw new IOException("Protected V2 Service tree data streams changed.");
        if (!directory && ComponentInspectionNative.GetHardLinkCount(handle) != 1)
            throw new IOException("Protected V2 Service tree hard-link count changed.");
    }

    private static UpdateDescriptorValidation ValidateDescriptor(FileSystemSecurity descriptor,
        InheritanceFlags expectedInheritance)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (!descriptor.AreAccessRulesProtected)
            return UpdateDescriptorValidation.Reject("DACL inheritance is not protected.");
        if (descriptor.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            !owner.Equals(Administrators))
            return UpdateDescriptorValidation.Reject("Owner differs from the protected Service tree contract.");

        var rules = descriptor.GetAccessRules(includeExplicit: true, includeInherited: true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        if (rules.Length != 3 || rules.Any(static rule => rule.IsInherited))
            return UpdateDescriptorValidation.Reject("Protected Service tree access-rule count differs.");
        foreach (var (expectedSid, expectedRights) in new[]
        {
            (Administrators, FileSystemRights.FullControl),
            (System, FileSystemRights.FullControl),
            (LocalService, RuntimeRead)
        })
        {
            if (rules.Count(rule => rule.IdentityReference.Equals(expectedSid) &&
                    rule.AccessControlType == AccessControlType.Allow &&
                    rule.FileSystemRights == expectedRights &&
                    rule.InheritanceFlags == expectedInheritance &&
                    rule.PropagationFlags == PropagationFlags.None) != 1)
                return UpdateDescriptorValidation.Reject("Protected Service tree access rule differs.");
        }
        return UpdateDescriptorValidation.Match;
    }

    /// <summary>Validate the exact protected directory descriptor on a caller-retained handle.</summary>
    internal static void RequireDirectoryAcl(SafeFileHandle handle)
    {
        var descriptor = new DirectorySecurity();
        descriptor.SetSecurityDescriptorBinaryForm(ReadDescriptor(handle));
        var result = ValidateDirectoryDescriptor(descriptor);
        if (!result.IsMatch)
            throw new IOException("Protected V2 Service tree directory descriptor rejected: " + result.Mismatch);
    }

    /// <summary>Validate the exact protected file descriptor on a caller-retained handle.</summary>
    internal static void RequireFileAcl(SafeFileHandle handle)
    {
        var descriptor = new FileSecurity();
        descriptor.SetSecurityDescriptorBinaryForm(ReadDescriptor(handle));
        var result = ValidateFileDescriptor(descriptor);
        if (!result.IsMatch)
            throw new IOException("Protected V2 Service tree file descriptor rejected: " + result.Mismatch);
    }

    private static byte[] ReadDescriptor(SafeFileHandle handle)
    {
        var status = GetSecurityInfo(handle, SeFileObject,
            OwnerSecurityInformation | DaclSecurityInformation,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var native);
        if (status != 0 || native == IntPtr.Zero)
        {
            if (native != IntPtr.Zero) _ = LocalFree(native);
            throw new IOException("Protected V2 Service tree descriptor is unavailable.");
        }
        try
        {
            if (!IsValidSecurityDescriptor(native))
                throw new IOException("Protected V2 Service tree descriptor is malformed.");
            var length = GetSecurityDescriptorLength(native);
            if (length is < 20 or > MaximumSecurityDescriptorBytes)
                throw new IOException("Protected V2 Service tree descriptor length rejected.");
            var bytes = new byte[checked((int)length)];
            Marshal.Copy(native, bytes, 0, bytes.Length);
            return bytes;
        }
        finally
        {
            if (LocalFree(native) != IntPtr.Zero)
                throw new IOException("Protected V2 Service tree descriptor release failed.");
        }
    }


    private static string RequireCanonicalFullPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            path.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            path.StartsWith("\\\\.\\", StringComparison.Ordinal))
            throw new IOException("Protected V2 Service tree path rejected.");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!string.Equals(path, full, StringComparison.OrdinalIgnoreCase) ||
            full.AsSpan(Path.GetPathRoot(full)!.Length).Contains(':'))
            throw new IOException("Protected V2 Service tree path is noncanonical.");
        return full;
    }

    private static void RequireNoReparseAncestors(string path)
    {
        for (var directory = Directory.GetParent(path); directory is not null; directory = directory.Parent)
        {
            var attributes = File.GetAttributes(directory.FullName);
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                (attributes & FileAttributes.Directory) == 0)
                throw new IOException("Protected V2 Service tree ancestor rejected.");
        }
    }

    private static void RequireExpectedFinalPath(SafeFileHandle handle, string expected)
    {
        var final = Path.TrimEndingDirectorySeparator(Path.GetFullPath(ComponentInspectionNative.FinalPath(handle)));
        if (!string.Equals(final, expected, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Protected V2 Service tree final path rejected.");
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Protected V2 Service tree inspection requires Windows.");
    }
}
