using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>
/// V2-only NTFS checks. These checks establish the state of retained handles during a
/// validation call; they do not make a returned path immutable against the signing operator.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ServiceReleaseV2FileSystemSecurity
{
    private const uint ReadControl = 0x00020000;
    private const uint WriteDac = 0x00040000;
    private const uint WriteOwner = 0x00080000;
    private const uint ReadAttributes = 0x00000080;
    private const uint GenericRead = 0x80000000;
    private const uint ShareRead = 1;
    private const uint ShareWrite = 2;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const uint OwnerSecurityInformation = 1;
    private const uint DaclSecurityInformation = 4;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;
    private const uint PersistentAcls = 0x00000008;
    private const uint FileTypeDisk = 1;
    private const int FileStreamInfo = 7;
    private const int ErrorHandleEof = 38;
    private const int MaximumStreamInfoBytes = 64 * 1024;
    private const int MaximumSecurityDescriptorBytes = 64 * 1024;
    private const string Unsafe = "V2 Service filesystem boundary is unsafe.";

    internal static void CreateProtectedDirectory(string absolutePath)
    {
        var retainedParents = new List<BoundPath>();
        try
        {
            RequireCanonicalLocalPath(absolutePath);
            var parent = Path.GetDirectoryName(absolutePath);
            if (parent is null || !Directory.Exists(parent) || Path.Exists(absolutePath))
                throw new IOException(Unsafe);
            RetainAncestors(parent, retainedParents);
            var descriptor = NewSecurityDescriptor(directory: true);
            var bytes = descriptor.GetSecurityDescriptorBinaryForm();
            var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                var attributes = new SecurityAttributes
                {
                    Length = (uint)Marshal.SizeOf<SecurityAttributes>(),
                    SecurityDescriptor = pinned.AddrOfPinnedObject(),
                    InheritHandle = 0
                };
                // CreateDirectoryW has create-new semantics; unlike Directory.CreateDirectory,
                // it cannot silently adopt an attacker-supplied leaf.
                if (!CreateDirectory(absolutePath, ref attributes)) throw new IOException(Unsafe);
            }
            finally { pinned.Free(); }
            foreach (var entry in retainedParents) entry.RequireUnchanged();
            RequireProtectedDirectory(absolutePath);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or SystemException)
        { throw new IOException(Unsafe); }
        finally { for (var i = retainedParents.Count - 1; i >= 0; i--) retainedParents[i].Dispose(); }
    }

    internal static void ProtectFile(string absolutePath)
    {
        var retainedParents = new List<BoundPath>();
        try
        {
            RequireCanonicalLocalPath(absolutePath);
            RetainAncestors(Path.GetDirectoryName(absolutePath)!, retainedParents);
            using var binding = OpenBound(absolutePath, directory: false,
                forSecurityUpdate: true);
            ProtectFile(binding.Handle);
            binding.RequireUnchanged();
            foreach (var entry in retainedParents) entry.RequireUnchanged();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or SystemException)
        { throw new IOException(Unsafe); }
        finally { for (var i = retainedParents.Count - 1; i >= 0; i--) retainedParents[i].Dispose(); }
    }

    /// <summary>
    /// Applies the v2 ACL directly to a create-new destination handle. The caller must open
    /// it with READ_CONTROL, WRITE_DAC and WRITE_OWNER and retain its identity/path binding.
    /// </summary>
    internal static void ProtectFile(SafeFileHandle retainedFileHandle)
    {
        try
        {
            if (retainedFileHandle is null || retainedFileHandle.IsInvalid || retainedFileHandle.IsClosed)
                throw new IOException(Unsafe);
            var descriptor = NewSecurityDescriptor(directory: false);
            var bytes = descriptor.GetSecurityDescriptorBinaryForm();
            var ownerOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4, 4));
            var daclOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16, 4));
            if (ownerOffset < 20 || daclOffset < 20 ||
                ownerOffset >= bytes.Length || daclOffset >= bytes.Length)
                throw new IOException(Unsafe);
            var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                var owner = IntPtr.Add(pinned.AddrOfPinnedObject(), ownerOffset);
                var dacl = IntPtr.Add(pinned.AddrOfPinnedObject(), daclOffset);
                if (SetSecurityInfo(retainedFileHandle, 1, OwnerSecurityInformation |
                    DaclSecurityInformation | ProtectedDaclSecurityInformation,
                    owner, IntPtr.Zero, dacl, IntPtr.Zero) != 0)
                    throw new IOException(Unsafe);
            }
            finally { pinned.Free(); }
            RequireProtectedAcl(retainedFileHandle, directory: false);
            RequireNoNamedStreams(retainedFileHandle);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or SystemException)
        { throw new IOException(Unsafe); }
    }

    internal static void RequireProtectedDirectory(string absolutePath)
    {
        try
        {
            RequireCanonicalLocalPath(absolutePath);
            using var binding = OpenBound(absolutePath, directory: true);
            RequireProtectedAcl(binding.Handle, directory: true);
            RequireNoNamedStreams(binding.Handle, directory: true);
            binding.RequireUnchanged();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or SystemException)
        { throw new IOException(Unsafe); }
    }

    internal static void RequireProtectedFile(string absolutePath)
    {
        try
        {
            RequireCanonicalLocalPath(absolutePath);
            using var binding = OpenBound(absolutePath, directory: false);
            RequireProtectedAcl(binding.Handle, directory: false);
            RequireNoNamedStreams(binding.Handle);
            binding.RequireUnchanged();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or SystemException)
        { throw new IOException(Unsafe); }
    }

    /// <summary>
    /// Reads a bounded protected file through the same retained, write/delete-denying handle
    /// whose ACL, ADS, final path, and identity are checked on both sides of the read.
    /// </summary>
    internal static byte[] ReadProtectedFileBytes(string absolutePath, int maximumBytes)
    {
        var ancestors = new List<BoundPath>();
        try
        {
            if (maximumBytes <= 0 || maximumBytes > 16 * 1024 * 1024)
                throw new IOException(Unsafe);
            RequireCanonicalLocalPath(absolutePath);
            RetainAncestors(Path.GetDirectoryName(absolutePath)!, ancestors);
            using var binding = OpenBound(absolutePath, directory: false);
            RequireProtectedHandle(binding.Handle, directory: false);
            var length = RandomAccess.GetLength(binding.Handle);
            if (length <= 0 || length > maximumBytes) throw new IOException(Unsafe);
            var bytes = new byte[checked((int)length)];
            var offset = 0;
            while (offset < bytes.Length)
            {
                var count = RandomAccess.Read(binding.Handle, bytes.AsSpan(offset), offset);
                if (count <= 0) throw new IOException(Unsafe);
                offset += count;
            }
            if (RandomAccess.GetLength(binding.Handle) != length)
                throw new IOException(Unsafe);
            RequireProtectedHandle(binding.Handle, directory: false);
            binding.RequireUnchanged();
            foreach (var ancestor in ancestors) ancestor.RequireUnchanged();
            return bytes;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or SystemException)
        { throw new IOException(Unsafe); }
        finally { for (var i = ancestors.Count - 1; i >= 0; i--) ancestors[i].Dispose(); }
    }

    /// <summary>Hashes a bounded protected file through its retained identity-bound handle.</summary>
    internal static string HashProtectedFile(string absolutePath, long maximumBytes)
    {
        var ancestors = new List<BoundPath>();
        try
        {
            if (maximumBytes <= 0 || maximumBytes > 1024L * 1024 * 1024)
                throw new IOException(Unsafe);
            RequireCanonicalLocalPath(absolutePath);
            RetainAncestors(Path.GetDirectoryName(absolutePath)!, ancestors);
            using var binding = OpenBound(absolutePath, directory: false);
            RequireProtectedHandle(binding.Handle, directory: false);
            var length = RandomAccess.GetLength(binding.Handle);
            if (length < 0 || length > maximumBytes) throw new IOException(Unsafe);
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[64 * 1024];
            long offset = 0;
            while (offset < length)
            {
                var requested = (int)Math.Min(buffer.Length, length - offset);
                var count = RandomAccess.Read(binding.Handle, buffer.AsSpan(0, requested), offset);
                if (count <= 0) throw new IOException(Unsafe);
                sha.AppendData(buffer.AsSpan(0, count));
                offset += count;
            }
            if (RandomAccess.GetLength(binding.Handle) != length)
                throw new IOException(Unsafe);
            RequireProtectedHandle(binding.Handle, directory: false);
            binding.RequireUnchanged();
            foreach (var ancestor in ancestors) ancestor.RequireUnchanged();
            return Convert.ToHexString(sha.GetHashAndReset());
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or SystemException)
        { throw new IOException(Unsafe); }
        finally { for (var i = ancestors.Count - 1; i >= 0; i--) ancestors[i].Dispose(); }
    }

    /// <summary>
    /// Checks a caller-retained handle without reopening its pathname. The caller remains
    /// responsible for canonical final-path, parent identity and SHA-256 binding.
    /// </summary>
    internal static void RequireProtectedHandle(SafeFileHandle retainedHandle, bool directory)
    {
        try
        {
            if (retainedHandle is null || retainedHandle.IsClosed || retainedHandle.IsInvalid ||
                !GetFileInformationByHandle(retainedHandle, out var info) ||
                GetFileType(retainedHandle) != FileTypeDisk ||
                ((info.Attributes & (uint)FileAttributes.Directory) != 0) != directory ||
                (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
                (!directory && info.LinkCount != 1))
                throw new IOException(Unsafe);
            RequireProtectedAcl(retainedHandle, directory);
            RequireNoNamedStreams(retainedHandle, directory);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or SystemException)
        { throw new IOException(Unsafe); }
    }

    internal static void RequireProtectedTree(string root, IReadOnlyList<TrustedManifestV2File> files)
    {
        try
        {
            if (files is null || files.Count == 0) throw new IOException(Unsafe);
            RequireCanonicalLocalPath(root);
            var directories = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { root };
            foreach (var file in files)
            {
                // Core's v2 codec is the canonical path and collision authority.
                _ = TrustedManifestV2Codec.CreateCanonicalPayload("0.0.0", 1, [file]);
                var parts = file.Path.Split('/');
                var directory = root;
                for (var i = 0; i < parts.Length - 1; i++)
                {
                    directory = Path.Combine(directory, parts[i]);
                    directories.Add(directory);
                }
            }
            foreach (var directory in directories) RequireProtectedDirectory(directory);
            foreach (var file in files)
                RequireProtectedFile(Path.Combine(root, file.Path.Replace('/', Path.DirectorySeparatorChar)));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or SystemException)
        { throw new IOException(Unsafe); }
    }

    /// <summary>
    /// Rejects every named NTFS stream through the same already-open file handle used for
    /// copying or hashing. Buffer exhaustion and unsupported filesystem semantics fail closed.
    /// </summary>
    internal static void RequireNoNamedStreams(SafeFileHandle retainedFileHandle, bool directory = false)
    {
        var buffer = Marshal.AllocHGlobal(MaximumStreamInfoBytes);
        try
        {
            if (retainedFileHandle is null || retainedFileHandle.IsInvalid || retainedFileHandle.IsClosed)
                throw new IOException(Unsafe);
            if (!GetFileInformationByHandleEx(retainedFileHandle, FileStreamInfo, buffer,
                MaximumStreamInfoBytes))
            {
                // Microsoft documents ERROR_HANDLE_EOF when a handle has no streams.
                // An ordinary directory may have none; a regular payload file must have
                // exactly its unnamed default data stream.
                if (directory && Marshal.GetLastPInvokeError() == ErrorHandleEof) return;
                throw new IOException(Unsafe);
            }
            // FILE_STREAM_INFO has four-byte offsets, two eight-byte lengths and UTF-16
            // StreamName beginning at byte 24. A second entry is always a named stream.
            var next = Marshal.ReadInt32(buffer, 0);
            var nameLength = Marshal.ReadInt32(buffer, 4);
            if (next != 0 || nameLength != 14 ||
                !string.Equals(Marshal.PtrToStringUni(IntPtr.Add(buffer, 24), 7),
                    "::$DATA", StringComparison.Ordinal) ||
                (!directory && Marshal.ReadInt64(buffer, 8) != RandomAccess.GetLength(retainedFileHandle)))
                throw new IOException(Unsafe);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or SystemException)
        { throw new IOException(Unsafe); }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static FileSystemSecurity NewSecurityDescriptor(bool directory)
    {
        FileSystemSecurity descriptor = directory ? new DirectorySecurity() : new FileSecurity();
        var operatorSid = WindowsIdentity.GetCurrent().User ?? throw new IOException(Unsafe);
        descriptor.SetOwner(operatorSid);
        descriptor.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        SecurityIdentifier[] identities =
        [
            operatorSid,
            new(WellKnownSidType.BuiltinAdministratorsSid, null),
            new(WellKnownSidType.LocalSystemSid, null)
        ];
        if (identities.Distinct().Count() != identities.Length) throw new IOException(Unsafe);
        foreach (var sid in identities)
            descriptor.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                directory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit :
                    InheritanceFlags.None,
                PropagationFlags.None, AccessControlType.Allow));
        return descriptor;
    }

    private static void RequireProtectedAcl(SafeFileHandle handle, bool directory)
    {
        IntPtr securityDescriptor = IntPtr.Zero;
        try
        {
            if (GetSecurityInfo(handle, 1, OwnerSecurityInformation | DaclSecurityInformation,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                out securityDescriptor) != 0 || securityDescriptor == IntPtr.Zero)
                throw new IOException(Unsafe);
            var length = GetSecurityDescriptorLength(securityDescriptor);
            if (length < 20 || length > MaximumSecurityDescriptorBytes) throw new IOException(Unsafe);
            var bytes = new byte[length];
            Marshal.Copy(securityDescriptor, bytes, 0, bytes.Length);
            var raw = new RawSecurityDescriptor(bytes, 0);
            var current = WindowsIdentity.GetCurrent().User ?? throw new IOException(Unsafe);
            if (raw.Owner is null || !raw.Owner.Equals(current) ||
                (raw.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
                raw.DiscretionaryAcl is not { Count: 3 } acl)
                throw new IOException(Unsafe);
            var expected = new HashSet<string>(StringComparer.Ordinal)
            {
                current.Value,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value
            };
            foreach (GenericAce entry in acl)
            {
                if (entry is not CommonAce ace || ace.AceQualifier != AceQualifier.AccessAllowed ||
                    ace.AccessMask != (int)FileSystemRights.FullControl ||
                    ace.SecurityIdentifier is null ||
                    ace.AceFlags != (directory ? AceFlags.ContainerInherit | AceFlags.ObjectInherit : AceFlags.None) ||
                    !expected.Remove(ace.SecurityIdentifier.Value))
                    throw new IOException(Unsafe);
            }
            if (expected.Count != 0) throw new IOException(Unsafe);
        }
        finally { if (securityDescriptor != IntPtr.Zero) _ = LocalFree(securityDescriptor); }
    }

    private static void RequireCanonicalLocalPath(string path)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) || Path.GetFullPath(path) != path ||
            path.Length < 3 || path[1] != ':' || path[2] != '\\' ||
            new DriveInfo(path[..3]).DriveType != DriveType.Fixed)
            throw new IOException(Unsafe);
        var drive = path[..3];
        if (!GetVolumeInformation(drive, null, 0, out _, out _, out var flags,
            null, 0) || (flags & PersistentAcls) == 0)
            throw new IOException(Unsafe);
    }

    private static void RetainAncestors(string path, List<BoundPath> retained)
    {
        var pending = new Stack<string>();
        for (var current = new DirectoryInfo(path); current is not null; current = current.Parent)
            pending.Push(current.FullName);
        while (pending.Count != 0)
            retained.Add(OpenBound(pending.Pop(), directory: true));
    }

    private sealed class BoundPath : IDisposable
    {
        internal SafeFileHandle Handle { get; }
        private readonly string _path;
        private readonly bool _directory;
        private readonly uint _volume;
        private readonly ulong _index;

        internal BoundPath(string path, bool directory, SafeFileHandle handle)
        {
            _path = path;
            _directory = directory;
            Handle = handle;
            (_volume, _index) = Inspect(handle, path, directory);
        }

        internal void RequireUnchanged()
        {
            if (Inspect(Handle, _path, _directory) != (_volume, _index))
                throw new IOException(Unsafe);
            using var other = CreateFile(_path, ReadControl | ReadAttributes,
                _directory ? ShareRead | ShareWrite : ShareRead,
                IntPtr.Zero, OpenExisting, OpenReparsePoint | (_directory ? BackupSemantics : 0), IntPtr.Zero);
            if (other.IsInvalid || Inspect(other, _path, _directory) != (_volume, _index))
                throw new IOException(Unsafe);
        }

        public void Dispose() => Handle.Dispose();
    }

    private static BoundPath OpenBound(string path, bool directory, bool forSecurityUpdate = false)
    {
        var parent = Path.GetDirectoryName(path);
        if (parent is not null && !new DirectoryInfo(parent).Exists)
            throw new IOException(Unsafe);
        var access = ReadControl | ReadAttributes | (directory ? 0 : GenericRead) |
            (forSecurityUpdate ? WriteDac | WriteOwner : 0);
        var handle = CreateFile(path, access,
            directory ? ShareRead | ShareWrite : ShareRead, IntPtr.Zero, OpenExisting,
            OpenReparsePoint | (directory ? BackupSemantics : 0), IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new IOException(Unsafe); }
        try { return new BoundPath(path, directory, handle); }
        catch { handle.Dispose(); throw; }
    }

    private static (uint Volume, ulong Index) Inspect(SafeFileHandle handle, string path, bool directory)
    {
        if (!GetFileInformationByHandle(handle, out var info) || GetFileType(handle) != FileTypeDisk ||
            ((info.Attributes & (uint)FileAttributes.Directory) != 0) != directory ||
            (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
            (!directory && info.LinkCount != 1))
            throw new IOException(Unsafe);
        var length = GetFinalPathNameByHandle(handle, null, 0, 0);
        if (length == 0 || length > 32768) throw new IOException(Unsafe);
        var buffer = new StringBuilder((int)length + 1);
        var written = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        var expected = path.Length == 3 && path[1] == ':' ? path : path.TrimEnd('\\');
        if (written == 0 || written >= buffer.Capacity ||
            !string.Equals(buffer.ToString(), "\\\\?\\" + expected,
                StringComparison.OrdinalIgnoreCase))
            throw new IOException(Unsafe);
        return (info.Volume, ((ulong)info.IndexHigh << 32) | info.IndexLow);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal uint Length;
        internal IntPtr SecurityDescriptor;
        internal int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfoNative
    {
        internal uint Attributes;
        private uint _creationLow, _creationHigh, _accessLow, _accessHigh, _writeLow, _writeHigh;
        internal uint Volume;
        private uint _sizeHigh, _sizeLow;
        internal uint LinkCount;
        internal uint IndexHigh, IndexLow;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string path, ref SecurityAttributes attributes);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfoNative info);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle handle);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,
        StringBuilder? path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass,
        IntPtr buffer, int bufferLength);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType,
        uint securityInformation, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl,
        out IntPtr securityDescriptor);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr allocation);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(SafeFileHandle handle, int objectType,
        uint securityInformation, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("kernel32.dll", EntryPoint = "GetVolumeInformationW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformation(string root, StringBuilder? volumeName,
        uint volumeNameSize, out uint serialNumber, out uint maximumComponentLength,
        out uint flags, StringBuilder? fileSystemName, uint fileSystemNameSize);
}
