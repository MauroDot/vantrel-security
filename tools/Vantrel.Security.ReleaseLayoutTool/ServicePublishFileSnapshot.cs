using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>
/// A bounded snapshot of a controlled Service publish directory. Metadata bytes are copied
/// from the same retained file handles that supplied their inventory hashes.
/// </summary>
public sealed class ServicePublishSnapshot
{
    private readonly byte[] _depsBytes;
    private readonly byte[] _runtimeConfigBytes;

    internal ServicePublishSnapshot(IReadOnlyList<TrustedManifestV2File> files,
        byte[] depsBytes, byte[] runtimeConfigBytes)
    {
        Files = new ReadOnlyCollection<TrustedManifestV2File>(files.ToArray());
        _depsBytes = depsBytes.ToArray();
        _runtimeConfigBytes = runtimeConfigBytes.ToArray();
    }

    public IReadOnlyList<TrustedManifestV2File> Files { get; }
    public byte[] DepsBytes => _depsBytes.ToArray();
    public byte[] RuntimeConfigBytes => _runtimeConfigBytes.ToArray();
}

/// <summary>
/// Windows-only, handle-bound inspection of SDK Service publish output. This captures an
/// inventory; it does not authorize later use of the directory after its handles are closed.
/// </summary>
public static class ServicePublishFileSnapshot
{
    public const string DepsFileName = "Vantrel.Security.Service.deps.json";
    public const string RuntimeConfigFileName = "Vantrel.Security.Service.runtimeconfig.json";
    private const int MaximumDepsBytes = 16 * 1024 * 1024;
    private const int MaximumRuntimeConfigBytes = 1024 * 1024;
    private const long MaximumFileBytes = 1024L * 1024 * 1024;
    private const long MaximumPublishBytes = 4L * 1024 * 1024 * 1024;
    private const int MaximumDirectories = 512;
    private const uint GenericRead = 0x80000000, ReadAttributes = 0x80;
    private const uint ShareRead = 1, ShareReadWrite = 3, OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000, BackupSemantics = 0x02000000;
    private const uint FileTypeDisk = 1;
    private const string PlaceholderHash = "0000000000000000000000000000000000000000000000000000000000000000";

    public static ServicePublishSnapshot Capture(string root)
    {
        var fullRoot = RequireRoot(root);
        var retained = new List<BoundEntry>();
        try
        {
            // Open and retain each ancestor. OPEN_REPARSE_POINT makes the final component of
            // each open inspectable, and the final-path check rejects redirected ancestors.
            var ancestors = new Stack<string>();
            for (var current = new DirectoryInfo(fullRoot); current is not null; current = current.Parent)
                ancestors.Push(current.FullName);
            while (ancestors.Count != 0)
                retained.Add(BoundEntry.Open(ancestors.Pop(), expectDirectory: true));

            var publishRoot = retained[^1];
            var directories = new List<DirectoryListing> { new(publishRoot) };
            var files = new List<BoundEntry>();
            var pending = new Stack<DirectoryListing>();
            pending.Push(directories[0]);
            while (pending.Count != 0)
            {
                var directory = pending.Pop();
                var entries = Directory.EnumerateFileSystemEntries(directory.Entry.Path)
                    .OrderBy(Path.GetFileName, StringComparer.Ordinal).ToArray();
                if (entries.Length == 0 || entries.Length > TrustedManifestV2Codec.MaximumFiles + MaximumDirectories)
                    throw new IOException("Service publish directory is incomplete or oversized.");
                foreach (var entryPath in entries)
                {
                    var name = Path.GetFileName(entryPath);
                    if (string.IsNullOrEmpty(name) || !directory.Names.Add(name))
                        throw new IOException("Service publish directory contains colliding entries.");
                    directory.ExactNames.Add(name);
                    var relative = directory.Entry.RelativePath.Length == 0
                        ? name : directory.Entry.RelativePath + "/" + name;
                    var isDirectory = (File.GetAttributes(entryPath) & FileAttributes.Directory) != 0;
                    // A directory must be capable of containing at least one canonical file.
                    RequireCanonicalPath(isDirectory ? relative + "/x" : relative);
                    var child = BoundEntry.Open(entryPath, isDirectory, relative);
                    retained.Add(child);
                    if (isDirectory)
                    {
                        if (directories.Count >= MaximumDirectories)
                            throw new IOException("Service publish directory is oversized.");
                        var next = new DirectoryListing(child);
                        directories.Add(next);
                        pending.Push(next);
                    }
                    else
                    {
                        if (files.Count >= TrustedManifestV2Codec.MaximumFiles)
                            throw new IOException("Service publish directory is oversized.");
                        files.Add(child);
                    }
                }
            }

            files.Sort(static (left, right) => StringComparer.Ordinal.Compare(left.RelativePath, right.RelativePath));
            // The Core codec is the path, collision, ordering and manifest-size authority.
            _ = TrustedManifestV2Codec.CreateCanonicalPayload("0.0.0", 1,
                files.Select(file => new TrustedManifestV2File(file.RelativePath, PlaceholderHash)).ToArray());

            var inventory = new List<TrustedManifestV2File>(files.Count);
            byte[]? depsBytes = null, runtimeConfigBytes = null;
            long totalBytes = 0;
            foreach (var file in files)
            {
                file.RequireUnchanged();
                var length = RandomAccess.GetLength(file.Handle);
                if (length < 0 || length > MaximumFileBytes || length > MaximumPublishBytes - totalBytes)
                    throw new IOException("Service publish content is oversized.");
                totalBytes += length;
                string hash;
                if (file.RelativePath == DepsFileName)
                {
                    depsBytes = ReadBounded(file, MaximumDepsBytes);
                    hash = Convert.ToHexString(SHA256.HashData(depsBytes));
                }
                else if (file.RelativePath == RuntimeConfigFileName)
                {
                    runtimeConfigBytes = ReadBounded(file, MaximumRuntimeConfigBytes);
                    hash = Convert.ToHexString(SHA256.HashData(runtimeConfigBytes));
                }
                else
                    hash = Hash(file);
                inventory.Add(new(file.RelativePath, hash));
            }
            if (depsBytes is null || runtimeConfigBytes is null)
                throw new IOException("Service publish metadata is incomplete.");
            _ = TrustedManifestV2Codec.CreateCanonicalPayload("0.0.0", 1, inventory);

            // Keep every handle open until the complete directory shape and every file
            // identity have been checked again. A parent handle is evidence, not a rename lock.
            foreach (var directory in directories)
            {
                directory.Entry.RequireUnchanged();
                var currentNames = Directory.EnumerateFileSystemEntries(directory.Entry.Path)
                    .Select(Path.GetFileName).ToArray();
                if (currentNames.Length != directory.ExactNames.Count ||
                    !currentNames.ToHashSet(StringComparer.Ordinal).SetEquals(directory.ExactNames))
                    throw new IOException("Service publish directory changed during inspection.");
            }
            foreach (var entry in retained) entry.RequireUnchanged();
            for (var index = 0; index < files.Count; index++)
                if (!string.Equals(Hash(files[index]), inventory[index].Sha256, StringComparison.Ordinal))
                    throw new IOException("Service publish content changed during inspection.");
            return new ServicePublishSnapshot(inventory, depsBytes, runtimeConfigBytes);
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or
            CryptographicException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new IOException("Service publish directory is unsafe.");
        }
        finally
        {
            for (var index = retained.Count - 1; index >= 0; index--) retained[index].Dispose();
        }
    }

    private static string RequireRoot(string root)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(root) ||
                !Path.IsPathFullyQualified(root) || Path.GetFullPath(root) != root ||
                root.Length < 3 || root[1] != ':' || root[2] != '\\' ||
                new DriveInfo(root[..3]).DriveType != DriveType.Fixed)
                throw new IOException();
            return Path.TrimEndingDirectorySeparator(root);
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or NotSupportedException)
        {
            throw new IOException("Service publish directory is unavailable.");
        }
    }

    private static void RequireCanonicalPath(string path)
    {
        try
        {
            _ = TrustedManifestV2Codec.CreateCanonicalPayload("0.0.0", 1,
                [new TrustedManifestV2File(path, PlaceholderHash)]);
        }
        catch (ArgumentException) { throw new IOException("Service publish path is unsafe."); }
    }

    private static byte[] ReadBounded(BoundEntry file, int maximum)
    {
        var length = RandomAccess.GetLength(file.Handle);
        if (length <= 0 || length > maximum) throw new IOException("Service publish metadata is invalid.");
        var bytes = new byte[(int)length];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var count = RandomAccess.Read(file.Handle, bytes.AsSpan(offset), offset);
            if (count <= 0) throw new IOException("Service publish content changed.");
            offset += count;
        }
        if (RandomAccess.GetLength(file.Handle) != length) throw new IOException("Service publish content changed.");
        file.RequireUnchanged();
        return bytes;
    }

    private static string Hash(BoundEntry file)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var length = RandomAccess.GetLength(file.Handle);
        var buffer = new byte[65536];
        long offset = 0;
        while (offset < length)
        {
            var count = RandomAccess.Read(file.Handle,
                buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - offset)), offset);
            if (count <= 0) throw new IOException("Service publish content changed.");
            digest.AppendData(buffer.AsSpan(0, count));
            offset += count;
        }
        if (RandomAccess.GetLength(file.Handle) != length) throw new IOException("Service publish content changed.");
        file.RequireUnchanged();
        return Convert.ToHexString(digest.GetHashAndReset());
    }

    private sealed class DirectoryListing(BoundEntry entry)
    {
        internal BoundEntry Entry { get; } = entry;
        internal HashSet<string> Names { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal HashSet<string> ExactNames { get; } = new(StringComparer.Ordinal);
    }

    private sealed class BoundEntry : IDisposable
    {
        private readonly (uint Volume, ulong Index) _identity;
        private readonly string _finalPath;
        private readonly bool _isDirectory;
        internal string Path { get; }
        internal string RelativePath { get; }
        internal SafeFileHandle Handle { get; }

        private BoundEntry(string path, string relativePath, bool isDirectory, SafeFileHandle handle)
        {
            Path = path;
            RelativePath = relativePath;
            Handle = handle;
            _isDirectory = isDirectory;
            (_identity, _finalPath) = Inspect(handle, isDirectory);
            if (!string.Equals(_finalPath, ExpectedFinal(path), StringComparison.OrdinalIgnoreCase))
                throw new IOException("Service publish path is redirected.");
        }

        internal static BoundEntry Open(string path, bool expectDirectory, string relativePath = "")
        {
            var handle = CreateFile(path, expectDirectory ? ReadAttributes : GenericRead | ReadAttributes,
                expectDirectory ? ShareReadWrite : ShareRead, IntPtr.Zero, OpenExisting,
                OpenReparsePoint | (expectDirectory ? BackupSemantics : 0), IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); throw new IOException("Service publish entry is unavailable."); }
            try { return new BoundEntry(path, relativePath, expectDirectory, handle); }
            catch { handle.Dispose(); throw; }
        }

        internal void RequireUnchanged()
        {
            if (Handle.IsClosed || Inspect(Handle, _isDirectory) != (_identity, _finalPath))
                throw new IOException("Service publish entry changed.");
            using var current = CreateFile(Path, ReadAttributes,
                _isDirectory ? ShareReadWrite : ShareRead, IntPtr.Zero, OpenExisting,
                OpenReparsePoint | (_isDirectory ? BackupSemantics : 0), IntPtr.Zero);
            if (current.IsInvalid || Inspect(current, _isDirectory) != (_identity, _finalPath))
                throw new IOException("Service publish entry changed.");
        }

        public void Dispose() => Handle.Dispose();

        private static ((uint Volume, ulong Index) Identity, string FinalPath) Inspect(SafeFileHandle handle, bool isDirectory)
        {
            if (!GetFileInformationByHandle(handle, out var info) ||
                GetFileType(handle) != FileTypeDisk ||
                (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
                ((info.Attributes & (uint)FileAttributes.Directory) != 0) != isDirectory ||
                (!isDirectory && info.LinkCount != 1))
                throw new IOException("Service publish entry is unsafe.");
            var length = GetFinalPathNameByHandle(handle, null, 0, 0);
            if (length is 0 or > 32768) throw new IOException("Service publish path is unavailable.");
            var buffer = new StringBuilder((int)length + 1);
            var written = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
            if (written == 0 || written >= buffer.Capacity ||
                !buffer.ToString().StartsWith("\\\\?\\", StringComparison.Ordinal))
                throw new IOException("Service publish path is unavailable.");
            return ((info.Volume, ((ulong)info.IndexHigh << 32) | info.IndexLow), buffer.ToString());
        }

        private static string ExpectedFinal(string path)
        {
            var trimmed = path.TrimEnd(System.IO.Path.DirectorySeparatorChar);
            if (trimmed.Length == 2 && trimmed[1] == ':') trimmed += "\\";
            return "\\\\?\\" + trimmed;
        }
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

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfoNative info);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle handle);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,
        StringBuilder? path, uint length, uint flags);
}
