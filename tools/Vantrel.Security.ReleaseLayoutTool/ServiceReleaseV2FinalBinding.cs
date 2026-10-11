using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

internal sealed record ServiceReleaseV2BoundFile(string RelativePath, string Sha256);

/// <summary>
/// Retains read-only, write/delete-denying file handles and non-delete-sharing directory
/// handles for the complete v2 output layout. A caller must keep this alive through record
/// publication and call Recheck immediately before publication. The source operator remains
/// trusted: directory handles do not promise to prevent every same-operator rename.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ServiceReleaseV2FinalBinding : IDisposable
{
    private const string Invalid = "V2 final release layout is unavailable or changed.";
    private const uint GenericRead = 0x80000000;
    private const uint ReadControl = 0x00020000;
    private const uint ReadAttributes = 0x00000080;
    private const uint ShareRead = 1;
    private const uint ShareWrite = 2;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const long MaximumFileBytes = 1024L * 1024 * 1024;
    private const long MaximumLayoutBytes = 4L * 1024 * 1024 * 1024;
    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    private readonly string _root;
    private readonly ServiceReleaseV2BoundFile[] _expected;
    private readonly List<BoundPath> _retained = [];
    private readonly Dictionary<string, BoundPath> _files = new(StringComparer.Ordinal);
    private readonly Dictionary<string, BoundPath> _directories = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<string>> _expectedChildren = new(StringComparer.Ordinal);
    private bool _disposed;

    private ServiceReleaseV2FinalBinding(string root, ServiceReleaseV2BoundFile[] expected)
    {
        _root = root;
        _expected = expected;
    }

    internal static ServiceReleaseV2FinalBinding Open(string layoutRoot,
        IReadOnlyList<ServiceReleaseV2BoundFile> expectedRootRelativeFiles)
    {
        ServiceReleaseV2FinalBinding? binding = null;
        try
        {
            var root = RequireCanonicalRoot(layoutRoot);
            var files = RequireCanonicalInventory(expectedRootRelativeFiles);
            binding = new(root, files);
            binding.OpenAll();
            binding.Recheck();
            return binding;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or
            InvalidDataException or CryptographicException)
        {
            binding?.Dispose();
            throw new IOException(Invalid);
        }
    }

    /// <summary>Borrowed handle; the caller must neither close nor write through it.</summary>
    internal SafeFileHandle GetHandle(string relativePath) => GetFile(relativePath).Handle;

    internal string Hash(string relativePath)
    {
        try { return HashBound(GetFile(relativePath)); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
        { throw new IOException(Invalid); }
    }

    internal byte[] ReadBounded(string relativePath, int maximumBytes)
    {
        try
        {
            if (maximumBytes < 1) throw new IOException(Invalid);
            var file = GetFile(relativePath);
            file.RequireUnchanged();
            var length = RandomAccess.GetLength(file.Handle);
            if (length < 0 || length > maximumBytes) throw new IOException(Invalid);
            var bytes = new byte[checked((int)length)];
            var offset = 0;
            while (offset < bytes.Length)
            {
                var read = RandomAccess.Read(file.Handle, bytes.AsSpan(offset), offset);
                if (read <= 0) throw new IOException(Invalid);
                offset += read;
            }
            file.RequireUnchanged();
            return bytes;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or
            OverflowException)
        { throw new IOException(Invalid); }
    }

    internal void Recheck()
    {
        try
        {
            ThrowIfDisposed();
            // Every ancestor stays bound by identity and final path, while protected ACL and
            // stream rules apply to the release layout root and all of its descendants.
            foreach (var path in _retained)
            {
                path.RequireUnchanged();
                if (path.InLayout)
                    ServiceReleaseV2FileSystemSecurity.RequireProtectedHandle(path.Handle,
                        path.IsDirectory);
            }
            foreach (var (directory, expectedNames) in _expectedChildren)
            {
                var actual = Directory.EnumerateFileSystemEntries(directory)
                    .Select(Path.GetFileName).ToArray();
                if (actual.Length != expectedNames.Count ||
                    actual.Any(name => name is null) || !expectedNames.SetEquals(actual!))
                    throw new IOException(Invalid);
            }
            long total = 0;
            foreach (var file in _expected)
            {
                var bound = _files[file.RelativePath];
                var length = RandomAccess.GetLength(bound.Handle);
                if (length < 0 || length > MaximumFileBytes || length > MaximumLayoutBytes - total)
                    throw new IOException(Invalid);
                total += length;
                if (HashBound(bound) != file.Sha256) throw new IOException(Invalid);
            }
            foreach (var path in _retained) path.RequireUnchanged();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or
            CryptographicException or KeyNotFoundException)
        { throw new IOException(Invalid); }
    }

    private void OpenAll()
    {
        var ancestors = new Stack<string>();
        for (var current = new DirectoryInfo(_root); current is not null; current = current.Parent)
            ancestors.Push(current.FullName);
        while (ancestors.Count != 0)
        {
            var path = ancestors.Pop();
            var bound = BoundPath.Open(path, directory: true,
                inLayout: path.Equals(_root, StringComparison.OrdinalIgnoreCase) ||
                    path.Equals(Path.GetDirectoryName(_root), StringComparison.OrdinalIgnoreCase));
            _retained.Add(bound);
            if (bound.InLayout) _directories.Add(path, bound);
        }

        foreach (var file in _expected)
        {
            var parent = _root;
            var segments = file.RelativePath.Split('/');
            for (var i = 0; i < segments.Length - 1; i++)
            {
                var child = Path.Combine(parent, segments[i]);
                AddExpectedChild(parent, segments[i]);
                if (!_directories.ContainsKey(child))
                {
                    var bound = BoundPath.Open(child, directory: true, inLayout: true);
                    _directories.Add(child, bound);
                    _retained.Add(bound);
                }
                parent = child;
            }
            AddExpectedChild(parent, segments[^1]);
            var path = Path.Combine(parent, segments[^1]);
            var item = BoundPath.Open(path, directory: false, inLayout: true);
            _retained.Add(item);
            _files.Add(file.RelativePath, item);
        }
    }

    private void AddExpectedChild(string parent, string name)
    {
        if (!_expectedChildren.TryGetValue(parent, out var children))
            _expectedChildren.Add(parent, children = new HashSet<string>(StringComparer.Ordinal));
        children.Add(name);
    }

    private BoundPath GetFile(string relativePath)
    {
        ThrowIfDisposed();
        if (!_files.TryGetValue(relativePath, out var file)) throw new IOException(Invalid);
        return file;
    }

    private static string HashBound(BoundPath file)
    {
        file.RequireUnchanged();
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        var length = RandomAccess.GetLength(file.Handle);
        if (length < 0 || length > MaximumFileBytes) throw new IOException(Invalid);
        long offset = 0;
        while (offset < length)
        {
            var wanted = checked((int)Math.Min(buffer.Length, length - offset));
            var read = RandomAccess.Read(file.Handle, buffer.AsSpan(0, wanted), offset);
            if (read <= 0) throw new IOException(Invalid);
            digest.AppendData(buffer, 0, read);
            offset += read;
        }
        file.RequireUnchanged();
        return Convert.ToHexString(digest.GetHashAndReset());
    }

    private static ServiceReleaseV2BoundFile[] RequireCanonicalInventory(
        IReadOnlyList<ServiceReleaseV2BoundFile> expected)
    {
        if (expected is null || expected.Count is < 1 or > TrustedManifestV2Codec.MaximumFiles)
            throw new IOException(Invalid);
        var snapshot = expected.ToArray();
        if (snapshot.Any(file => file is null)) throw new IOException(Invalid);
        // Layout-root sidecars are deliberately permitted here, although the Service-only
        // trusted-manifest codec excludes those names from its signed Service inventory.
        var seenFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenDirectories = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? previous = null;
        foreach (var file in snapshot)
        {
            var path = file.RelativePath;
            if (!IsCanonicalPath(path) || !IsUpperHash(file.Sha256) ||
                !seenFiles.Add(path) || seenDirectories.ContainsKey(path) ||
                (previous is not null && StringComparer.Ordinal.Compare(previous, path) >= 0))
                throw new IOException(Invalid);
            for (var slash = path.IndexOf('/'); slash >= 0; slash = path.IndexOf('/', slash + 1))
            {
                var directory = path[..slash];
                if (seenFiles.Contains(directory) ||
                    (seenDirectories.TryGetValue(directory, out var original) && original != directory))
                    throw new IOException(Invalid);
                seenDirectories[directory] = directory;
            }
            previous = path;
        }
        return snapshot;
    }

    private static bool IsUpperHash(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool IsCanonicalPath(string? path)
    {
        if (path is not { Length: > 0 and <= 240 }) return false;
        var segments = path.Split('/');
        if (segments.Length > 8) return false;
        foreach (var segment in segments)
        {
            if (segment.Length is < 1 or > 120 ||
                !IsEndpoint(segment[0]) || !IsEndpoint(segment[^1]) ||
                ReservedDeviceNames.Contains(segment.Split('.')[0])) return false;
            foreach (var c in segment)
                if (!IsEndpoint(c) && c is not '.' and not '-') return false;
        }
        return true;
    }

    private static bool IsEndpoint(char c) => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or
        >= '0' and <= '9' or '_';

    private static string RequireCanonicalRoot(string path)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) || Path.GetFullPath(path) != path ||
            path.Length < 4 || path[1] != ':' || path[2] != '\\' ||
            new DriveInfo(path[..3]).DriveType != DriveType.Fixed || !Directory.Exists(path))
            throw new IOException(Invalid);
        return path;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ServiceReleaseV2FinalBinding));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        for (var i = _retained.Count - 1; i >= 0; i--) _retained[i].Dispose();
    }

    private sealed class BoundPath : IDisposable
    {
        private readonly string _path;
        private readonly (uint Volume, ulong Index) _identity;
        internal SafeFileHandle Handle { get; }
        internal bool IsDirectory { get; }
        internal bool InLayout { get; }

        private BoundPath(string path, bool directory, bool inLayout, SafeFileHandle handle)
        {
            _path = path;
            IsDirectory = directory;
            InLayout = inLayout;
            Handle = handle;
            _identity = Inspect(handle, path, directory);
        }

        internal static BoundPath Open(string path, bool directory, bool inLayout)
        {
            var access = ReadControl | ReadAttributes | (directory ? 0 : GenericRead);
            var share = directory ? ShareRead | ShareWrite : ShareRead;
            var handle = CreateFile(path, access, share, IntPtr.Zero, OpenExisting,
                OpenReparsePoint | (directory ? BackupSemantics : 0), IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); throw new IOException(Invalid); }
            try { return new BoundPath(path, directory, inLayout, handle); }
            catch { handle.Dispose(); throw; }
        }

        internal void RequireUnchanged()
        {
            if (Inspect(Handle, _path, IsDirectory) != _identity) throw new IOException(Invalid);
            var access = ReadControl | ReadAttributes | (IsDirectory ? 0 : GenericRead);
            var share = IsDirectory ? ShareRead | ShareWrite : ShareRead;
            using var reopened = CreateFile(_path, access, share, IntPtr.Zero, OpenExisting,
                OpenReparsePoint | (IsDirectory ? BackupSemantics : 0), IntPtr.Zero);
            if (reopened.IsInvalid || Inspect(reopened, _path, IsDirectory) != _identity)
                throw new IOException(Invalid);
        }

        public void Dispose() => Handle.Dispose();
    }

    private static (uint Volume, ulong Index) Inspect(SafeFileHandle handle, string expectedPath,
        bool directory)
    {
        if (handle.IsInvalid || handle.IsClosed || GetFileType(handle) != 1 ||
            !GetFileInformationByHandle(handle, out var info) ||
            ((info.Attributes & (uint)FileAttributes.Directory) != 0) != directory ||
            (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
            (!directory && info.LinkCount != 1))
            throw new IOException(Invalid);
        var length = GetFinalPathNameByHandle(handle, null, 0, 0);
        if (length == 0 || length > 32768) throw new IOException(Invalid);
        var finalPath = new StringBuilder((int)length + 1);
        var written = GetFinalPathNameByHandle(handle, finalPath, (uint)finalPath.Capacity, 0);
        var expected = expectedPath.Length == 3 && expectedPath[1] == ':' ? expectedPath :
            expectedPath.TrimEnd('\\');
        if (written == 0 || written >= finalPath.Capacity ||
            !string.Equals(finalPath.ToString(), "\\\\?\\" + expected,
                StringComparison.OrdinalIgnoreCase))
            throw new IOException(Invalid);
        return (info.Volume, ((ulong)info.IndexHigh << 32) | info.IndexLow);
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
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfoNative info);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle handle);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,
        StringBuilder? path, uint length, uint flags);
}
