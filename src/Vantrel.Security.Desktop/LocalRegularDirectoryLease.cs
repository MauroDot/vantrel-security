using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Desktop;

internal enum LocalRegularDirectoryLeaseOutcome { Opened, Declined, Unavailable }

internal sealed class LocalRegularDirectoryLease : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x0010;
    private const uint FileAttributeReparsePoint = 0x0400;
    private readonly DirectoryIdentity _identity;
    private bool _disposed;

    private LocalRegularDirectoryLease(SafeFileHandle handle, string normalizedPath, string finalDosPath, DirectoryIdentity identity)
    {
        Handle = handle;
        NormalizedPath = normalizedPath;
        FinalDosPath = finalDosPath;
        _identity = identity;
    }

    internal SafeFileHandle Handle { get; }
    internal string NormalizedPath { get; }
    internal string FinalDosPath { get; }
    internal uint VolumeSerialNumber => _identity.VolumeSerialNumber;

    internal bool IsExactDirectChildFinalPath(string finalPath, string entryName) => !_disposed &&
        string.Equals(Path.GetDirectoryName(finalPath), FinalDosPath, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(Path.GetFileName(finalPath), entryName, StringComparison.OrdinalIgnoreCase);

    internal static Task<(LocalRegularDirectoryLeaseOutcome Outcome, LocalRegularDirectoryLease? Lease)> OpenAsync(
        string selectedPath, CancellationToken token)
    {
        if (!TryNormalizeFixedLocalPath(selectedPath, out var normalizedPath))
            return Task.FromResult((LocalRegularDirectoryLeaseOutcome.Declined, (LocalRegularDirectoryLease?)null));
        token.ThrowIfCancellationRequested();
        if (!IsCurrentPathSafe(normalizedPath))
            return Task.FromResult((LocalRegularDirectoryLeaseOutcome.Declined, (LocalRegularDirectoryLease?)null));

        try
        {
            var handle = CreateFile(normalizedPath, GenericRead, (uint)(FileShare.ReadWrite | FileShare.Delete), IntPtr.Zero,
                OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                return Task.FromResult((LocalRegularDirectoryLeaseOutcome.Unavailable, (LocalRegularDirectoryLease?)null));
            }

            if (!TryReadDirectoryIdentity(handle, out var identity) ||
                !TryGetFinalNormalizedDosPath(handle, out var finalPath) ||
                !string.Equals(finalPath, ToExtendedDosPath(normalizedPath), StringComparison.OrdinalIgnoreCase))
            {
                handle.Dispose();
                return Task.FromResult((LocalRegularDirectoryLeaseOutcome.Declined, (LocalRegularDirectoryLease?)null));
            }

            return Task.FromResult((LocalRegularDirectoryLeaseOutcome.Opened,
                (LocalRegularDirectoryLease?)new LocalRegularDirectoryLease(handle, normalizedPath, finalPath, identity)));
        }
        catch (UnauthorizedAccessException) { return Task.FromResult((LocalRegularDirectoryLeaseOutcome.Unavailable, (LocalRegularDirectoryLease?)null)); }
        catch (IOException) { return Task.FromResult((LocalRegularDirectoryLeaseOutcome.Unavailable, (LocalRegularDirectoryLease?)null)); }
        catch (NotSupportedException) { return Task.FromResult((LocalRegularDirectoryLeaseOutcome.Unavailable, (LocalRegularDirectoryLease?)null)); }
    }

    internal bool IsUnchanged() => !_disposed && IsCurrentPathSafe(NormalizedPath) &&
        TryReadDirectoryIdentity(Handle, out var identity) && identity == _identity &&
        TryGetFinalNormalizedDosPath(Handle, out var finalPath) &&
        string.Equals(finalPath, FinalDosPath, StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Handle.Dispose();
    }

    private static bool TryNormalizeFixedLocalPath(string path, out string normalizedPath)
    {
        normalizedPath = string.Empty;
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith("\\\\", StringComparison.Ordinal) || !Path.IsPathFullyQualified(path)) return false;
        try
        {
            normalizedPath = Path.GetFullPath(path);
            var root = Path.GetPathRoot(normalizedPath);
            if (root is { Length: 3 } && root[1] == ':' && root[2] == Path.DirectorySeparatorChar &&
                new DriveInfo(root).DriveType == DriveType.Fixed)
            {
                return true;
            }
        }
        catch (ArgumentException) { }
        catch (IOException) { }
        normalizedPath = string.Empty;
        return false;
    }

    private static bool IsCurrentPathSafe(string normalizedPath)
    {
        try
        {
            var root = Path.GetPathRoot(normalizedPath);
            var parent = Path.GetDirectoryName(normalizedPath);
            if (root is null || parent is null || !IsRegularDirectory(root)) return false;
            var relativeParent = Path.GetRelativePath(root, parent);
            var current = root;
            if (relativeParent != ".")
            {
                foreach (var segment in relativeParent.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
                {
                    current = Path.Combine(current, segment);
                    if (!IsRegularDirectory(current)) return false;
                }
            }

            return IsRegularDirectory(normalizedPath);
        }
        catch (ArgumentException) { return false; }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static bool IsRegularDirectory(string path)
    {
        var attributes = File.GetAttributes(path);
        return (attributes & FileAttributes.Directory) != 0 && (attributes & FileAttributes.ReparsePoint) == 0;
    }

    private static bool TryReadDirectoryIdentity(SafeFileHandle handle, out DirectoryIdentity identity)
    {
        identity = default;
        if (!GetFileInformationByHandle(handle, out var information) ||
            (information.FileAttributes & (FileAttributeDirectory | FileAttributeReparsePoint)) != FileAttributeDirectory)
        {
            return false;
        }

        identity = new DirectoryIdentity(information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow,
            ((ulong)information.LastWriteTimeHigh << 32) | information.LastWriteTimeLow);
        return true;
    }

    private static bool TryGetFinalNormalizedDosPath(SafeFileHandle handle, out string finalPath)
    {
        finalPath = string.Empty;
        var required = GetFinalPathNameByHandle(handle, null, 0, 0);
        if (required == 0 || required > int.MaxValue - 1) return false;
        var buffer = new StringBuilder((int)required + 1);
        var written = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (written == 0 || written >= (uint)buffer.Capacity) return false;
        finalPath = buffer.ToString();
        return finalPath.StartsWith("\\\\?\\", StringComparison.Ordinal) && !finalPath.Contains('\0');
    }

    private static string ToExtendedDosPath(string normalizedPath) => "\\\\?\\" + normalizedPath;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder? path, uint pathLength, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string fileName, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes; private uint _creationLow; private uint _creationHigh; private uint _accessLow; private uint _accessHigh;
        internal uint LastWriteTimeLow; internal uint LastWriteTimeHigh; internal uint VolumeSerialNumber; private uint _sizeHigh; private uint _sizeLow;
        private uint _links; internal uint FileIndexHigh; internal uint FileIndexLow;
    }

    private readonly record struct DirectoryIdentity(uint VolumeSerialNumber, ulong FileIndex, ulong LastWriteTime);
}
