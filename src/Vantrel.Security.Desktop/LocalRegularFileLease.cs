using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Desktop;

internal enum LocalRegularFileLeaseOutcome { Opened, Declined, Unavailable }

internal sealed class LocalFileInspectionCoordinator
{
    private int _inFlight;
    internal bool IsInFlight => Volatile.Read(ref _inFlight) != 0;

    internal bool TryAcquire(out IDisposable? lease)
    {
        if (Interlocked.CompareExchange(ref _inFlight, 1, 0) != 0) { lease = null; return false; }
        lease = new ReleaseLease(this);
        return true;
    }

    private sealed class ReleaseLease(LocalFileInspectionCoordinator owner) : IDisposable
    {
        private LocalFileInspectionCoordinator? _owner = owner;
        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release();
    }

    private void Release() => Volatile.Write(ref _inFlight, 0);
}

internal sealed class LocalRegularFileLease : IDisposable
{
    internal const long MaximumByteLength = 256L * 1024 * 1024;
    private const uint FileTypeDisk = 0x0001;
    private const uint GenericRead = 0x80000000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x0010;
    private const uint FileAttributeDevice = 0x0040;
    private const uint FileAttributeReparsePoint = 0x0400;
    private readonly FileIdentity _identity;
    private bool _disposed;

    private LocalRegularFileLease(SafeFileHandle handle, string normalizedPath, string finalDosPath, FileIdentity identity)
    {
        Handle = handle; NormalizedPath = normalizedPath; FinalDosPath = finalDosPath; _identity = identity;
    }

    internal SafeFileHandle Handle { get; }
    internal string NormalizedPath { get; }
    internal string FinalDosPath { get; }
    internal string FileName => Path.GetFileName(NormalizedPath);
    internal long ByteLength => _identity.ByteLength;

    internal static async Task<(LocalRegularFileLeaseOutcome Outcome, LocalRegularFileLease? Lease)> OpenAsync(
        string selectedPath, CancellationToken token, Func<CancellationToken, Task>? afterPathValidationAsync = null)
    {
        if (!TryNormalizeFixedLocalPath(selectedPath, out var normalizedPath)) return (LocalRegularFileLeaseOutcome.Declined, null);
        token.ThrowIfCancellationRequested();
        if (!HasNoReparseAncestor(normalizedPath) || !IsInitiallyRegular(normalizedPath)) return (LocalRegularFileLeaseOutcome.Declined, null);
        if (afterPathValidationAsync is not null) await afterPathValidationAsync(token).ConfigureAwait(false);
        try
        {
            var handle = CreateFile(normalizedPath, GenericRead, (uint)(FileShare.ReadWrite | FileShare.Delete), IntPtr.Zero,
                OpenExisting, FileFlagOverlapped | FileFlagSequentialScan | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); return (LocalRegularFileLeaseOutcome.Unavailable, null); }
            if (!TryReadRegularFileIdentity(handle, out var identity) || identity.ByteLength > MaximumByteLength ||
                !TryGetFinalNormalizedDosPath(handle, out var finalPath) ||
                !string.Equals(finalPath, ToExtendedDosPath(normalizedPath), StringComparison.OrdinalIgnoreCase))
            {
                handle.Dispose(); return (LocalRegularFileLeaseOutcome.Declined, null);
            }
            return (LocalRegularFileLeaseOutcome.Opened, new LocalRegularFileLease(handle, normalizedPath, finalPath, identity));
        }
        catch (UnauthorizedAccessException) { return (LocalRegularFileLeaseOutcome.Unavailable, null); }
        catch (IOException) { return (LocalRegularFileLeaseOutcome.Unavailable, null); }
        catch (NotSupportedException) { return (LocalRegularFileLeaseOutcome.Unavailable, null); }
    }

    internal bool IsUnchanged() => !_disposed && TryReadRegularFileIdentity(Handle, out var identity) && identity == _identity &&
        TryGetFinalNormalizedDosPath(Handle, out var finalPath) && string.Equals(finalPath, FinalDosPath, StringComparison.OrdinalIgnoreCase);

    public void Dispose() { if (_disposed) return; _disposed = true; Handle.Dispose(); }

    private static bool TryNormalizeFixedLocalPath(string path, out string normalizedPath)
    {
        normalizedPath = string.Empty;
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith("\\\\", StringComparison.Ordinal) || !Path.IsPathFullyQualified(path)) return false;
        try
        {
            normalizedPath = Path.GetFullPath(path); var root = Path.GetPathRoot(normalizedPath);
            if (root is { Length: 3 } && root[1] == ':' && root[2] == Path.DirectorySeparatorChar && new DriveInfo(root).DriveType == DriveType.Fixed) return true;
        }
        catch (ArgumentException) { }
        catch (IOException) { }
        normalizedPath = string.Empty; return false;
    }

    private static bool HasNoReparseAncestor(string normalizedPath)
    {
        try
        {
            var root = Path.GetPathRoot(normalizedPath); var parent = Path.GetDirectoryName(normalizedPath);
            if (root is null || parent is null || !IsRegularDirectory(root)) return false;
            var relative = Path.GetRelativePath(root, parent); if (relative == ".") return true;
            var current = root;
            foreach (var segment in relative.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
            { current = Path.Combine(current, segment); if (!IsRegularDirectory(current)) return false; }
            return true;
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

    private static bool IsInitiallyRegular(string path)
    {
        try { var attributes = File.GetAttributes(path); return (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) == 0; }
        catch (UnauthorizedAccessException) { return false; }
        catch (IOException) { return false; }
    }

    private static bool TryReadRegularFileIdentity(SafeFileHandle handle, out FileIdentity identity)
    {
        identity = default;
        if (GetFileType(handle) != FileTypeDisk || !GetFileInformationByHandle(handle, out var information) ||
            (information.FileAttributes & (FileAttributeDirectory | FileAttributeDevice | FileAttributeReparsePoint)) != 0) return false;
        var length = ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow; if (length > long.MaxValue) return false;
        identity = new(information.VolumeSerialNumber, ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow,
            (long)length, ((ulong)information.LastWriteTimeHigh << 32) | information.LastWriteTimeLow);
        return true;
    }

    private static bool TryGetFinalNormalizedDosPath(SafeFileHandle handle, out string finalPath)
    {
        finalPath = string.Empty; var required = GetFinalPathNameByHandle(handle, null, 0, 0);
        if (required == 0 || required > int.MaxValue - 1) return false;
        var buffer = new StringBuilder((int)required + 1); var written = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (written == 0 || written >= (uint)buffer.Capacity) return false;
        finalPath = buffer.ToString(); return finalPath.StartsWith("\\\\?\\", StringComparison.Ordinal) && !finalPath.Contains('\0');
    }

    private static string ToExtendedDosPath(string normalizedPath) => "\\\\?\\" + normalizedPath;

    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint GetFileType(SafeFileHandle file);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder? path, uint pathLength, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string fileName, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes; private uint _creationLow; private uint _creationHigh; private uint _accessLow; private uint _accessHigh;
        internal uint LastWriteTimeLow; internal uint LastWriteTimeHigh; internal uint VolumeSerialNumber; internal uint FileSizeHigh; internal uint FileSizeLow;
        private uint _links; internal uint FileIndexHigh; internal uint FileIndexLow;
    }

    private readonly record struct FileIdentity(uint VolumeSerialNumber, ulong FileIndex, long ByteLength, ulong LastWriteTime);
}
