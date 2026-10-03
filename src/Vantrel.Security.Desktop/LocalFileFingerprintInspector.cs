using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Desktop;

internal enum FileFingerprintInspectionOutcome
{
    Completed,
    Declined,
    Unavailable,
    Changed,
    AlreadyInProgress
}

internal sealed record FileFingerprintInspectionResult(
    FileFingerprintInspectionOutcome Outcome,
    string? FileName,
    long? ByteLength,
    string? Sha256)
{
    internal static FileFingerprintInspectionResult Completed(string fileName, long byteLength, string sha256) =>
        new(FileFingerprintInspectionOutcome.Completed, fileName, byteLength, sha256);

    internal static FileFingerprintInspectionResult WithoutFile(FileFingerprintInspectionOutcome outcome) =>
        new(outcome, null, null, null);
}

/// <summary>
/// Creates a transient SHA-256 fingerprint for one user-selected local regular file.
/// This class neither classifies a file nor sends file data outside the Desktop process.
/// </summary>
internal sealed class LocalFileFingerprintInspector
{
    internal const long MaximumByteLength = 256L * 1024 * 1024;
    private const int BufferSize = 64 * 1024;
    private const uint FileTypeDisk = 0x0001;
    private const uint GenericRead = 0x80000000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x0010;
    private const uint FileAttributeDevice = 0x0040;
    private const uint FileAttributeReparsePoint = 0x0400;

    private readonly Func<CancellationToken, Task>? _afterFirstReadAsync;
    private readonly Func<CancellationToken, Task>? _afterPathValidationAsync;
    private int _inFlight;

    internal LocalFileFingerprintInspector(
        Func<CancellationToken, Task>? afterFirstReadAsync = null,
        Func<CancellationToken, Task>? afterPathValidationAsync = null)
    {
        _afterFirstReadAsync = afterFirstReadAsync;
        _afterPathValidationAsync = afterPathValidationAsync;
    }

    internal async Task<FileFingerprintInspectionResult> InspectAsync(string selectedPath, CancellationToken cancellationToken)
    {
        if (!TryNormalizeFixedLocalPath(selectedPath, out var normalizedPath))
            return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Declined);

        if (Interlocked.CompareExchange(ref _inFlight, 1, 0) != 0)
            return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.AlreadyInProgress);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!HasNoReparseAncestor(normalizedPath) || !IsInitiallyRegular(normalizedPath))
                return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Declined);

            if (_afterPathValidationAsync is not null)
                await _afterPathValidationAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                using var handle = CreateFile(
                    normalizedPath,
                    GenericRead,
                    (uint)(FileShare.ReadWrite | FileShare.Delete),
                    IntPtr.Zero,
                    OpenExisting,
                    FileFlagOverlapped | FileFlagSequentialScan | FileFlagOpenReparsePoint,
                    IntPtr.Zero);
                if (handle.IsInvalid)
                    return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Unavailable);

                if (!TryReadRegularFileIdentity(handle, out var before))
                    return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Declined);

                if (!TryGetFinalNormalizedDosPath(handle, out var finalPath) ||
                    !string.Equals(finalPath, ToExtendedDosPath(normalizedPath), StringComparison.OrdinalIgnoreCase))
                    return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Declined);

                if (before.ByteLength > MaximumByteLength)
                    return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Declined);

                var buffer = new byte[BufferSize];
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                long offset = 0;
                var firstRead = true;
                while (offset < before.ByteLength)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var requested = (int)Math.Min(buffer.Length, before.ByteLength - offset);
                    var read = await RandomAccess.ReadAsync(handle, buffer.AsMemory(0, requested), offset, cancellationToken)
                        .ConfigureAwait(false);
                    if (read == 0)
                        return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Changed);

                    hash.AppendData(buffer, 0, read);
                    offset += read;

                    if (firstRead)
                    {
                        firstRead = false;
                        if (_afterFirstReadAsync is not null)
                            await _afterFirstReadAsync(cancellationToken).ConfigureAwait(false);
                    }
                }

                cancellationToken.ThrowIfCancellationRequested();
                if (!TryReadRegularFileIdentity(handle, out var after) || before != after)
                    return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Changed);

                return FileFingerprintInspectionResult.Completed(
                    Path.GetFileName(normalizedPath),
                    before.ByteLength,
                    Convert.ToHexString(hash.GetHashAndReset()));
            }
            catch (UnauthorizedAccessException)
            {
                return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Unavailable);
            }
            catch (IOException)
            {
                return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Unavailable);
            }
            catch (NotSupportedException)
            {
                return FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Unavailable);
            }
        }
        finally
        {
            Volatile.Write(ref _inFlight, 0);
        }
    }

    private static bool TryNormalizeFixedLocalPath(string path, out string normalizedPath)
    {
        normalizedPath = string.Empty;
        if (string.IsNullOrWhiteSpace(path) ||
            path.StartsWith("\\\\", StringComparison.Ordinal) ||
            path.StartsWith("\\?\\", StringComparison.Ordinal) ||
            path.StartsWith("\\.\\", StringComparison.Ordinal) ||
            !Path.IsPathFullyQualified(path))
            return false;

        try
        {
            normalizedPath = Path.GetFullPath(path);
            var root = Path.GetPathRoot(normalizedPath);
            if (root is not { Length: 3 } || root[1] != ':' || root[2] != Path.DirectorySeparatorChar ||
                new DriveInfo(root).DriveType != DriveType.Fixed)
            {
                normalizedPath = string.Empty;
                return false;
            }

            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static bool HasNoReparseAncestor(string normalizedPath)
    {
        try
        {
            var root = Path.GetPathRoot(normalizedPath);
            var parent = Path.GetDirectoryName(normalizedPath);
            if (root is null || parent is null) return false;

            var current = root;
            if (!IsRegularDirectory(current)) return false;
            var relativeParent = Path.GetRelativePath(root, parent);
            if (relativeParent == ".") return true;

            foreach (var segment in relativeParent.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                         StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, segment);
                if (!IsRegularDirectory(current)) return false;
            }

            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsRegularDirectory(string path)
    {
        var attributes = File.GetAttributes(path);
        return (attributes & FileAttributes.Directory) != 0 &&
            (attributes & FileAttributes.ReparsePoint) == 0;
    }

    private static bool IsInitiallyRegular(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            return (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) == 0;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static bool TryReadRegularFileIdentity(SafeFileHandle handle, out FileIdentity identity)
    {
        identity = default;
        if (GetFileType(handle) != FileTypeDisk || !GetFileInformationByHandle(handle, out var information))
            return false;

        if ((information.FileAttributes & (FileAttributeDirectory | FileAttributeDevice | FileAttributeReparsePoint)) != 0)
            return false;

        var byteLength = ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow;
        if (byteLength > long.MaxValue)
            return false;

        identity = new FileIdentity(
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow,
            (long)byteLength,
            ((ulong)information.LastWriteTimeHigh << 32) | information.LastWriteTimeLow);
        return identity.ByteLength >= 0;
    }

    private static bool TryGetFinalNormalizedDosPath(SafeFileHandle handle, out string finalPath)
    {
        finalPath = string.Empty;
        var requiredLength = GetFinalPathNameByHandle(handle, null, 0, 0);
        if (requiredLength == 0 || requiredLength > int.MaxValue - 1) return false;

        var buffer = new StringBuilder((int)requiredLength + 1);
        var writtenLength = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (writtenLength == 0 || writtenLength >= (uint)buffer.Capacity) return false;

        finalPath = buffer.ToString();
        return finalPath.StartsWith("\\\\?\\", StringComparison.Ordinal) && !finalPath.Contains('\0');
    }

    private static string ToExtendedDosPath(string normalizedPath) => "\\\\?\\" + normalizedPath;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle file);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder? path,
        uint pathLength,
        uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        private uint _creationTimeLow;
        private uint _creationTimeHigh;
        private uint _lastAccessTimeLow;
        private uint _lastAccessTimeHigh;
        internal uint LastWriteTimeLow;
        internal uint LastWriteTimeHigh;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        private uint _numberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    private readonly record struct FileIdentity(uint VolumeSerialNumber, ulong FileIndex, long ByteLength,
        ulong LastWriteTime);
}
