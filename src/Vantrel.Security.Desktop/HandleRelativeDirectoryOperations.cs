using System.Buffers.Binary;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Desktop;

/// <summary>
/// Enumerates direct entries from an already-open directory and opens the exact
/// enumerated file ID. GetFileInformationByHandleEx advances enumeration on the
/// supplied directory handle; OpenFileById accepts that same handle as its
/// documented volume hint, so no selected-directory text path is reopened.
/// </summary>
internal interface IHandleRelativeDirectoryOperations
{
    IEnumerable<HandleRelativeDirectoryEntry> Enumerate(SafeFileHandle directoryHandle);
    SafeFileHandle OpenFile(SafeFileHandle directoryHandle, long fileId);
}

internal sealed record HandleRelativeDirectoryEntry(string Name, long FileId, uint Attributes);

internal enum FileIdType
{
    FileId = 0,
    ObjectId = 1,
    ExtendedFileIdType = 2,
    MaximumFileIdType = 3
}

[StructLayout(LayoutKind.Explicit, Size = 24)]
internal struct FileIdDescriptor
{
    [FieldOffset(0)] internal uint Size;
    [FieldOffset(4)] internal FileIdType Type;
    [FieldOffset(8)] internal long FileId;
}

internal interface IHandleRelativeDirectoryNativeApi
{
    bool ReadDirectory(SafeFileHandle directoryHandle, int informationClass, byte[] buffer, out int error);
    SafeFileHandle OpenFileById(SafeFileHandle directoryHandle, ref FileIdDescriptor fileId, uint desiredAccess, uint shareMode, uint flagsAndAttributes);
}

internal sealed class WindowsHandleRelativeDirectoryOperations : IHandleRelativeDirectoryOperations
{
    private const int FileIdBothDirectoryInfo = 10;
    private const int FileIdBothDirectoryRestartInfo = 11;
    private const int ErrorNoMoreFiles = 18;
    private const int BufferLength = 64 * 1024;
    private const int FileNameOffset = 104;
    private const uint GenericRead = 0x80000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private readonly IHandleRelativeDirectoryNativeApi _native;

    internal WindowsHandleRelativeDirectoryOperations(IHandleRelativeDirectoryNativeApi? native = null) =>
        _native = native ?? new Kernel32HandleRelativeDirectoryNativeApi();

    public IEnumerable<HandleRelativeDirectoryEntry> Enumerate(SafeFileHandle directoryHandle)
    {
        ArgumentNullException.ThrowIfNull(directoryHandle);
        var buffer = new byte[BufferLength];
        var informationClass = FileIdBothDirectoryRestartInfo;
        while (true)
        {
            if (!_native.ReadDirectory(directoryHandle, informationClass, buffer, out var error))
            {
                if (error == ErrorNoMoreFiles) yield break;
                throw new IOException("The directory entries could not be observed.", new Win32Exception(error));
            }

            informationClass = FileIdBothDirectoryInfo;
            var offset = 0;
            while (true)
            {
                if (offset < 0 || offset > buffer.Length - FileNameOffset)
                    throw new IOException("The directory entry data was malformed.");

                var nextOffset = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, sizeof(uint)));
                var attributes = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset + 56, sizeof(uint)));
                var nameByteLength = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset + 60, sizeof(uint)));
                var fileId = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(offset + 96, sizeof(long)));
                var remainingLength = buffer.Length - offset;
                if (nextOffset != 0 && (nextOffset > (uint)remainingLength || nextOffset < FileNameOffset || (nextOffset & 7) != 0))
                    throw new IOException("The directory entry data was malformed.");

                var recordLength = nextOffset == 0 ? remainingLength : (int)nextOffset;
                if ((nameByteLength & 1) != 0 || nameByteLength == 0 || nameByteLength > recordLength - FileNameOffset ||
                    recordLength < FileNameOffset)
                {
                    throw new IOException("The directory entry data was malformed.");
                }

                var name = System.Text.Encoding.Unicode.GetString(buffer, offset + FileNameOffset, checked((int)nameByteLength));
                yield return new HandleRelativeDirectoryEntry(name, fileId, attributes);
                if (nextOffset == 0) break;
                offset = checked(offset + (int)nextOffset);
            }
        }
    }

    public SafeFileHandle OpenFile(SafeFileHandle directoryHandle, long fileId)
    {
        ArgumentNullException.ThrowIfNull(directoryHandle);
        var descriptor = new FileIdDescriptor
        {
            Size = (uint)Marshal.SizeOf<FileIdDescriptor>(),
            Type = FileIdType.FileId,
            FileId = fileId
        };
        return _native.OpenFileById(directoryHandle, ref descriptor, GenericRead,
            (uint)(FileShare.ReadWrite | FileShare.Delete),
            FileFlagOverlapped | FileFlagSequentialScan | FileFlagOpenReparsePoint);
    }

    private sealed class Kernel32HandleRelativeDirectoryNativeApi : IHandleRelativeDirectoryNativeApi
    {
        public bool ReadDirectory(SafeFileHandle directoryHandle, int informationClass, byte[] buffer, out int error)
        {
            var result = GetFileInformationByHandleEx(directoryHandle, informationClass, buffer, (uint)buffer.Length);
            error = result ? 0 : Marshal.GetLastWin32Error();
            return result;
        }

        public SafeFileHandle OpenFileById(SafeFileHandle directoryHandle, ref FileIdDescriptor fileId, uint desiredAccess,
            uint shareMode, uint flagsAndAttributes) =>
            NativeOpenFileById(directoryHandle, ref fileId, desiredAccess, shareMode, IntPtr.Zero, flagsAndAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            int fileInformationClass,
            [Out] byte[] fileInformation,
            uint bufferSize);

        [DllImport("kernel32.dll", EntryPoint = "OpenFileById", SetLastError = true)]
        private static extern SafeFileHandle NativeOpenFileById(
            SafeFileHandle volumeHint,
            ref FileIdDescriptor fileId,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint flagsAndAttributes);
    }

}
