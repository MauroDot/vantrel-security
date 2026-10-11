using System.ComponentModel;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Service;

internal static class ComponentInspectionNative
{
    private const uint GenericRead = 0x80000000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileAttributeReparsePoint = 0x400;
    private const uint FileAttributeDirectory = 0x10;
    private const int FileStreamInfo = 7;
    private const int ErrorHandleEof = 38;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorMoreData = 234;
    private const int MaximumStreamInfoBytes = 64 * 1024;
    private const int MaximumStreamEntries = 16;
    private const int MaximumStreamNameBytes = 1024;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, FileShare share,
        IntPtr securityAttributes, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, char[] path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation info);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass,
        [Out] byte[] information, uint informationLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    // Identity is the complete 64-bit file index; VolumeSerial is compared separately.
    internal readonly record struct Metadata(bool IsReparsePoint, bool IsDirectory, long Length,
        ulong Identity, ulong LastWrite, uint VolumeSerial = 0);

    internal static SafeFileHandle Open(string path)
    {
        var handle = CreateFileW(path, GenericRead, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero,
            OpenExisting, FileFlagOpenReparsePoint | FileFlagOverlapped, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        return handle;
    }

    /// <summary>V2-only read binding: deny writes and deletion while identity and bytes are evaluated.</summary>
    internal static SafeFileHandle OpenProtected(string path, bool directory = false)
    {
        var handle = CreateFileW(path, GenericRead, FileShare.Read, IntPtr.Zero, OpenExisting,
            FileFlagOpenReparsePoint | FileFlagOverlapped | (directory ? FileFlagBackupSemantics : 0), IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        return handle;
    }

    internal static bool HasOnlyDefaultDataStream(SafeFileHandle handle, bool directory = false)
    {
        for (var size = 1024; size <= MaximumStreamInfoBytes; size *= 2)
        {
            var information = new byte[size];
            if (GetFileInformationByHandleEx(handle, FileStreamInfo, information, (uint)size))
                return ParseOnlyDefaultDataStream(information, directory);
            var error = Marshal.GetLastWin32Error();
            if (directory && error == ErrorHandleEof) return true; // Directories have no unnamed $DATA stream.
            if (error is ErrorInsufficientBuffer or ErrorMoreData && size < MaximumStreamInfoBytes) continue;
            throw new Win32Exception(error);
        }
        throw new IOException("Installed stream inventory exceeds its bound.");
    }

    /// <summary>Parses only the bounded FILE_STREAM_INFO chain returned for the retained object.</summary>
    internal static bool ParseOnlyDefaultDataStream(ReadOnlySpan<byte> information, bool directory)
    {
        const int fixedSize = 24; // NextEntryOffset, StreamNameLength, size and allocation size.
        var offset = 0;
        var count = 0;
        var onlyDefault = false;
        while (true)
        {
            if (++count > MaximumStreamEntries || offset > information.Length - fixedSize)
                throw new IOException("Installed stream inventory is malformed.");
            var entry = information[offset..];
            var next = BinaryPrimitives.ReadUInt32LittleEndian(entry);
            var nameLength = BinaryPrimitives.ReadUInt32LittleEndian(entry[4..]);
            var streamSize = BinaryPrimitives.ReadInt64LittleEndian(entry[8..]);
            var allocationSize = BinaryPrimitives.ReadInt64LittleEndian(entry[16..]);
            if (nameLength is 0 or > MaximumStreamNameBytes || (nameLength & 1) != 0 ||
                nameLength > entry.Length - fixedSize || streamSize < 0 || allocationSize < 0)
                throw new IOException("Installed stream name is malformed.");
            var name = Encoding.Unicode.GetString(entry.Slice(fixedSize, checked((int)nameLength)));
            if (count == 1) onlyDefault = string.Equals(name, "::$DATA", StringComparison.Ordinal);
            else onlyDefault = false;
            if (next == 0) return !directory && count == 1 && onlyDefault;
            var minimum = (fixedSize + (int)nameLength + 7) & ~7;
            if ((next & 7) != 0 || next < minimum || next > entry.Length - fixedSize)
                throw new IOException("Installed stream offsets are malformed.");
            offset = checked(offset + (int)next);
        }
    }

    internal static string FinalPath(SafeFileHandle handle)
    {
        var buffer = new char[32768];
        var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0 || length >= buffer.Length) throw new IOException("Final path is unavailable.");
        var value = new string(buffer, 0, (int)length);
        return value.StartsWith("\\\\?\\", StringComparison.Ordinal) ? value[4..] : value;
    }

    internal static Metadata GetMetadata(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var value)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var length = ((long)value.SizeHigh << 32) | value.SizeLow;
        var identity = ComposeFileIndex(value.IndexHigh, value.IndexLow);
        var write = ((ulong)value.WriteHigh << 32) | value.WriteLow;
        return new((value.Attributes & FileAttributeReparsePoint) != 0, (value.Attributes & FileAttributeDirectory) != 0,
            length, identity, write, value.VolumeSerial);
    }

    internal static ulong ComposeFileIndex(uint high, uint low) => ((ulong)high << 32) | low;
}

internal interface IComponentInspectionHandleOperations
{
    Microsoft.Win32.SafeHandles.SafeFileHandle Open(string path);
    ComponentInspectionNative.Metadata Metadata(Microsoft.Win32.SafeHandles.SafeFileHandle handle);
    string FinalPath(Microsoft.Win32.SafeHandles.SafeFileHandle handle);
    FileStream CreateStream(Microsoft.Win32.SafeHandles.SafeFileHandle handle);
}

internal sealed class NativeComponentInspectionHandleOperations : IComponentInspectionHandleOperations
{
    public Microsoft.Win32.SafeHandles.SafeFileHandle Open(string path) => ComponentInspectionNative.Open(path);
    public ComponentInspectionNative.Metadata Metadata(Microsoft.Win32.SafeHandles.SafeFileHandle handle) => ComponentInspectionNative.GetMetadata(handle);
    public string FinalPath(Microsoft.Win32.SafeHandles.SafeFileHandle handle) => ComponentInspectionNative.FinalPath(handle);
    public FileStream CreateStream(Microsoft.Win32.SafeHandles.SafeFileHandle handle) => new(handle, FileAccess.Read, 65536, isAsync: true);
}
