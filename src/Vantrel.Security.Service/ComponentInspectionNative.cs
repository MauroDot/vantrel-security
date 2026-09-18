using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.Service;

internal static class ComponentInspectionNative
{
    private const uint GenericRead = 0x80000000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileAttributeReparsePoint = 0x400;
    private const uint FileAttributeDirectory = 0x10;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, FileShare share,
        IntPtr securityAttributes, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, char[] path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation info);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    internal readonly record struct Metadata(bool IsReparsePoint, bool IsDirectory, long Length, ulong Identity, ulong LastWrite);

    internal static SafeFileHandle Open(string path)
    {
        var handle = CreateFileW(path, GenericRead, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero,
            OpenExisting, FileFlagOpenReparsePoint | FileFlagOverlapped, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        return handle;
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
        var identity = ((ulong)value.VolumeSerial << 32) | value.IndexLow ^ ((ulong)value.IndexHigh << 16);
        var write = ((ulong)value.WriteHigh << 32) | value.WriteLow;
        return new((value.Attributes & FileAttributeReparsePoint) != 0, (value.Attributes & FileAttributeDirectory) != 0, length, identity, write);
    }
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
