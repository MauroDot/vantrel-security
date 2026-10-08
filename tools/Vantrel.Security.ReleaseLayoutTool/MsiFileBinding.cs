using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>A path and its direct parent held without delete sharing for the entire operation.</summary>
public sealed class MsiFileBinding : IDisposable
{
    private const uint Read = 0x80000000, Write = 0x40000000, ReadAttributes = 0x80;
    private const uint OpenExisting = 3, CreateNew = 1, OpenReparse = 0x00200000, BackupSemantics = 0x02000000;
    private readonly SafeFileHandle _parent;
    private readonly string _parentPath;
    private readonly string _finalPath;
    private readonly (uint Volume, ulong Index) _parentIdentity;
    private readonly (uint Volume, ulong Index) _fileIdentity;
    public string Path { get; }
    public SafeFileHandle Handle { get; }

    private MsiFileBinding(string path, SafeFileHandle parent, SafeFileHandle file)
    {
        Path = path; _parent = parent; Handle = file;
        _parentPath = FinalPath(parent); _finalPath = FinalPath(file);
        _parentIdentity = Identity(parent, expectDirectory: true);
        _fileIdentity = Identity(file, expectDirectory: false);
        if (!string.Equals(_parentPath, ExpectedFinal(System.IO.Path.GetDirectoryName(path)!), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(_finalPath, ExpectedFinal(path), StringComparison.OrdinalIgnoreCase))
            throw new IOException("MSI file binding is unavailable.");
    }

    public static MsiFileBinding Open(string path, bool createNew = false)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length < 3 || path[1] != ':' || path[2] != '\\' ||
            new DriveInfo(path[..3]).DriveType != DriveType.Fixed || !System.IO.Path.IsPathFullyQualified(path) ||
            !string.Equals(System.IO.Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(System.IO.Path.GetExtension(path), ".msi", StringComparison.OrdinalIgnoreCase))
            throw new IOException("MSI file binding is unavailable.");
        for (var directory = new DirectoryInfo(System.IO.Path.GetDirectoryName(path)!); directory is not null; directory = directory.Parent)
            if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("MSI file binding is unavailable.");
        var parent = CreateFile(System.IO.Path.GetDirectoryName(path)!, ReadAttributes,
            (uint)(FileShare.ReadWrite), IntPtr.Zero, OpenExisting, BackupSemantics | OpenReparse, IntPtr.Zero);
        if (parent.IsInvalid) { parent.Dispose(); throw new IOException("MSI file binding is unavailable."); }
        try
        {
            var file = CreateFile(path, createNew ? Read | Write : Read,
                (uint)(createNew ? FileShare.ReadWrite : FileShare.Read), IntPtr.Zero, createNew ? CreateNew : OpenExisting, OpenReparse, IntPtr.Zero);
            if (file.IsInvalid) { file.Dispose(); throw new IOException("MSI file binding is unavailable."); }
            try { return new MsiFileBinding(path, parent, file); }
            catch { file.Dispose(); throw; }
        }
        catch { parent.Dispose(); throw; }
    }

    public void RequireUnchanged()
    {
        if (Handle.IsClosed || _parent.IsClosed || Identity(Handle, expectDirectory: false) != _fileIdentity ||
            Identity(_parent, expectDirectory: true) != _parentIdentity ||
            !string.Equals(FinalPath(Handle), _finalPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(FinalPath(_parent), _parentPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(FinalPath(Handle), ExpectedFinal(Path), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(FinalPath(_parent), ExpectedFinal(System.IO.Path.GetDirectoryName(Path)!), StringComparison.OrdinalIgnoreCase) ||
            (File.GetAttributes(Path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("MSI file binding changed.");
    }

    public string Sha256()
    {
        RequireUnchanged();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var length = RandomAccess.GetLength(Handle);
        var buffer = new byte[65536]; long position = 0;
        while (position < length)
        {
            var count = RandomAccess.Read(Handle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - position)), position);
            if (count <= 0) throw new IOException("MSI file binding changed.");
            hash.AppendData(buffer.AsSpan(0, count)); position += count;
        }
        if (RandomAccess.GetLength(Handle) != length) throw new IOException("MSI file binding changed.");
        RequireUnchanged();
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    public void CopyTo(MsiFileBinding destination)
    {
        var length = RandomAccess.GetLength(Handle); var buffer = new byte[65536]; long position = 0;
        while (position < length)
        {
            var count = RandomAccess.Read(Handle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - position)), position);
            if (count <= 0) throw new IOException("MSI source changed.");
            RandomAccess.Write(destination.Handle, buffer.AsSpan(0, count), position); position += count;
        }
        RandomAccess.FlushToDisk(destination.Handle);
        if (RandomAccess.GetLength(Handle) != length || RandomAccess.GetLength(destination.Handle) != length)
            throw new IOException("MSI source changed.");
        RequireUnchanged(); destination.RequireUnchanged();
    }

    public void Dispose() { Handle.Dispose(); _parent.Dispose(); }
    private static string ExpectedFinal(string path) => "\\\\?\\" + path.TrimEnd(System.IO.Path.DirectorySeparatorChar);
    private static (uint Volume, ulong Index) Identity(SafeFileHandle handle, bool expectDirectory)
    {
        if (!GetFileInformationByHandle(handle, out var info) ||
            (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
            ((info.Attributes & (uint)FileAttributes.Directory) != 0) != expectDirectory)
            throw new IOException("MSI file binding is unavailable.");
        return (info.Volume, ((ulong)info.IndexHigh << 32) | info.IndexLow);
    }
    private static string FinalPath(SafeFileHandle handle)
    {
        var length = GetFinalPathNameByHandle(handle, null, 0, 0);
        if (length == 0 || length > 32768) throw new IOException("MSI file binding is unavailable.");
        var buffer = new StringBuilder((int)length + 1);
        var written = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (written == 0 || written >= buffer.Capacity || !buffer.ToString().StartsWith("\\\\?\\", StringComparison.Ordinal))
            throw new IOException("MSI file binding is unavailable.");
        return buffer.ToString();
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInfoNative information);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder? path, uint length, uint flags);
    [StructLayout(LayoutKind.Sequential)] private struct FileInfoNative
    {
        internal uint Attributes; private uint _creationLow, _creationHigh, _accessLow, _accessHigh, _writeLow, _writeHigh;
        internal uint Volume; private uint _sizeHigh, _sizeLow, _links; internal uint IndexHigh, IndexLow;
    }
}
