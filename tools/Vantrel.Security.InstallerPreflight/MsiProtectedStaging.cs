using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Vantrel.Security.InstallerPreflight;

internal readonly record struct FileIdentity(uint Volume, ulong Index, string FinalPath);

internal sealed class MsiProtectedStaging : IDisposable
{
    private const uint ReadAttributes = 0x80, Read = 0x80000000, Write = 0x40000000;
    private const uint ShareRead = 1, ShareReadWrite = 3, OpenExisting = 3, CreateDispositionNew = 1;
    private const uint BackupSemantics = 0x02000000, OpenReparse = 0x00200000;
    private readonly string _directory;
    private readonly SafeFileHandle _parent;
    private readonly FileIdentity _parentIdentity;
    private readonly SecurityIdentifier _operator;
    private readonly HashSet<string> _allowed;

    private MsiProtectedStaging(string directory, SafeFileHandle parent, SecurityIdentifier signingOperator)
    {
        _directory = directory;
        _parent = parent;
        _operator = signingOperator;
        _allowed = new(StringComparer.Ordinal)
        {
            signingOperator.Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value
        };
        _parentIdentity = Inspect(_parent, expectDirectory: true);
        VerifyDirectory();
    }

    internal static MsiProtectedStaging CreateNew(string directory)
    {
        if (!OperatingSystem.IsWindows() || Path.GetFullPath(directory) != directory ||
            Directory.Exists(directory) || File.Exists(directory)) throw new IOException();
        CheckAncestors(Path.GetDirectoryName(directory)!);
        var signingOperator = WindowsIdentity.GetCurrent().User ?? throw new IOException();
        var descriptor = IntPtr.Zero;
        var acl = $"O:{signingOperator.Value}G:{signingOperator.Value}D:P" +
            $"(A;OICI;FA;;;{signingOperator.Value})(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(acl, 1, out descriptor, out _)) throw new IOException();
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                Descriptor = descriptor
            };
            if (!CreateDirectory(directory, ref attributes)) throw new IOException();
        }
        finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
        var handle = CreateFile(directory, ReadAttributes, ShareReadWrite, IntPtr.Zero,
            OpenExisting, BackupSemantics | OpenReparse, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new IOException(); }
        try { return new MsiProtectedStaging(directory, handle, signingOperator); }
        catch { handle.Dispose(); throw; }
    }

    internal SafeFileHandle CreateNewMsi(string path)
    {
        VerifyDirectory();
        if (!string.Equals(Path.GetDirectoryName(path), _directory, StringComparison.OrdinalIgnoreCase) ||
            File.Exists(path) || Directory.Exists(path)) throw new IOException();
        var handle = CreateFile(path, Read | Write, ShareRead, IntPtr.Zero, CreateDispositionNew, OpenReparse, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new IOException(); }
        try { VerifyFile(path, handle); return handle; }
        catch { handle.Dispose(); throw; }
    }

    internal void VerifyDirectory()
    {
        CheckAncestors(_directory);
        if (Inspect(_parent, expectDirectory: true) != _parentIdentity ||
            !string.Equals(_parentIdentity.FinalPath, ExpectedFinal(_directory), StringComparison.OrdinalIgnoreCase))
            throw new IOException();
        VerifyAcl(new DirectoryInfo(_directory).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner),
            requireProtected: true);
    }

    internal FileIdentity VerifyFile(string path, SafeFileHandle handle)
    {
        VerifyDirectory();
        if (!string.Equals(Path.GetDirectoryName(path), _directory, StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException();
        var identity = Inspect(handle, expectDirectory: false);
        if (!string.Equals(identity.FinalPath, ExpectedFinal(path), StringComparison.OrdinalIgnoreCase)) throw new IOException();
        VerifyAcl(new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner),
            requireProtected: false);
        return identity;
    }

    private void VerifyAcl(FileSystemSecurity security, bool requireProtected)
    {
        if (requireProtected && !security.AreAccessRulesProtected) throw new IOException();
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            !string.Equals(owner.Value, _operator.Value, StringComparison.Ordinal))
            throw new IOException();
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        var found = new HashSet<string>(StringComparer.Ordinal);
        foreach (FileSystemAccessRule rule in rules)
        {
            var sid = ((SecurityIdentifier)rule.IdentityReference).Value;
            if (!_allowed.Contains(sid) || rule.AccessControlType != AccessControlType.Allow ||
                (rule.FileSystemRights & FileSystemRights.FullControl) != FileSystemRights.FullControl ||
                (requireProtected && rule.IsInherited)) throw new IOException();
            found.Add(sid);
        }
        if (!found.SetEquals(_allowed)) throw new IOException();
    }

    internal static FileIdentity Inspect(SafeFileHandle handle, bool expectDirectory)
    {
        if (!GetFileInformationByHandle(handle, out var info) ||
            ((info.Attributes & (uint)FileAttributes.Directory) != 0) != expectDirectory ||
            (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0) throw new IOException();
        var length = GetFinalPathNameByHandle(handle, null, 0, 0);
        if (length is 0 or > 32768) throw new IOException();
        var text = new StringBuilder((int)length + 1);
        var written = GetFinalPathNameByHandle(handle, text, (uint)text.Capacity, 0);
        if (written == 0 || written >= text.Capacity || !text.ToString().StartsWith("\\\\?\\", StringComparison.Ordinal))
            throw new IOException();
        return new(info.Volume, ((ulong)info.IndexHigh << 32) | info.IndexLow, text.ToString());
    }

    internal static void CheckAncestors(string path)
    {
        for (var directory = new DirectoryInfo(path); directory is not null; directory = directory.Parent)
            if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException();
    }
    private static string ExpectedFinal(string path) => "\\\\?\\" + path.TrimEnd(Path.DirectorySeparatorChar);
    public void Dispose() => _parent.Dispose();

    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr Descriptor;
        [MarshalAs(UnmanagedType.Bool)] internal bool InheritHandle;
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfoNative
    {
        internal uint Attributes;
        private uint _creationLow, _creationHigh, _accessLow, _accessHigh, _writeLow, _writeHigh;
        internal uint Volume;
        private uint _sizeHigh, _sizeLow, _links;
        internal uint IndexHigh, IndexLow;
    }
    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision,
        out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string path, ref SecurityAttributes attributes);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfoNative info);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder? path, uint length, uint flags);
}
