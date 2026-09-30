using System.Security.AccessControl;
using System.Security.Principal;

namespace Vantrel.Security.Service;

internal interface IOfflineUpdateFileOperations
{
    void CreateFixedDirectory(string path);
    FileAttributes GetAttributes(string path);
    void ApplyProtectedDirectoryAcl(string path, bool allowLocalService);
    void ApplyProtectedFileAcl(string path, bool allowLocalService);
    Task CopyFixedFileContentsAsync(FileStream source, FileStream destination, CancellationToken token);
    Task FlushFixedFileToDiskAsync(FileStream destination, CancellationToken token);
}

internal sealed class WindowsOfflineUpdateFileOperations : IOfflineUpdateFileOperations
{
    internal static readonly WindowsOfflineUpdateFileOperations Instance = new();
    private WindowsOfflineUpdateFileOperations() { }
    public void CreateFixedDirectory(string path) => Directory.CreateDirectory(path);
    public FileAttributes GetAttributes(string path) => File.GetAttributes(path);
    // Streams are borrowed for these awaited operations; storage retains ownership.
    public async Task CopyFixedFileContentsAsync(FileStream source, FileStream destination, CancellationToken token)
    {
        await source.CopyToAsync(destination, 65536, token);
    }
    public async Task FlushFixedFileToDiskAsync(FileStream destination, CancellationToken token)
    {
        await destination.FlushAsync(token);
        destination.Flush(flushToDisk: true);
    }
    public void ApplyProtectedDirectoryAcl(string path, bool allowLocalService)
    {
        if (!OperatingSystem.IsWindows()) return;
        var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
        AddRules(security, allowLocalService, true); new DirectoryInfo(path).SetAccessControl(security);
    }
    public void ApplyProtectedFileAcl(string path, bool allowLocalService)
    {
        if (!OperatingSystem.IsWindows()) return;
        var security = new FileSecurity(); security.SetAccessRuleProtection(true, false);
        AddRules(security, allowLocalService, false); new FileInfo(path).SetAccessControl(security);
    }
    private static void AddRules(FileSystemSecurity security, bool allowLocalService, bool inheritance)
    {
        var flags = inheritance ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None;
        if (allowLocalService) security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null), FileSystemRights.Modify, flags, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, flags, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, flags, PropagationFlags.None, AccessControlType.Allow));
    }
}
