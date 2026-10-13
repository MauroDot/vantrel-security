using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class V2ServiceTreeFileSystemSecurityTests
{
    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalService =
        new(WellKnownSidType.LocalServiceSid, null);
    private static readonly SecurityIdentifier Users =
        new(WellKnownSidType.BuiltinUsersSid, null);

    [TestMethod]
    public void Service_tree_descriptors_allow_local_service_to_read_and_execute_only()
    {
        var directory = V2ServiceTreeFileSystemSecurity.CreateDirectoryDescriptor();
        var file = V2ServiceTreeFileSystemSecurity.CreateFileDescriptor();

        Assert.IsTrue(V2ServiceTreeFileSystemSecurity.ValidateDirectoryDescriptor(directory).IsMatch);
        Assert.IsTrue(V2ServiceTreeFileSystemSecurity.ValidateFileDescriptor(file).IsMatch);
        Assert.IsTrue(directory.AreAccessRulesProtected);
        Assert.IsTrue(file.AreAccessRulesProtected);
        Assert.AreEqual(Administrators, directory.GetOwner(typeof(SecurityIdentifier)));
        Assert.AreEqual(Administrators, file.GetOwner(typeof(SecurityIdentifier)));

        var forbidden = FileSystemRights.WriteData | FileSystemRights.AppendData |
            FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes |
            FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (var descriptor in new FileSystemSecurity[] { directory, file })
        {
            var rules = descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>().ToArray();
            Assert.AreEqual(3, rules.Length);
            var localService = rules.Single(rule => rule.IdentityReference.Equals(LocalService));
            Assert.AreEqual(AccessControlType.Allow, localService.AccessControlType);
            Assert.AreEqual(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
                localService.FileSystemRights);
            Assert.AreEqual(0, (int)(localService.FileSystemRights & forbidden));
            Assert.IsFalse(rules.Any(rule => rule.IdentityReference.Equals(Users)));
        }
    }

    [TestMethod]
    public void Service_tree_descriptor_validation_rejects_extra_or_writable_aces()
    {
        var directory = V2ServiceTreeFileSystemSecurity.CreateDirectoryDescriptor();
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        directory.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Write,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        Assert.IsFalse(V2ServiceTreeFileSystemSecurity.ValidateDirectoryDescriptor(directory).IsMatch);

        directory = V2ServiceTreeFileSystemSecurity.CreateDirectoryDescriptor();
        directory.RemoveAccessRuleAll(new FileSystemAccessRule(LocalService, FileSystemRights.ReadAndExecute,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        directory.AddAccessRule(new FileSystemAccessRule(LocalService, FileSystemRights.Modify,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        Assert.IsFalse(V2ServiceTreeFileSystemSecurity.ValidateDirectoryDescriptor(directory).IsMatch);

        var file = V2ServiceTreeFileSystemSecurity.CreateFileDescriptor();
        file.RemoveAccessRuleAll(new FileSystemAccessRule(LocalService, FileSystemRights.ReadAndExecute,
            AccessControlType.Allow));
        file.AddAccessRule(new FileSystemAccessRule(LocalService, FileSystemRights.Modify,
            AccessControlType.Allow));
        Assert.IsFalse(V2ServiceTreeFileSystemSecurity.ValidateFileDescriptor(file).IsMatch);

        file = V2ServiceTreeFileSystemSecurity.CreateFileDescriptor();
        file.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
        Assert.IsFalse(V2ServiceTreeFileSystemSecurity.ValidateFileDescriptor(file).IsMatch);
    }

    [TestMethod]
    public void Disposable_service_tree_creation_is_create_new_and_handle_checked()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("Windows native handle inspection is required.");
            return;
        }

        var parent = Path.Combine(Path.GetTempPath(), "Vantrel.ServiceTreeAclTest." + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(parent);
        try
        {
            var root = Path.Combine(parent, "Service");
            using (V2ServiceTreeFileSystemSecurity.CreateNewDirectory(root, enforceAcl: false))
            {
                using var nested = V2ServiceTreeFileSystemSecurity.CreateNewDirectory(
                    Path.Combine(root, "nested"), enforceAcl: false);
                Assert.ThrowsException<IOException>(() =>
                    V2ServiceTreeFileSystemSecurity.CreateNewDirectory(root, enforceAcl: false));
            }

            var filePath = Path.Combine(root, "nested", "runtime.dll");
            using (var stream = V2ServiceTreeFileSystemSecurity.CreateNewFile(filePath, enforceAcl: false))
            {
                stream.WriteByte(0x42);
                stream.Flush(flushToDisk: true);
            }
            using (var checkedFile = V2ServiceTreeFileSystemSecurity.OpenValidatedFile(filePath,
                enforceAcl: false)) { }
            Assert.ThrowsException<IOException>(() =>
                V2ServiceTreeFileSystemSecurity.CreateNewFile(filePath, enforceAcl: false));
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    [TestMethod]
    [TestCategory("AdministratorOnly")]
    public void Service_tree_acl_round_trip_on_disk_requires_administrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("Windows is required for Service-tree ACL validation.");
            return;
        }
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Assert.Inconclusive("An elevated Administrator token is required for Service-tree ACL validation.");
            return;
        }

        var parent = Path.Combine(Path.GetTempPath(), "Vantrel.ServiceTreeAclTest." + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(parent);
        try
        {
            var root = Path.Combine(parent, "Service");
            using (V2ServiceTreeFileSystemSecurity.CreateNewDirectory(root)) { }
            var nested = Path.Combine(root, "nested");
            using (V2ServiceTreeFileSystemSecurity.CreateNewDirectory(nested)) { }
            foreach (var name in new[]
            {
                "runtime.dll", "Vantrel.Security.TrustedManifest", "Vantrel.Security.ReleaseMetadata"
            })
            {
                var file = Path.Combine(nested, name);
                using (var stream = V2ServiceTreeFileSystemSecurity.CreateNewFile(file))
                {
                    stream.WriteByte(0x42);
                    stream.Flush(flushToDisk: true);
                }
                using var handle = V2ServiceTreeFileSystemSecurity.OpenValidatedFile(file);
                V2ServiceTreeFileSystemSecurity.RequireFileAcl(handle);
            }
            foreach (var path in new[] { root, nested })
            {
                using var handle = V2ServiceTreeFileSystemSecurity.OpenValidatedDirectory(path);
                V2ServiceTreeFileSystemSecurity.RequireDirectoryAcl(handle);
            }
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }
}
