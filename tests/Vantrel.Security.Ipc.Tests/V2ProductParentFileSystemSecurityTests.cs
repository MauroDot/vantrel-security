using System.ComponentModel;
using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class V2ProductParentFileSystemSecurityTests
{
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier LocalService =
        new(WellKnownSidType.LocalServiceSid, null);
    private static readonly SecurityIdentifier Users =
        new(WellKnownSidType.BuiltinUsersSid, null);
    private const FileSystemRights ReadAndExecute = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;
    private const InheritanceFlags ChildInheritance =
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    [TestMethod]
    public void Product_parent_descriptor_has_exact_protected_read_and_execute_contract()
    {
        var descriptor = V2ProductParentFileSystemSecurity.CreateDirectoryDescriptor();
        Assert.IsTrue(V2ProductParentFileSystemSecurity.ValidateDirectoryDescriptor(descriptor).IsMatch);
        Assert.IsTrue(descriptor.AreAccessRulesProtected);
        Assert.AreEqual(Administrators, descriptor.GetOwner(typeof(SecurityIdentifier)));

        var rules = Rules(descriptor);
        Assert.AreEqual(4, rules.Length);
        AssertRule(rules, Administrators, FileSystemRights.FullControl, ChildInheritance);
        AssertRule(rules, System, FileSystemRights.FullControl, ChildInheritance);
        AssertRule(rules, LocalService, ReadAndExecute, InheritanceFlags.None);
        AssertRule(rules, Users, ReadAndExecute, ChildInheritance);

        var mutation = FileSystemRights.WriteData | FileSystemRights.CreateFiles |
            FileSystemRights.CreateDirectories | FileSystemRights.AppendData |
            FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes |
            FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (var sid in new[] { LocalService, Users })
            Assert.AreEqual(0, (int)(rules.Single(rule => rule.IdentityReference.Equals(sid)).FileSystemRights & mutation));
    }

    [TestMethod]
    public void Product_parent_validation_rejects_owner_protection_and_every_extra_or_changed_ace()
    {
        var descriptor = V2ProductParentFileSystemSecurity.CreateDirectoryDescriptor();
        descriptor.SetOwner(System);
        AssertRejected(descriptor);

        descriptor = V2ProductParentFileSystemSecurity.CreateDirectoryDescriptor();
        descriptor.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
        AssertRejected(descriptor);

        descriptor = V2ProductParentFileSystemSecurity.CreateDirectoryDescriptor();
        descriptor.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.Write, AccessControlType.Allow));
        AssertRejected(descriptor);

        descriptor = V2ProductParentFileSystemSecurity.CreateDirectoryDescriptor();
        descriptor.AddAccessRule(new FileSystemAccessRule(LocalService,
            FileSystemRights.DeleteSubdirectoriesAndFiles, AccessControlType.Allow));
        AssertRejected(descriptor);

        descriptor = V2ProductParentFileSystemSecurity.CreateDirectoryDescriptor();
        descriptor.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.WriteData,
            AccessControlType.Deny));
        AssertRejected(descriptor);

        descriptor = V2ProductParentFileSystemSecurity.CreateDirectoryDescriptor();
        descriptor.RemoveAccessRuleAll(new FileSystemAccessRule(Users, ReadAndExecute,
            ChildInheritance, PropagationFlags.None, AccessControlType.Allow));
        descriptor.AddAccessRule(new FileSystemAccessRule(Users, ReadAndExecute,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        AssertRejected(descriptor);

        descriptor = V2ProductParentFileSystemSecurity.CreateDirectoryDescriptor();
        descriptor.RemoveAccessRuleAll(new FileSystemAccessRule(LocalService, ReadAndExecute,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        descriptor.AddAccessRule(new FileSystemAccessRule(LocalService, ReadAndExecute,
            ChildInheritance, PropagationFlags.None, AccessControlType.Allow));
        AssertRejected(descriptor);

        descriptor = V2ProductParentFileSystemSecurity.CreateDirectoryDescriptor();
        descriptor.RemoveAccessRuleAll(new FileSystemAccessRule(Users, ReadAndExecute,
            ChildInheritance, PropagationFlags.None, AccessControlType.Allow));
        descriptor.AddAccessRule(new FileSystemAccessRule(Users, ReadAndExecute,
            ChildInheritance, PropagationFlags.InheritOnly, AccessControlType.Allow));
        AssertRejected(descriptor);
    }

    [TestMethod]
    public void Protected_Service_child_contract_is_independent_of_inheritable_Users_parent_rule()
    {
        var parent = V2ProductParentFileSystemSecurity.CreateDirectoryDescriptor();
        var service = V2ServiceTreeFileSystemSecurity.CreateDirectoryDescriptor();
        var serviceFile = V2ServiceTreeFileSystemSecurity.CreateFileDescriptor();

        Assert.IsTrue(V2ProductParentFileSystemSecurity.ValidateDirectoryDescriptor(parent).IsMatch);
        Assert.IsTrue(V2ServiceTreeFileSystemSecurity.ValidateDirectoryDescriptor(service).IsMatch);
        Assert.IsTrue(V2ServiceTreeFileSystemSecurity.ValidateFileDescriptor(serviceFile).IsMatch);
        Assert.IsTrue(service.AreAccessRulesProtected);
        Assert.IsTrue(serviceFile.AreAccessRulesProtected);
        Assert.IsFalse(Rules(service).Any(rule => rule.IdentityReference.Equals(Users)));
        Assert.IsFalse(Rules(serviceFile).Any(rule => rule.IdentityReference.Equals(Users)));
        Assert.AreEqual(ReadAndExecute,
            Rules(service).Single(rule => rule.IdentityReference.Equals(LocalService)).FileSystemRights);
        Assert.AreEqual(ReadAndExecute,
            Rules(serviceFile).Single(rule => rule.IdentityReference.Equals(LocalService)).FileSystemRights);
    }

    [TestMethod]
    public void Fixed_production_parent_is_derived_from_installed_Service_root()
    {
        Assert.AreEqual(Path.GetDirectoryName(FixedUpdatePaths.InstalledServiceRoot),
            V2ProductParentFileSystemSecurity.ProductParentPath);
    }

    [TestMethod]
    public void Disposable_parent_validation_rejects_missing_wrong_type_and_bad_path()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("Windows retained-handle inspection is required.");
            return;
        }
        var root = NewDisposableTempPath();
        Assert.IsFalse(File.Exists(root) || Directory.Exists(root), "Missing-object fixture already exists.");
        var missing = Assert.ThrowsException<Win32Exception>(() =>
            V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(root, enforceAcl: false));
        Assert.IsTrue(missing.NativeErrorCode is ErrorFileNotFound or ErrorPathNotFound,
            "Missing-object validation failed for an unexpected native reason.");
        Assert.ThrowsException<IOException>(() =>
            V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(
                FixedUpdatePaths.InstalledServiceRoot, enforceAcl: false));

        ComponentInspectionNative.Metadata? created = null;
        try
        {
            using (var stream = new FileStream(root, FileMode.CreateNew, FileAccess.ReadWrite,
                       FileShare.None))
                created = ComponentInspectionNative.GetMetadata(stream.SafeFileHandle);
            using var fixture = ComponentInspectionNative.OpenProtected(root);
            var onDisk = ComponentInspectionNative.GetMetadata(fixture);
            Assert.AreEqual(created.Value.VolumeSerial, onDisk.VolumeSerial);
            Assert.AreEqual(created.Value.Identity, onDisk.Identity);
            Assert.IsFalse(onDisk.IsDirectory || onDisk.IsReparsePoint,
                "Wrong-type fixture was not an ordinary file.");
            Assert.ThrowsException<IOException>(() =>
                V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(root, enforceAcl: false));
        }
        finally
        {
            if (created is { } identity)
                DeleteCreatedDisposableObject(root, identity, directory: false);
        }
    }

    [TestMethod]
    public void Disposable_parent_retains_handle_and_rejects_wrong_path_or_disposal()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("Windows retained-handle inspection is required.");
            return;
        }
        var root = NewDisposableTempPath();
        ComponentInspectionNative.Metadata? created = null;
        try
        {
            using var handle = V2ProductParentFileSystemSecurity.CreateNewDisposableDirectory(root,
                enforceAcl: false);
            created = ComponentInspectionNative.GetMetadata(handle);
            V2ProductParentFileSystemSecurity.RequireValidatedDisposableHandle(handle, root,
                enforceAcl: false);
            Assert.ThrowsException<IOException>(() =>
                V2ProductParentFileSystemSecurity.RequireValidatedDisposableHandle(handle,
                    NewDisposableTempPath(), enforceAcl: false));
            Assert.ThrowsException<IOException>(() =>
                V2ProductParentFileSystemSecurity.CreateNewDisposableDirectory(root, enforceAcl: false));
            handle.Dispose();
            Assert.ThrowsException<IOException>(() =>
                V2ProductParentFileSystemSecurity.RequireValidatedDisposableHandle(handle, root,
                    enforceAcl: false));
        }
        finally
        {
            if (created is { } identity)
                DeleteCreatedDisposableObject(root, identity, directory: true);
        }
    }

    [TestMethod]
    public void Disposable_parent_reparse_leaf_fails_closed()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("Windows reparse inspection is required.");
            return;
        }
        var root = NewDisposableTempPath();
        var target = NewDisposableTempPath();
        ComponentInspectionNative.Metadata? createdTarget = null;
        try
        {
            using (var targetHandle = V2ProductParentFileSystemSecurity.CreateNewDisposableDirectory(
                       target, enforceAcl: false))
                createdTarget = ComponentInspectionNative.GetMetadata(targetHandle);
            try { Directory.CreateSymbolicLink(root, target); }
            catch (Exception error) when (error.HResult == PrivilegeNotHeldHResult &&
                (error is IOException or UnauthorizedAccessException or Win32Exception))
            {
                Assert.Inconclusive("Symbolic-link creation privilege is unavailable.");
                return;
            }
            using var linkHandle = ComponentInspectionNative.OpenProtected(root, directory: true);
            var link = ComponentInspectionNative.GetMetadata(linkHandle);
            Assert.IsTrue(link.IsDirectory && link.IsReparsePoint,
                "Reparse fixture was not created as a directory symlink.");
            Assert.ThrowsException<IOException>(() =>
                V2ProductParentFileSystemSecurity.OpenValidatedDisposableDirectory(root,
                    enforceAcl: false));
        }
        finally
        {
            // The existing handle-bound deletion primitive refuses reparse points. Preserve
            // this unique link as reviewable residue instead of deleting by pathname.
            if (createdTarget is { } identity)
                DeleteCreatedDisposableObject(target, identity, directory: true);
        }
    }

    private static string NewDisposableTempPath() =>
        Path.Combine(Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath())),
            "Vantrel.ParentAclTest." + Guid.NewGuid().ToString("N"));

    private static FileSystemAccessRule[] Rules(FileSystemSecurity descriptor) =>
        descriptor.GetAccessRules(includeExplicit: true, includeInherited: true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();

    private static void AssertRule(FileSystemAccessRule[] rules, SecurityIdentifier sid,
        FileSystemRights rights, InheritanceFlags inheritance)
    {
        var rule = rules.Single(item => item.IdentityReference.Equals(sid));
        Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
        Assert.AreEqual(rights, rule.FileSystemRights);
        Assert.AreEqual(inheritance, rule.InheritanceFlags);
        Assert.AreEqual(PropagationFlags.None, rule.PropagationFlags);
        Assert.IsFalse(rule.IsInherited);
    }

    private static void AssertRejected(DirectorySecurity descriptor) =>
        Assert.IsFalse(V2ProductParentFileSystemSecurity.ValidateDirectoryDescriptor(descriptor).IsMatch);

    private static void DeleteCreatedDisposableObject(string path,
        ComponentInspectionNative.Metadata expected, bool directory)
    {
        if (expected.IsReparsePoint || expected.IsDirectory != directory)
            throw new IOException("Disposable fixture identity is unsafe for cleanup.");
        using var handle = ComponentInspectionNative.OpenProtectedForDeletion(path, directory);
        if (directory)
        {
            V2ProductParentFileSystemSecurity.RequireValidatedDisposableHandle(handle, path,
                enforceAcl: false);
            if (Directory.EnumerateFileSystemEntries(path).Any())
                throw new IOException("Disposable directory contains unexpected residue.");
        }
        var current = ComponentInspectionNative.GetMetadata(handle);
        if (current.IsReparsePoint || current.IsDirectory != expected.IsDirectory ||
            current.VolumeSerial != expected.VolumeSerial || current.Identity != expected.Identity)
            throw new IOException("Disposable fixture identity changed; residue preserved.");
        ComponentInspectionNative.MarkValidatedObjectForDeletion(handle, current, path, directory);
    }
}
