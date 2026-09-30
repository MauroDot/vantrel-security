using System.Security.AccessControl;
using System.Security;
using System.Security.Principal;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class UpdateFilesystemSecurityTests
{
    private const string FixtureVariable = "KESTERMERE_ACL_PROVISION_FIXTURE";
    private const string TransactionId = "0123456789abcdef0123456789abcdef";
    private const string BackupId = "fedcba9876543210fedcba9876543210";
    private const string TransactionFileName = "file-only-inheritance-transaction-v1.bin";
    private const string TransactionDirectoryName = "file-only-inheritance-transaction-v1.dir";
    private const string PolicyFileName = "file-only-inheritance-policy-v1.bin";
    private const string PolicyDirectoryName = "file-only-inheritance-policy-v1.dir";
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier LocalService = new(WellKnownSidType.LocalServiceSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    [DataTestMethod]
    [DataRow((int)UpdateDirectoryRole.ProductRoot, false, false, false)]
    [DataRow((int)UpdateDirectoryRole.UpdatesRoot, false, false, false)]
    [DataRow((int)UpdateDirectoryRole.TransactionsRoot, true, false, true)]
    [DataRow((int)UpdateDirectoryRole.TransactionDirectory, false, true, false)]
    [DataRow((int)UpdateDirectoryRole.PrivateCandidateDirectory, false, true, false)]
    [DataRow((int)UpdateDirectoryRole.BackupsRoot, false, true, false)]
    [DataRow((int)UpdateDirectoryRole.FixedBackupDirectory, false, true, false)]
    [DataRow((int)UpdateDirectoryRole.ReleasePolicyRoot, true, false, true)]
    public void Structural_role_has_exact_protected_descriptor(int roleValue, bool createsFiles, bool noLocalService,
        bool hasMutableFileInheritance)
    {
        var role = (UpdateDirectoryRole)roleValue;
        var descriptor = UpdateFilesystemSecurity.CreateDirectoryDescriptor(role);
        Assert.IsTrue(UpdateFilesystemSecurity.ValidateDirectoryDescriptor(role, descriptor).IsMatch);
        Assert.AreEqual(Administrators, descriptor.GetOwner(typeof(SecurityIdentifier)));
        Assert.IsTrue(descriptor.AreAccessRulesProtected);
        var rules = Rules(descriptor);
        AssertFullControl(rules, Administrators);
        AssertFullControl(rules, System);
        var local = rules.Where(rule => rule.IdentityReference.Equals(LocalService)).ToArray();
        Assert.AreEqual(noLocalService ? 0 : hasMutableFileInheritance ? 2 : 1, local.Length);
        if (!noLocalService)
        {
            var direct = local.Single(rule => rule.InheritanceFlags == InheritanceFlags.None &&
                rule.PropagationFlags == PropagationFlags.None);
            Assert.AreEqual(createsFiles, direct.FileSystemRights.HasFlag(FileSystemRights.CreateFiles));
            Assert.IsFalse(direct.FileSystemRights.HasFlag(FileSystemRights.CreateDirectories));
            AssertNoStructuralMutation(direct.FileSystemRights);
        }
        if (hasMutableFileInheritance)
        {
            var fileOnly = local.Single(rule => rule.InheritanceFlags == InheritanceFlags.ObjectInherit &&
                rule.PropagationFlags == PropagationFlags.InheritOnly);
            Assert.AreEqual(AccessControlType.Allow, fileOnly.AccessControlType);
            Assert.IsFalse(fileOnly.IsInherited);
            Assert.AreEqual(MutableFileRights, fileOnly.FileSystemRights);
        }
        Assert.IsFalse(rules.Any(rule => rule.IdentityReference.Equals(Users) && HasWrite(rule.FileSystemRights)));
    }

    [TestMethod]
    public void LocalService_file_inheritance_is_limited_to_mutable_parent_direct_files()
    {
        foreach (var role in new[] { UpdateDirectoryRole.ProductRoot, UpdateDirectoryRole.UpdatesRoot })
        {
            var local = Rules(UpdateFilesystemSecurity.CreateDirectoryDescriptor(role))
                .Single(rule => rule.IdentityReference.Equals(LocalService));
            Assert.AreEqual(InheritanceFlags.None, local.InheritanceFlags, role.ToString());
            Assert.AreEqual(PropagationFlags.None, local.PropagationFlags, role.ToString());
        }
        foreach (var role in new[] { UpdateDirectoryRole.TransactionsRoot, UpdateDirectoryRole.ReleasePolicyRoot })
        {
            var local = Rules(UpdateFilesystemSecurity.CreateDirectoryDescriptor(role))
                .Where(rule => rule.IdentityReference.Equals(LocalService)).ToArray();
            Assert.AreEqual(2, local.Length, role.ToString());
            var direct = local.Single(rule => rule.InheritanceFlags == InheritanceFlags.None);
            Assert.AreEqual(PropagationFlags.None, direct.PropagationFlags, role.ToString());
            AssertNoStructuralMutation(direct.FileSystemRights);
            var fileOnly = local.Single(rule => rule.InheritanceFlags == InheritanceFlags.ObjectInherit);
            Assert.AreEqual(PropagationFlags.InheritOnly, fileOnly.PropagationFlags, role.ToString());
            Assert.AreEqual(MutableFileRights, fileOnly.FileSystemRights, role.ToString());
            Assert.IsFalse(fileOnly.InheritanceFlags.HasFlag(InheritanceFlags.ContainerInherit), role.ToString());
        }
        foreach (var role in new[] { UpdateDirectoryRole.TransactionDirectory, UpdateDirectoryRole.PrivateCandidateDirectory,
                     UpdateDirectoryRole.BackupsRoot, UpdateDirectoryRole.FixedBackupDirectory })
            Assert.IsFalse(Rules(UpdateFilesystemSecurity.CreateDirectoryDescriptor(role))
                .Any(rule => rule.IdentityReference.Equals(LocalService)), role.ToString());
    }

    [TestMethod]
    public void Provisioned_mutable_file_descriptor_requires_Administrators_owner_and_exact_DACL()
    {
        var descriptor = UpdateFilesystemSecurity.CreateProvisionedMutableFileDescriptor();
        Assert.IsTrue(UpdateFilesystemSecurity.ValidateProvisionedMutableFileDescriptor(descriptor).IsMatch);
        Assert.IsFalse(UpdateFilesystemSecurity.ValidateLocalServiceReplacedMutableFileDescriptor(descriptor).IsMatch);
        Assert.AreEqual(Administrators, descriptor.GetOwner(typeof(SecurityIdentifier)));
        Assert.IsTrue(descriptor.AreAccessRulesProtected);
        var rules = Rules(descriptor);
        AssertFullControl(rules, Administrators);
        AssertFullControl(rules, System);
        var local = rules.Single(rule => rule.IdentityReference.Equals(LocalService));
        Assert.AreEqual(MutableFileRights, local.FileSystemRights);
        Assert.IsFalse(local.FileSystemRights.HasFlag(FileSystemRights.TakeOwnership));
        Assert.IsFalse(local.FileSystemRights.HasFlag(FileSystemRights.ExecuteFile));
        Assert.AreEqual(InheritanceFlags.None, local.InheritanceFlags);
        Assert.AreEqual(PropagationFlags.None, local.PropagationFlags);
    }

    [TestMethod]
    public void LocalService_replaced_mutable_file_descriptor_requires_LocalService_owner_and_exact_DACL()
    {
        var descriptor = UpdateFilesystemSecurity.CreateMutableFileDaclDescriptor();
        descriptor.SetOwner(LocalService);
        Assert.IsTrue(UpdateFilesystemSecurity.ValidateLocalServiceReplacedMutableFileDescriptor(descriptor).IsMatch);
        Assert.IsFalse(UpdateFilesystemSecurity.ValidateProvisionedMutableFileDescriptor(descriptor).IsMatch);

        var thirdOwner = UpdateFilesystemSecurity.CreateMutableFileDaclDescriptor();
        thirdOwner.SetOwner(Users);
        Assert.IsFalse(UpdateFilesystemSecurity.ValidateProvisionedMutableFileDescriptor(thirdOwner).IsMatch);
        Assert.IsFalse(UpdateFilesystemSecurity.ValidateLocalServiceReplacedMutableFileDescriptor(thirdOwner).IsMatch);
    }

    [TestMethod]
    public void Both_mutable_file_owner_states_reject_canonical_DACL_relaxation_or_shape_changes()
    {
        foreach (var owner in new[] { Administrators, LocalService })
        {
            Func<FileSecurity, UpdateDescriptorValidation> validate = owner.Equals(Administrators)
                ? UpdateFilesystemSecurity.ValidateProvisionedMutableFileDescriptor
                : UpdateFilesystemSecurity.ValidateLocalServiceReplacedMutableFileDescriptor;

            var inherited = UpdateFilesystemSecurity.CreateMutableFileDaclDescriptor();
            inherited.SetOwner(owner);
            inherited.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);
            Assert.IsFalse(validate(inherited).IsMatch);

            var extraSid = UpdateFilesystemSecurity.CreateMutableFileDaclDescriptor();
            extraSid.SetOwner(owner);
            extraSid.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Read, AccessControlType.Allow));
            Assert.IsFalse(validate(extraSid).IsMatch);

            var deny = UpdateFilesystemSecurity.CreateMutableFileDaclDescriptor();
            deny.SetOwner(owner);
            deny.AddAccessRule(new FileSystemAccessRule(LocalService, FileSystemRights.Read, AccessControlType.Deny));
            Assert.IsFalse(validate(deny).IsMatch);

            var broader = UpdateFilesystemSecurity.CreateMutableFileDaclDescriptor();
            broader.SetOwner(owner);
            broader.AddAccessRule(new FileSystemAccessRule(LocalService, FileSystemRights.TakeOwnership, AccessControlType.Allow));
            Assert.IsFalse(validate(broader).IsMatch);
        }
    }

    [TestMethod]
    public void Unexpected_normalized_or_privileged_right_is_rejected()
    {
        var descriptor = UpdateFilesystemSecurity.CreateDirectoryDescriptor(UpdateDirectoryRole.TransactionsRoot);
        descriptor.AddAccessRule(new FileSystemAccessRule(LocalService, FileSystemRights.Delete, AccessControlType.Allow));
        var result = UpdateFilesystemSecurity.ValidateDirectoryDescriptor(UpdateDirectoryRole.TransactionsRoot, descriptor);
        Assert.IsFalse(result.IsMatch);
        Assert.IsNotNull(result.Mismatch);
    }

    [TestMethod, TestCategory("ManualAclHarness"), DoNotParallelize]
    public void Administrator_only_direct_child_files_inherit_only_the_LocalService_mutable_file_rule()
    {
        ManualAclHarnessGate.RequirePhase("filesystem-inheritance");
        RequireAdministrator();
        var rawFixture = Environment.GetEnvironmentVariable(FixtureVariable) ??
            throw new InvalidOperationException("A disposable Program Files fixture is required.");
        var fixtureRoot = ValidateFreshFixturePath(rawFixture);
        var provisioner = new UpdateFilesystemProvisioner(fixtureRoot);
        ProvisionedUpdateFilesystem? fixture = null;
        try
        {
            fixture = provisioner.ProvisionDisposableFixture(TransactionId, BackupId);
            AssertStructuralDirectories(fixture);
            Assert.IsTrue(UpdateFilesystemSecurity.ValidateProvisionedMutableFileOnDisk(new FileInfo(fixture.JournalFile)).IsMatch);
            Assert.IsTrue(UpdateFilesystemSecurity.ValidateProvisionedMutableFileOnDisk(new FileInfo(fixture.PolicyFile)).IsMatch);

            AssertDirectFileOnlyInheritance(fixture.ProductRoot, fixture.TransactionsRoot, UpdateDirectoryRole.TransactionsRoot,
                TransactionFileName, TransactionDirectoryName);
            AssertDirectFileOnlyInheritance(fixture.ProductRoot, fixture.ReleasePolicyRoot, UpdateDirectoryRole.ReleasePolicyRoot,
                PolicyFileName, PolicyDirectoryName);

            AssertFixtureInventory(fixture, includeInheritanceObjects: true);
            DeleteKnownFile(fixture.ProductRoot, Path.Combine(fixture.TransactionsRoot, TransactionFileName));
            DeleteKnownDirectory(fixture.ProductRoot, Path.Combine(fixture.TransactionsRoot, TransactionDirectoryName));
            DeleteKnownFile(fixture.ProductRoot, Path.Combine(fixture.ReleasePolicyRoot, PolicyFileName));
            DeleteKnownDirectory(fixture.ProductRoot, Path.Combine(fixture.ReleasePolicyRoot, PolicyDirectoryName));
            AssertFixtureInventory(fixture, includeInheritanceObjects: false);
            provisioner.CleanupDisposableFixture(fixture);
            fixture = null;
            Assert.IsFalse(Directory.Exists(fixtureRoot));
        }
        catch (Exception exception) when (fixture is not null)
        {
            throw new IOException("Filesystem-inheritance fixture preserved for Administrator review: " + fixture.ProductRoot,
                exception);
        }
    }

    [TestMethod, DoNotParallelize]
    public void Filesystem_inheritance_phase_gate_skips_before_fixture_variable_is_read()
    {
        var previous = Environment.GetEnvironmentVariable("KESTERMERE_ACL_MANUAL_PHASE");
        try
        {
            Environment.SetEnvironmentVariable("KESTERMERE_ACL_MANUAL_PHASE", null);
            Assert.ThrowsException<AssertInconclusiveException>(() =>
                ManualAclHarnessGate.RequirePhase("filesystem-inheritance"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("KESTERMERE_ACL_MANUAL_PHASE", previous);
        }
    }

    [TestMethod]
    public void Filesystem_inheritance_fixture_path_rejects_invalid_or_existing_identity_before_creation()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        Assert.ThrowsException<ArgumentException>(() => ValidateFreshFixturePath(Path.Combine(Path.GetTempPath(),
            "Kestermere Security ACL Provision-0123456789abcdef0123456789abcdef")));
        Assert.ThrowsException<ArgumentException>(() => ValidateFreshFixturePath(Path.Combine(programFiles,
            "Kestermere Security ACL Provision-not-hex")));
        Assert.ThrowsException<IOException>(() => ValidateFreshFixturePath(Path.Combine(programFiles,
            "Kestermere Security ACL Provision-0123456789abcdef0123456789abcdef"), _ => true));
    }

    [TestMethod]
    public void Filesystem_inheritance_administrator_verification_fails_closed()
    {
        Assert.ThrowsException<UnauthorizedAccessException>(() => RequireAdministrator(() => false));
        Assert.ThrowsException<UnauthorizedAccessException>(() => RequireAdministrator(() =>
            throw new SecurityException("Token membership is unavailable.")));
    }

    [TestMethod]
    public void Filesystem_inheritance_live_test_is_non_parallel()
    {
        var method = typeof(UpdateFilesystemSecurityTests).GetMethod(
            nameof(Administrator_only_direct_child_files_inherit_only_the_LocalService_mutable_file_rule));
        Assert.IsNotNull(method);
        Assert.IsTrue(method.GetCustomAttributes(typeof(DoNotParallelizeAttribute), inherit: false).Any());
    }

    [TestMethod]
    public void Descriptor_validation_rejects_mutable_file_inheritance_broadening_or_loss_of_protection()
    {
        AssertInvalidInheritedFileRule(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.InheritOnly, MutableFileRights);
        AssertInvalidInheritedFileRule(InheritanceFlags.ObjectInherit, PropagationFlags.None, MutableFileRights);
        AssertInvalidInheritedFileRule(InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly,
            MutableFileRights | FileSystemRights.TakeOwnership);

        var extraSid = UpdateFilesystemSecurity.CreateDirectoryDescriptor(UpdateDirectoryRole.TransactionsRoot);
        extraSid.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        Assert.IsFalse(UpdateFilesystemSecurity.ValidateDirectoryDescriptor(UpdateDirectoryRole.TransactionsRoot, extraSid).IsMatch);

        var unprotected = UpdateFilesystemSecurity.CreateDirectoryDescriptor(UpdateDirectoryRole.TransactionsRoot);
        unprotected.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);
        Assert.IsFalse(UpdateFilesystemSecurity.ValidateDirectoryDescriptor(UpdateDirectoryRole.TransactionsRoot, unprotected).IsMatch);

        AssertDescriptorRejectsMissingRequiredFullControl(Administrators);
        AssertDescriptorRejectsMissingRequiredFullControl(System);
    }

    [TestMethod]
    public void Inherited_directory_carrier_is_accepted_only_as_file_only_inherit_only_LocalService_rule()
    {
        Assert.IsTrue(IsExpectedInheritedDirectoryCarrier(LocalService, AccessControlType.Allow, MutableFileRights,
            isInherited: true, InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly));
        Assert.IsFalse(IsExpectedInheritedDirectoryCarrier(LocalService, AccessControlType.Allow, MutableFileRights,
            isInherited: false, InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly));
        Assert.IsFalse(IsExpectedInheritedDirectoryCarrier(LocalService, AccessControlType.Allow, MutableFileRights,
            isInherited: true, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly));
        Assert.IsFalse(IsExpectedInheritedDirectoryCarrier(LocalService, AccessControlType.Allow, MutableFileRights,
            isInherited: true, InheritanceFlags.ObjectInherit, PropagationFlags.None));
        Assert.IsFalse(IsExpectedInheritedDirectoryCarrier(LocalService, AccessControlType.Allow,
            MutableFileRights | FileSystemRights.TakeOwnership, isInherited: true,
            InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly));
        Assert.IsFalse(IsExpectedInheritedDirectoryCarrier(LocalService, AccessControlType.Deny, MutableFileRights,
            isInherited: true, InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly));
        Assert.IsFalse(IsExpectedInheritedDirectoryCarrier(Users, AccessControlType.Allow, MutableFileRights,
            isInherited: true, InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly));
    }

    [TestMethod]
    public void Incorrect_owner_is_rejected_without_descriptor_mutation()
    {
        var descriptor = UpdateFilesystemSecurity.CreateDirectoryDescriptor(UpdateDirectoryRole.UpdatesRoot);
        descriptor.SetOwner(Users);
        var before = descriptor.GetSecurityDescriptorBinaryForm();
        var result = UpdateFilesystemSecurity.ValidateDirectoryDescriptor(UpdateDirectoryRole.UpdatesRoot, descriptor);
        Assert.IsFalse(result.IsMatch);
        CollectionAssert.AreEqual(before, descriptor.GetSecurityDescriptorBinaryForm());
    }

    [TestMethod]
    public void Mismatched_actual_descriptor_is_rejected_without_mutation()
    {
        var root = Path.Combine(Path.GetTempPath(), "kestermere-acl-contract-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var directory = new DirectoryInfo(root);
            var before = directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                .GetSecurityDescriptorBinaryForm();
            var result = UpdateFilesystemSecurity.ValidateDirectoryOnDisk(UpdateDirectoryRole.TransactionsRoot, directory);
            var after = directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                .GetSecurityDescriptorBinaryForm();
            Assert.IsFalse(result.IsMatch);
            CollectionAssert.AreEqual(before, after);
        }
        finally { Directory.Delete(root); }
    }

    private static FileSystemAccessRule[] Rules(FileSystemSecurity descriptor) =>
        descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();

    private static void AssertFullControl(IEnumerable<FileSystemAccessRule> rules, SecurityIdentifier sid)
    {
        var rule = rules.Single(item => item.IdentityReference.Equals(sid));
        Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
        Assert.AreEqual(FileSystemRights.FullControl, rule.FileSystemRights);
        Assert.IsFalse(rule.IsInherited);
    }

    private static void AssertNoStructuralMutation(FileSystemRights rights)
    {
        Assert.IsFalse(rights.HasFlag(FileSystemRights.Delete));
        Assert.IsFalse(rights.HasFlag(FileSystemRights.DeleteSubdirectoriesAndFiles));
        Assert.IsFalse(rights.HasFlag(FileSystemRights.ChangePermissions));
        Assert.IsFalse(rights.HasFlag(FileSystemRights.TakeOwnership));
    }

    private static bool HasWrite(FileSystemRights rights) => (rights & (FileSystemRights.Write | FileSystemRights.Modify |
        FileSystemRights.FullControl | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) != 0;

    private static readonly FileSystemRights MutableFileRights = FileSystemRights.Read | FileSystemRights.Write |
        FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.Synchronize;
    private static readonly FileSystemRights LocalServiceCreateFileRights = FileSystemRights.ReadAndExecute |
        FileSystemRights.Synchronize | FileSystemRights.CreateFiles;

    private static void AssertInvalidInheritedFileRule(InheritanceFlags inheritance, PropagationFlags propagation,
        FileSystemRights rights)
    {
        var descriptor = UpdateFilesystemSecurity.CreateDirectoryDescriptor(UpdateDirectoryRole.TransactionsRoot);
        var existing = Rules(descriptor).Single(rule => rule.IdentityReference.Equals(LocalService) &&
            rule.InheritanceFlags == InheritanceFlags.ObjectInherit && rule.PropagationFlags == PropagationFlags.InheritOnly);
        descriptor.RemoveAccessRuleSpecific(existing);
        descriptor.AddAccessRule(new FileSystemAccessRule(LocalService, rights, inheritance, propagation, AccessControlType.Allow));
        Assert.IsFalse(UpdateFilesystemSecurity.ValidateDirectoryDescriptor(UpdateDirectoryRole.TransactionsRoot, descriptor).IsMatch);
    }

    private static void AssertDescriptorRejectsMissingRequiredFullControl(SecurityIdentifier sid)
    {
        var descriptor = UpdateFilesystemSecurity.CreateDirectoryDescriptor(UpdateDirectoryRole.TransactionsRoot);
        var rule = Rules(descriptor).Single(item => item.IdentityReference.Equals(sid));
        descriptor.RemoveAccessRuleSpecific(rule);
        Assert.IsFalse(UpdateFilesystemSecurity.ValidateDirectoryDescriptor(UpdateDirectoryRole.TransactionsRoot, descriptor).IsMatch);
    }

    private static void RequireAdministrator() => RequireAdministrator(() =>
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    });

    private static void RequireAdministrator(Func<bool> roleVerification)
    {
        try
        {
            if (!roleVerification())
                throw new UnauthorizedAccessException("An enabled Administrator token is required.");
        }
        catch (SecurityException exception)
        {
            throw new UnauthorizedAccessException("The Administrator token could not be verified.", exception);
        }
    }

    private static string ValidateFreshFixturePath(string raw, Func<string, bool>? exists = null)
    {
        if (string.IsNullOrWhiteSpace(raw) || !Path.IsPathFullyQualified(raw))
            throw new ArgumentException("A disposable Program Files fixture is required.", nameof(raw));
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(raw));
        var programFiles = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
        var name = Path.GetFileName(root);
        if (!string.Equals(Path.GetDirectoryName(root), programFiles, StringComparison.OrdinalIgnoreCase) ||
            !IsExactFixtureName(name))
            throw new ArgumentException("The fixture must be a dedicated Program Files test child.", nameof(raw));
        exists ??= path => Directory.Exists(path) || File.Exists(path);
        if (exists(root)) throw new IOException("The disposable fixture already exists.");
        return root;
    }

    private static bool IsExactFixtureName(string name)
    {
        const string prefix = "Kestermere Security ACL Provision-";
        if (!name.StartsWith(prefix, StringComparison.Ordinal) || name.Length != prefix.Length + 32) return false;
        return name[prefix.Length..].All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
    }

    private static void AssertStructuralDirectories(ProvisionedUpdateFilesystem fixture)
    {
        foreach (var (path, role) in new[]
                 {
                     (fixture.ProductRoot, UpdateDirectoryRole.ProductRoot),
                     (fixture.UpdatesRoot, UpdateDirectoryRole.UpdatesRoot),
                     (fixture.TransactionsRoot, UpdateDirectoryRole.TransactionsRoot),
                     (fixture.TransactionRoot, UpdateDirectoryRole.TransactionDirectory),
                     (fixture.PrivateCandidateRoot, UpdateDirectoryRole.PrivateCandidateDirectory),
                     (fixture.BackupsRoot, UpdateDirectoryRole.BackupsRoot),
                     (fixture.FixedBackupRoot, UpdateDirectoryRole.FixedBackupDirectory),
                     (fixture.ReleasePolicyRoot, UpdateDirectoryRole.ReleasePolicyRoot)
                 })
        {
            EnsureContainedAndNoReparse(fixture.ProductRoot, path, mustExist: true);
            Assert.IsTrue(UpdateFilesystemSecurity.ValidateDirectoryOnDisk(role, new DirectoryInfo(path)).IsMatch, role.ToString());
        }
    }

    private static void AssertDirectFileOnlyInheritance(string fixtureRoot, string parent, UpdateDirectoryRole role,
        string fileName, string directoryName)
    {
        EnsureContainedAndNoReparse(fixtureRoot, parent, mustExist: true);
        AssertMutableParentDescriptor(parent, role);

        var file = Path.Combine(parent, fileName);
        EnsureContainedAndNoReparse(fixtureRoot, file, mustExist: false);
        using (var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096,
                   FileOptions.WriteThrough))
        {
            stream.Write("file-only-inheritance-v1"u8);
            stream.Flush(flushToDisk: true);
        }
        EnsureContainedAndNoReparse(fixtureRoot, file, mustExist: true);
        AssertInheritedMutableFileDescriptor(file);

        var directory = Path.Combine(parent, directoryName);
        EnsureContainedAndNoReparse(fixtureRoot, directory, mustExist: false);
        Directory.CreateDirectory(directory);
        EnsureContainedAndNoReparse(fixtureRoot, directory, mustExist: true);
        var attributes = File.GetAttributes(directory);
        Assert.IsTrue(attributes.HasFlag(FileAttributes.Directory));
        Assert.IsFalse(attributes.HasFlag(FileAttributes.ReparsePoint));
        AssertInheritedMutableDirectoryCarrierDescriptor(directory);
    }

    private static void AssertMutableParentDescriptor(string path, UpdateDirectoryRole role)
    {
        var descriptor = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        Assert.IsTrue(UpdateFilesystemSecurity.ValidateDirectoryDescriptor(role, descriptor).IsMatch, role.ToString());
        Assert.AreEqual(Administrators, descriptor.GetOwner(typeof(SecurityIdentifier)));
        Assert.IsTrue(descriptor.AreAccessRulesProtected);
        var rules = Rules(descriptor);
        AssertParentFullControl(rules, Administrators);
        AssertParentFullControl(rules, System);
        var local = rules.Where(rule => rule.IdentityReference.Equals(LocalService)).ToArray();
        Assert.AreEqual(2, local.Length);
        var direct = local.Single(rule => rule.InheritanceFlags == InheritanceFlags.None &&
            rule.PropagationFlags == PropagationFlags.None);
        Assert.AreEqual(LocalServiceCreateFileRights, direct.FileSystemRights);
        Assert.AreEqual(AccessControlType.Allow, direct.AccessControlType);
        var fileOnly = local.Single(rule => rule.InheritanceFlags == InheritanceFlags.ObjectInherit &&
            rule.PropagationFlags == PropagationFlags.InheritOnly);
        Assert.AreEqual(MutableFileRights, fileOnly.FileSystemRights);
        Assert.AreEqual(AccessControlType.Allow, fileOnly.AccessControlType);
        Assert.IsFalse(fileOnly.InheritanceFlags.HasFlag(InheritanceFlags.ContainerInherit));
        Assert.IsFalse(fileOnly.IsInherited);
    }

    private static void AssertInheritedMutableFileDescriptor(string path)
    {
        var attributes = File.GetAttributes(path);
        Assert.IsFalse(attributes.HasFlag(FileAttributes.Directory));
        Assert.IsFalse(attributes.HasFlag(FileAttributes.ReparsePoint));
        var rules = Rules(new FileInfo(path).GetAccessControl(AccessControlSections.Access));
        Assert.AreEqual(3, rules.Length);
        Assert.IsTrue(rules.All(rule => rule.AccessControlType == AccessControlType.Allow));
        Assert.IsTrue(rules.All(rule => rule.IdentityReference.Equals(Administrators) || rule.IdentityReference.Equals(System) ||
            rule.IdentityReference.Equals(LocalService)));
        AssertInheritedFullControl(rules, Administrators);
        AssertInheritedFullControl(rules, System);
        var local = rules.Single(rule => rule.IdentityReference.Equals(LocalService));
        Assert.AreEqual(MutableFileRights, local.FileSystemRights);
        Assert.AreEqual(AccessControlType.Allow, local.AccessControlType);
        Assert.IsTrue(local.IsInherited);
        Assert.AreEqual(InheritanceFlags.None, local.InheritanceFlags);
        Assert.AreEqual(PropagationFlags.None, local.PropagationFlags);
    }

    private static void AssertInheritedMutableDirectoryCarrierDescriptor(string path)
    {
        var rules = Rules(new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access));
        Assert.AreEqual(3, rules.Length);
        Assert.IsTrue(rules.All(rule => rule.AccessControlType == AccessControlType.Allow));
        Assert.IsTrue(rules.All(rule => rule.IdentityReference.Equals(Administrators) || rule.IdentityReference.Equals(System) ||
            rule.IdentityReference.Equals(LocalService)));
        AssertInheritedDirectoryFullControl(rules, Administrators);
        AssertInheritedDirectoryFullControl(rules, System);
        var local = rules.Single(rule => rule.IdentityReference.Equals(LocalService));
        Assert.IsTrue(IsExpectedInheritedDirectoryCarrier(local));
        // InheritOnly means this carrier ACE does not apply to this directory. It is
        // retained solely to propagate the ObjectInherit rule to files below it.
        Assert.AreEqual(PropagationFlags.InheritOnly, local.PropagationFlags);
    }

    private static void AssertParentFullControl(IEnumerable<FileSystemAccessRule> rules, SecurityIdentifier sid)
    {
        var rule = rules.Single(item => item.IdentityReference.Equals(sid));
        Assert.AreEqual(FileSystemRights.FullControl, rule.FileSystemRights);
        Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
        Assert.IsFalse(rule.IsInherited);
        Assert.AreEqual(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, rule.InheritanceFlags);
        Assert.AreEqual(PropagationFlags.None, rule.PropagationFlags);
    }

    private static void AssertInheritedFullControl(IEnumerable<FileSystemAccessRule> rules, SecurityIdentifier sid)
    {
        var rule = rules.Single(item => item.IdentityReference.Equals(sid));
        Assert.AreEqual(FileSystemRights.FullControl, rule.FileSystemRights);
        Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
        Assert.IsTrue(rule.IsInherited);
        Assert.AreEqual(InheritanceFlags.None, rule.InheritanceFlags);
        Assert.AreEqual(PropagationFlags.None, rule.PropagationFlags);
    }

    private static void AssertInheritedDirectoryFullControl(IEnumerable<FileSystemAccessRule> rules, SecurityIdentifier sid)
    {
        var rule = rules.Single(item => item.IdentityReference.Equals(sid));
        Assert.AreEqual(FileSystemRights.FullControl, rule.FileSystemRights);
        Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
        Assert.IsTrue(rule.IsInherited);
        Assert.AreEqual(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, rule.InheritanceFlags);
        Assert.AreEqual(PropagationFlags.None, rule.PropagationFlags);
    }

    private static bool IsExpectedInheritedDirectoryCarrier(FileSystemAccessRule rule) =>
        IsExpectedInheritedDirectoryCarrier((SecurityIdentifier)rule.IdentityReference, rule.AccessControlType,
            rule.FileSystemRights, rule.IsInherited, rule.InheritanceFlags, rule.PropagationFlags);

    private static bool IsExpectedInheritedDirectoryCarrier(SecurityIdentifier sid, AccessControlType accessControlType,
        FileSystemRights rights, bool isInherited, InheritanceFlags inheritance, PropagationFlags propagation) =>
        sid.Equals(LocalService) && accessControlType == AccessControlType.Allow && rights == MutableFileRights &&
        isInherited && inheritance == InheritanceFlags.ObjectInherit && propagation == PropagationFlags.InheritOnly;

    private static void AssertFixtureInventory(ProvisionedUpdateFilesystem fixture, bool includeInheritanceObjects)
    {
        AssertExactChildren(fixture.ProductRoot, fixture.ProductRoot, ("Updates", true), ("ReleasePolicy", true));
        AssertExactChildren(fixture.ProductRoot, fixture.UpdatesRoot, ("Transactions", true), ("Backups", true));
        AssertExactChildren(fixture.ProductRoot, fixture.TransactionsRoot,
            includeInheritanceObjects
                ? [(TransactionId, true), (UpdateTransactionJournalStore.JournalFileName, false),
                    (TransactionFileName, false), (TransactionDirectoryName, true)]
                : [(TransactionId, true), (UpdateTransactionJournalStore.JournalFileName, false)]);
        AssertExactChildren(fixture.ProductRoot, fixture.TransactionRoot, ("candidate", true));
        AssertExactChildren(fixture.ProductRoot, fixture.PrivateCandidateRoot);
        AssertExactChildren(fixture.ProductRoot, fixture.BackupsRoot, (BackupId, true));
        AssertExactChildren(fixture.ProductRoot, fixture.FixedBackupRoot);
        AssertExactChildren(fixture.ProductRoot, fixture.ReleasePolicyRoot,
            includeInheritanceObjects
                ? [(ReleasePolicyStore.PolicyFileName, false), (PolicyFileName, false), (PolicyDirectoryName, true)]
                : [(ReleasePolicyStore.PolicyFileName, false)]);
        if (includeInheritanceObjects)
        {
            AssertExactChildren(fixture.ProductRoot, Path.Combine(fixture.TransactionsRoot, TransactionDirectoryName));
            AssertExactChildren(fixture.ProductRoot, Path.Combine(fixture.ReleasePolicyRoot, PolicyDirectoryName));
        }
    }

    private static void AssertExactChildren(string fixtureRoot, string directory, params (string Name, bool IsDirectory)[] expected)
    {
        EnsureContainedAndNoReparse(fixtureRoot, directory, mustExist: true);
        var expectedByName = expected.ToDictionary(item => item.Name, item => item.IsDirectory, StringComparer.Ordinal);
        Assert.AreEqual(expected.Length, expectedByName.Count, "Test inventory has duplicate expected names.");
        var actual = Directory.EnumerateFileSystemEntries(directory).ToArray();
        Assert.AreEqual(expectedByName.Count, actual.Length, directory);
        foreach (var path in actual)
        {
            EnsureContainedAndNoReparse(fixtureRoot, path, mustExist: true);
            var name = Path.GetFileName(path);
            Assert.IsTrue(expectedByName.TryGetValue(name, out var expectedDirectory), Path.GetRelativePath(fixtureRoot, path));
            var isDirectory = File.GetAttributes(path).HasFlag(FileAttributes.Directory);
            Assert.AreEqual(expectedDirectory, isDirectory, Path.GetRelativePath(fixtureRoot, path));
        }
    }

    private static void DeleteKnownFile(string fixtureRoot, string path)
    {
        EnsureContainedAndNoReparse(fixtureRoot, path, mustExist: true);
        var attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.Directory)) throw new IOException("Expected inheritance test file is a directory.");
        File.Delete(path);
    }

    private static void DeleteKnownDirectory(string fixtureRoot, string path)
    {
        EnsureContainedAndNoReparse(fixtureRoot, path, mustExist: true);
        var attributes = File.GetAttributes(path);
        if (!attributes.HasFlag(FileAttributes.Directory)) throw new IOException("Expected inheritance test directory is a file.");
        if (Directory.EnumerateFileSystemEntries(path).Any()) throw new IOException("Inheritance test directory is not empty.");
        Directory.Delete(path, recursive: false);
    }

    private static void EnsureContainedAndNoReparse(string fixtureRoot, string path, bool mustExist)
    {
        fixtureRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(fixtureRoot));
        path = Path.GetFullPath(path);
        if (!IsSameOrChild(path, fixtureRoot)) throw new IOException("Inheritance test path escaped the fixture.");
        var existsAsDirectory = Directory.Exists(path);
        var existsAsFile = File.Exists(path);
        if (mustExist && !existsAsDirectory && !existsAsFile)
            throw new IOException("Expected inheritance test identity is unavailable.");
        if (!mustExist && (existsAsDirectory || existsAsFile))
            throw new IOException("Inheritance test identity already exists.");
        var current = existsAsDirectory ? new DirectoryInfo(path) :
            existsAsFile ? new FileInfo(path).Directory : new DirectoryInfo(Path.GetDirectoryName(path)!);
        for (; current is not null; current = current.Parent)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Inheritance test reparse point rejected.");
            if (string.Equals(current.FullName, fixtureRoot, StringComparison.OrdinalIgnoreCase)) return;
        }
        throw new IOException("Inheritance test fixture ancestry rejected.");
    }

    private static bool IsSameOrChild(string path, string root)
    {
        path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return string.Equals(path, root, StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}
