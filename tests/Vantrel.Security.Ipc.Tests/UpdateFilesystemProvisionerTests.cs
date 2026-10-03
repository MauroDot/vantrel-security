using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
[DoNotParallelize]
public sealed class UpdateFilesystemProvisionerTests
{
    private const string FixtureVariable = "KESTERMERE_ACL_PROVISION_FIXTURE";
    private const string TransactionId = "0123456789abcdef0123456789abcdef";
    private const string BackupId = "fedcba9876543210fedcba9876543210";

    [TestMethod]
    public void Non_administrator_is_rejected_before_disposable_artifact_creation()
    {
        var root = NewProgramFilesFixturePath();
        var provisioner = new UpdateFilesystemProvisioner(root, () => false);
        Assert.ThrowsException<UnauthorizedAccessException>(() => provisioner.ProvisionDisposableFixture(TransactionId, BackupId));
        Assert.IsFalse(Directory.Exists(root));
        Assert.IsFalse(File.Exists(root));
    }

    [TestMethod]
    public void Disposable_boundary_rejects_arbitrary_user_writable_and_production_paths()
    {
        Assert.ThrowsException<ArgumentException>(() => new UpdateFilesystemProvisioner(
            Path.Combine(Path.GetTempPath(), "Kestermere Security ACL Provision-" + Guid.NewGuid().ToString("N")), () => true));
        Assert.ThrowsException<ArgumentException>(() => new UpdateFilesystemProvisioner(FixedUpdatePaths.VantrelRoot, () => true));
        Assert.ThrowsException<ArgumentException>(() => new UpdateFilesystemProvisioner("relative-test-root", () => true));
    }

    [TestMethod, TestCategory("ManualAclHarness")]
    public void Existing_disposable_root_is_rejected_without_descriptor_repair()
    {
        ManualAclHarnessGate.RequirePhase("provision");
        var root = NewProgramFilesFixturePath();
        if (!new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Administrator token required.");
        Directory.CreateDirectory(root);
        try
        {
            var before = new DirectoryInfo(root).GetAccessControl().GetSecurityDescriptorBinaryForm();
            Assert.ThrowsException<IOException>(() => new UpdateFilesystemProvisioner(root, () => true));
            var after = new DirectoryInfo(root).GetAccessControl().GetSecurityDescriptorBinaryForm();
            CollectionAssert.AreEqual(before, after);
        }
        finally { Directory.Delete(root); }
    }

    [TestMethod, TestCategory("ManualAclHarness")]
    public void Administrator_only_provisions_and_cleans_disposable_update_security_hierarchy()
    {
        ManualAclHarnessGate.RequirePhase("provision");
        var raw = Environment.GetEnvironmentVariable(FixtureVariable);
        if (string.IsNullOrWhiteSpace(raw)) throw new InvalidOperationException("Provisioning fixture path is required.");
        var provisioner = new UpdateFilesystemProvisioner(raw);
        ProvisionedUpdateFilesystem? paths = null;
        try
        {
            paths = provisioner.ProvisionDisposableFixture(TransactionId, BackupId);
            AssertDirectory(paths.ProductRoot, UpdateDirectoryRole.ProductRoot);
            AssertDirectory(paths.UpdatesRoot, UpdateDirectoryRole.UpdatesRoot);
            AssertDirectory(paths.TransactionsRoot, UpdateDirectoryRole.TransactionsRoot);
            AssertDirectory(paths.TransactionRoot, UpdateDirectoryRole.TransactionDirectory);
            AssertDirectory(paths.PrivateCandidateRoot, UpdateDirectoryRole.PrivateCandidateDirectory);
            AssertDirectory(paths.BackupsRoot, UpdateDirectoryRole.BackupsRoot);
            AssertDirectory(paths.FixedBackupRoot, UpdateDirectoryRole.FixedBackupDirectory);
            AssertDirectory(paths.ReleasePolicyRoot, UpdateDirectoryRole.ReleasePolicyRoot);
            Assert.IsTrue(UpdateFilesystemSecurity.ValidateProvisionedMutableFileOnDisk(new FileInfo(paths.OwnerLockFile)).IsMatch);
            Assert.IsTrue(UpdateFilesystemSecurity.ValidateProvisionedMutableFileOnDisk(new FileInfo(paths.JournalFile)).IsMatch);
            Assert.IsTrue(UpdateFilesystemSecurity.ValidateProvisionedMutableFileOnDisk(new FileInfo(paths.PolicyFile)).IsMatch);
        }
        finally
        {
            if (paths is not null) provisioner.CleanupDisposableFixture(paths);
            Assert.IsFalse(Directory.Exists(Path.GetFullPath(raw)));
        }
    }

    [DataTestMethod, TestCategory("ManualAclHarness")]
    [DataRow(false)]
    [DataRow(true)]
    public void Administrator_only_provisioning_failure_cleans_partial_fixed_hierarchy(bool aclFailure)
    {
        ManualAclHarnessGate.RequirePhase("provision");
        var raw = Environment.GetEnvironmentVariable(FixtureVariable);
        if (string.IsNullOrWhiteSpace(raw)) throw new InvalidOperationException("Provisioning fixture path is required.");
        var provisioner = new UpdateFilesystemProvisioner(raw);
        var reached = 0;
        if (aclFailure)
            Assert.ThrowsException<UnauthorizedAccessException>(() => provisioner.ProvisionDisposableFixtureForTest(
                TransactionId, BackupId, null, index => { reached++; return index == 3; }));
        else
            Assert.ThrowsException<IOException>(() => provisioner.ProvisionDisposableFixtureForTest(
                TransactionId, BackupId, index => { reached++; return index == 3; }, null));
        Assert.AreEqual(4, reached);
        Assert.IsFalse(Directory.Exists(Path.GetFullPath(raw)));
        Assert.IsFalse(File.Exists(Path.GetFullPath(raw)));
    }

    [TestMethod, TestCategory("ManualAclHarness")]
    public void Administrator_only_conflicting_state_is_rejected_without_repair_or_sibling_removal()
    {
        ManualAclHarnessGate.RequirePhase("provision");
        var raw = Environment.GetEnvironmentVariable(FixtureVariable);
        if (string.IsNullOrWhiteSpace(raw)) throw new InvalidOperationException("Provisioning fixture path is required.");
        var provisioner = new UpdateFilesystemProvisioner(raw);
        var sibling = Path.GetFullPath(raw) + "-unrelated";
        ProvisionedUpdateFilesystem? paths = null;
        try
        {
            Directory.CreateDirectory(sibling);
            File.WriteAllText(Path.Combine(sibling, "preserve.txt"), "preserve");
            File.WriteAllText(raw, "unexpected-file");
            Assert.ThrowsException<IOException>(() => provisioner.ProvisionDisposableFixture(TransactionId, BackupId));
            Assert.AreEqual("unexpected-file", File.ReadAllText(raw));
            File.Delete(raw);
            paths = provisioner.ProvisionDisposableFixture(TransactionId, BackupId);
            var candidateBefore = new DirectoryInfo(paths.PrivateCandidateRoot).GetAccessControl()
                .GetSecurityDescriptorBinaryForm();
            Assert.ThrowsException<IOException>(() => provisioner.ProvisionDisposableFixture(TransactionId, BackupId));
            CollectionAssert.AreEqual(candidateBefore, new DirectoryInfo(paths.PrivateCandidateRoot).GetAccessControl()
                .GetSecurityDescriptorBinaryForm());

            File.Delete(paths.JournalFile);
            Directory.CreateDirectory(paths.JournalFile);
            Assert.ThrowsException<IOException>(() => provisioner.ProvisionDisposableFixture(TransactionId, BackupId));
            Assert.IsTrue(Directory.Exists(paths.JournalFile));
            Assert.AreEqual("preserve", File.ReadAllText(Path.Combine(sibling, "preserve.txt")));
            Directory.Delete(paths.JournalFile);
        }
        finally
        {
            if (paths is not null) provisioner.CleanupDisposableFixture(paths);
            if (Directory.Exists(sibling)) Directory.Delete(sibling, recursive: true);
            Assert.IsFalse(Directory.Exists(Path.GetFullPath(raw)));
        }
    }

    private static void AssertDirectory(string path, UpdateDirectoryRole role) =>
        Assert.IsTrue(UpdateFilesystemSecurity.ValidateDirectoryOnDisk(role, new DirectoryInfo(path)).IsMatch, role.ToString());

    private static string NewProgramFilesFixturePath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "Kestermere Security ACL Provision-" + Guid.NewGuid().ToString("N"));

}
