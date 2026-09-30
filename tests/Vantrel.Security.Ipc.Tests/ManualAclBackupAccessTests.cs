using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class ManualAclBackupAccessTests
{
    private const string FixtureVariable = "KESTERMERE_ACL_FIXTURE";
    private const string BackupFileName = "Vantrel.Security.Core.dll";
    private static readonly byte[] Sentinel = "kestermere-acl-harness-sentinel-v1"u8.ToArray();

    [TestMethod, TestCategory("ManualAclHarness")]
    public void Acl_harness_administrator_setup()
    {
        ManualAclHarnessGate.RequirePhase("setup");
        RequireAdministrator();
        var root = Fixture(mustExist: false);

        try
        {
            Directory.CreateDirectory(root);
            WindowsOfflineUpdateFileOperations.Instance.ApplyProtectedDirectoryAcl(root, allowLocalService: false);
            var file = Path.Combine(root, BackupFileName);
            File.WriteAllBytes(file, Sentinel);
            WindowsOfflineUpdateFileOperations.Instance.ApplyProtectedFileAcl(file, allowLocalService: false);
            Assert.IsTrue(new DirectoryInfo(root).GetAccessControl().AreAccessRulesProtected);
            Assert.IsTrue(new FileInfo(file).GetAccessControl().AreAccessRulesProtected);
        }
        catch
        {
            Cleanup(root);
            throw;
        }
    }

    [TestMethod, TestCategory("ManualAclHarness")]
    public void Acl_harness_non_elevated_write_denied()
    {
        ManualAclHarnessGate.RequirePhase("attempt");
        if (IsAdministrator()) throw new InvalidOperationException("Non-elevated token required.");

        var root = Fixture(mustExist: true);
        var file = Path.Combine(root, BackupFileName);

        try
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.None);
            stream.Write("modified"u8);
            Assert.Fail("Protected backup write unexpectedly succeeded.");
        }
        catch (UnauthorizedAccessException exception) when ((uint)exception.HResult == 0x80070005)
        {
        }
    }

    [TestMethod, TestCategory("ManualAclHarness")]
    public void Acl_harness_administrator_verify_cleanup()
    {
        ManualAclHarnessGate.RequirePhase("verify-cleanup");
        RequireAdministrator();
        var root = Fixture(mustExist: true);
        var file = Path.Combine(root, BackupFileName);

        try
        {
            CollectionAssert.AreEqual(Sentinel, File.ReadAllBytes(file));
            Assert.IsTrue(new DirectoryInfo(root).GetAccessControl().AreAccessRulesProtected);
            Assert.IsTrue(new FileInfo(file).GetAccessControl().AreAccessRulesProtected);
        }
        finally
        {
            Cleanup(root);
            Assert.IsFalse(Directory.Exists(root));
        }
    }

    [TestMethod]
    public void Manual_acl_fixture_validation_accepts_nonexistent_direct_temp_leaf()
    {
        var root = NewFixturePath();
        Assert.IsFalse(Directory.Exists(root));
        Assert.AreEqual(root, ValidateFixture(root, mustExist: false));
    }

    [TestMethod]
    public void Manual_acl_fixture_validation_rejects_existing_leaf_during_setup()
    {
        var root = NewFixturePath();
        try
        {
            Directory.CreateDirectory(root);
            Assert.ThrowsException<InvalidOperationException>(() => ValidateFixture(root, mustExist: false));
        }
        finally
        {
            Cleanup(root);
        }
    }

    [TestMethod]
    public void Manual_acl_fixture_validation_rejects_invalid_containment_and_missing_required_ancestor()
    {
        var outside = Path.Combine(Path.GetTempPath(), "not-kestermere-acl-" + Guid.NewGuid().ToString("N"));
        var missingAncestor = Path.Combine(Path.GetTempPath(), "missing-acl-parent-" + Guid.NewGuid().ToString("N"), "kestermere-acl-child");

        Assert.ThrowsException<InvalidOperationException>(() => ValidateFixture(outside, mustExist: false));
        Assert.ThrowsException<InvalidOperationException>(() => ValidateFixture(missingAncestor, mustExist: false));
    }

    [TestMethod]
    public void Manual_acl_fixture_validation_rejects_existing_reparse_ancestor_without_inspecting_setup_leaf()
    {
        var root = NewFixturePath();
        var inspected = new List<string>();
        Assert.ThrowsException<IOException>(() => ValidateFixture(root, mustExist: false, path =>
        {
            inspected.Add(path);
            return string.Equals(path, Path.GetDirectoryName(root), StringComparison.OrdinalIgnoreCase)
                ? FileAttributes.ReparsePoint
                : FileAttributes.Normal;
        }));
        CollectionAssert.DoesNotContain(inspected, root);
    }
    [TestMethod]
    public void Manual_acl_fixture_validation_rejects_reparse_leaf()
    {
        var leaf = NewFixturePath();
        var target = Path.Combine(Path.GetTempPath(), "kestermere-acl-target-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(target);
        try
        {
            try
            {
                Directory.CreateSymbolicLink(leaf, target);
            }
            catch (UnauthorizedAccessException)
            {
                Assert.Inconclusive("Symbolic-link creation is unavailable for this test token.");
                return;
            }
            catch (IOException exception) when ((uint)exception.HResult == 0x80070522)
            {
                Assert.Inconclusive("Symbolic-link creation requires a privilege unavailable to this test token.");
                return;
            }

            Assert.ThrowsException<IOException>(() => ValidateFixture(leaf, mustExist: true));
        }
        finally
        {
            if (Directory.Exists(leaf)) Directory.Delete(leaf);
            Cleanup(target);
        }
    }

    private static string Fixture(bool mustExist)
    {
        var raw = Environment.GetEnvironmentVariable(FixtureVariable);
        if (string.IsNullOrWhiteSpace(raw)) throw new InvalidOperationException("Manual ACL fixture path is required.");
        return ValidateFixture(raw, mustExist);
    }

    private static string ValidateFixture(string raw, bool mustExist, Func<string, FileAttributes>? getAttributes = null)
    {
        if (!Path.IsPathFullyQualified(raw)) throw new InvalidOperationException("Manual ACL fixture path is required.");

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(raw));
        var temp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
        var parent = Path.GetDirectoryName(root);
        if (!IsDirectChild(root, temp) || parent is null ||
            !Path.GetFileName(root).StartsWith("kestermere-acl-", StringComparison.OrdinalIgnoreCase) ||
            OverlapsProductionOrRepository(root))
        {
            throw new InvalidOperationException("Manual ACL fixture path rejected.");
        }

        var existing = Directory.Exists(root);
        if (mustExist != existing)
        {
            throw new InvalidOperationException(mustExist ? "Manual ACL fixture is unavailable." : "Manual ACL fixture already exists.");
        }

        // Setup intentionally requires a missing leaf. Inspect only existing ancestors.
        getAttributes ??= File.GetAttributes;
        var current = existing ? root : parent;
        if (!Directory.Exists(current)) throw new InvalidOperationException("Manual ACL fixture ancestor is unavailable.");
        while (true)
        {
            if ((getAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("Manual ACL fixture reparse point rejected.");
            }

            var next = Directory.GetParent(current);
            if (next is null) break;
            current = next.FullName;
        }

        return root;
    }

    private static bool IsDirectChild(string child, string parent) =>
        string.Equals(Path.GetDirectoryName(child), parent, StringComparison.OrdinalIgnoreCase);

    private static bool OverlapsProductionOrRepository(string path)
    {
        var policy = Path.Combine(FixedUpdatePaths.VantrelRoot, "ReleasePolicy");
        return PathsOverlap(path, FixedUpdatePaths.InstalledServiceRoot) ||
               PathsOverlap(path, FixedUpdatePaths.UpdatesRoot) ||
               PathsOverlap(path, policy) ||
               PathsOverlap(path, Environment.CurrentDirectory);
    }

    private static bool PathsOverlap(string left, string right) => IsSameOrChild(left, right) || IsSameOrChild(right, left);

    private static bool IsSameOrChild(string candidate, string parent)
    {
        candidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        parent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent));
        return string.Equals(candidate, parent, StringComparison.OrdinalIgnoreCase) ||
               candidate.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string NewFixturePath() => Path.Combine(Path.GetTempPath(), "kestermere-acl-" + Guid.NewGuid().ToString("N"));
    private static bool IsAdministrator() => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    private static void RequireAdministrator() { if (!IsAdministrator()) throw new InvalidOperationException("Administrator token required."); }
    private static void Cleanup(string root) { if (Directory.Exists(root)) Directory.Delete(root, true); }
}
