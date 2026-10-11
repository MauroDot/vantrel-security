using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2FileSystemSecurityTests
{
    [TestMethod]
    public void Protected_stage_and_file_reject_inherited_or_unapproved_writers()
    {
        using var fixture = new TemporaryDirectory();
        var stage = Path.Combine(fixture.Root, "stage");
        ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(stage);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(stage);
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(stage));

        var file = Path.Combine(stage, "payload.dll");
        File.WriteAllText(file, "approved content");
        // An inherited DACL is not treated as explicit v2 protection.
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.RequireProtectedFile(file));
        ServiceReleaseV2FileSystemSecurity.ProtectFile(file);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedFile(file);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedTree(stage,
        [
            new TrustedManifestV2File("payload.dll",
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))))
        ]);

        var security = new FileInfo(file).GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.WriteData, AccessControlType.Allow));
        new FileInfo(file).SetAccessControl(security);
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.RequireProtectedFile(file));
    }

    [TestMethod]
    public void Ordinary_directory_with_inherited_access_is_not_a_protected_stage()
    {
        using var fixture = new TemporaryDirectory();
        var ordinary = Path.Combine(fixture.Root, "ordinary");
        Directory.CreateDirectory(ordinary);
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(ordinary));
    }

    [TestMethod]
    public void File_acl_can_be_applied_to_the_retained_create_new_identity()
    {
        using var fixture = new TemporaryDirectory();
        var stage = Path.Combine(fixture.Root, "stage");
        ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(stage);
        var file = Path.Combine(stage, "payload.dll");
        using (var handle = CreateFile(file, 0x80000000 | 0x40000000 | 0x00040000 | 0x00080000,
            1, IntPtr.Zero, 1, 0x00200000, IntPtr.Zero))
        {
            Assert.IsFalse(handle.IsInvalid);
            RandomAccess.Write(handle, "payload"u8, 0);
            ServiceReleaseV2FileSystemSecurity.ProtectFile(handle);
        }
        ServiceReleaseV2FileSystemSecurity.RequireProtectedFile(file);
    }

    [TestMethod]
    public void Same_handle_stream_check_rejects_named_ads_and_accepts_only_default_stream()
    {
        using var fixture = new TemporaryDirectory();
        var file = Path.Combine(fixture.Root, "payload.dll");
        File.WriteAllText(file, "approved content");
        using var handle = File.OpenHandle(file, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, FileOptions.None);
        ServiceReleaseV2FileSystemSecurity.RequireNoNamedStreams(handle);
        File.WriteAllText(file + ":hidden", "not manifest-recorded");
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.RequireNoNamedStreams(handle));
    }

    [TestMethod]
    public void Bound_protected_reader_and_hasher_reject_named_streams_and_inherited_acl()
    {
        using var fixture = new TemporaryDirectory();
        var stage = Path.Combine(fixture.Root, "stage");
        ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(stage);
        var file = Path.Combine(stage, "payload.dll");
        File.WriteAllText(file, "approved content");
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(file, 1024));
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.HashProtectedFile(file, 1024));
        ServiceReleaseV2FileSystemSecurity.ProtectFile(file);
        CollectionAssert.AreEqual(File.ReadAllBytes(file),
            ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(file, 1024));
        Assert.AreEqual(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))),
            ServiceReleaseV2FileSystemSecurity.HashProtectedFile(file, 1024));
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(file, 2));
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.HashProtectedFile(file, 2));
        File.WriteAllText(file + ":hidden", "unrecorded");
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(file, 1024));
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FileSystemSecurity.HashProtectedFile(file, 1024));
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(),
            "vantrel-task073-fs-" + Guid.NewGuid().ToString("N"));

        internal TemporaryDirectory() => Directory.CreateDirectory(Root);

        public void Dispose()
        {
            var root = Path.GetFullPath(Root);
            var temp = Path.GetFullPath(Path.GetTempPath());
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(root).StartsWith("vantrel-task073-fs-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(root, recursive: true);
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
}
