using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2FinalBindingTests
{
    [TestMethod]
    public void Root_sidecars_and_nested_payload_are_bound_to_exact_names_and_bytes()
    {
        using var fixture = new Fixture();
        using var binding = ServiceReleaseV2FinalBinding.Open(fixture.Root, fixture.Expected);
        binding.Recheck();
        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("signed manifest"),
            binding.ReadBounded("Vantrel.Security.TrustedManifest", 1024));
        Assert.AreEqual(fixture.Expected.Single(file => file.RelativePath ==
            "service/Vantrel.Security.Service.dll").Sha256,
            binding.Hash("service/Vantrel.Security.Service.dll"));
        Assert.IsFalse(binding.GetHandle("service/Vantrel.Security.Service.dll").IsClosed);
    }

    [TestMethod]
    public void Existing_bytes_cannot_change_while_retained_and_writes_resume_after_disposal()
    {
        using var fixture = new Fixture();
        var path = Path.Combine(fixture.Root, "service", "Vantrel.Security.Service.dll");
        using (var binding = ServiceReleaseV2FinalBinding.Open(fixture.Root, fixture.Expected))
        {
            Assert.ThrowsException<IOException>(() => File.AppendAllText(path, "changed"));
            binding.Recheck();
        }
        File.AppendAllText(path, "changed");
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2FinalBinding.Open(fixture.Root, fixture.Expected));
    }

    [TestMethod]
    public void Unrecorded_root_or_nested_entry_fails_even_after_successful_capture()
    {
        using var fixture = new Fixture();
        using var binding = ServiceReleaseV2FinalBinding.Open(fixture.Root, fixture.Expected);
        var extra = Path.Combine(fixture.Root, "service", "unexpected.dll");
        File.WriteAllText(extra, "unexpected");
        Assert.ThrowsException<IOException>(() => binding.Recheck());
        File.Delete(extra);
        binding.Recheck();

        File.WriteAllText(Path.Combine(fixture.Root, "unrecorded.txt"), "unexpected");
        Assert.ThrowsException<IOException>(() => binding.Recheck());
    }

    [TestMethod]
    public void Parent_or_leaf_substitution_is_blocked_or_detected_before_approval()
    {
        using var fixture = new Fixture();
        using var binding = ServiceReleaseV2FinalBinding.Open(fixture.Root, fixture.Expected);
        var leaf = Path.Combine(fixture.Root, "service", "Vantrel.Security.Service.dll");
        var movedLeaf = leaf + ".moved";
        try { File.Move(leaf, movedLeaf); }
        catch (IOException) { binding.Recheck(); }
        if (File.Exists(movedLeaf)) Assert.ThrowsException<IOException>(() => binding.Recheck());

        var movedParent = fixture.Root + ".moved";
        try { Directory.Move(fixture.Root, movedParent); }
        catch (IOException)
        {
            if (File.Exists(leaf)) binding.Recheck();
        }
        if (Directory.Exists(movedParent)) Assert.ThrowsException<IOException>(() => binding.Recheck());
    }

    [TestMethod]
    public void Unsafe_or_ambiguous_expected_paths_fail_before_opening_any_file()
    {
        using var fixture = new Fixture();
        foreach (var path in new[] { "../escape.dll", "C:escape.dll", "C:/escape.dll",
            "service\\escape.dll", "service/CON.txt", "service/trailing.",
            "service/Vantrel.Security.Service.DLL" })
        {
            var candidate = fixture.Expected.Append(new ServiceReleaseV2BoundFile(path, new string('A', 64)))
                .OrderBy(item => item.RelativePath, StringComparer.Ordinal).ToArray();
            Assert.ThrowsException<IOException>(() => ServiceReleaseV2FinalBinding.Open(fixture.Root, candidate));
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _temporary = Path.Combine(Path.GetTempPath(),
            "vantrel-task073-binding-" + Guid.NewGuid().ToString("N"));
        internal string Root { get; }
        internal IReadOnlyList<ServiceReleaseV2BoundFile> Expected { get; }

        internal Fixture()
        {
            Directory.CreateDirectory(_temporary);
            var parent = Path.Combine(_temporary, "protected");
            Root = Path.Combine(parent, "layout");
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(parent);
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Root);
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Path.Combine(Root, "service"));
            Write("Vantrel.Security.TrustedManifest", "signed manifest");
            Write("Vantrel.Security.ReleaseMetadata", "signed metadata");
            Write("beta-release-descriptor-v1.txt", "descriptor");
            Write("release-notes.md", "notes");
            Write("service/Vantrel.Security.Service.dll", "service bytes");
            Expected = new[]
            {
                "Vantrel.Security.TrustedManifest", "Vantrel.Security.ReleaseMetadata",
                "beta-release-descriptor-v1.txt", "release-notes.md",
                "service/Vantrel.Security.Service.dll"
            }.Select(relative => new ServiceReleaseV2BoundFile(relative,
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(PathFor(relative))))))
                .OrderBy(item => item.RelativePath, StringComparer.Ordinal).ToArray();
        }

        private string PathFor(string relative) => Path.Combine(Root, relative.Replace('/', '\\'));

        private void Write(string relative, string content)
        {
            var path = PathFor(relative);
            File.WriteAllBytes(path, Encoding.ASCII.GetBytes(content));
            ServiceReleaseV2FileSystemSecurity.ProtectFile(path);
        }

        public void Dispose()
        {
            var temp = Path.GetFullPath(Path.GetTempPath());
            var root = Path.GetFullPath(_temporary);
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(root).StartsWith("vantrel-task073-binding-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(root, recursive: true);
        }
    }
}
