using System.Runtime.Versioning;
using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.ManifestTool;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2PrivateKeyProviderTests
{
    private const int PrivilegeNotHeld = unchecked((int)0x80070522);

    [TestMethod]
    public void Protected_external_pkcs8_imports_the_matching_ephemeral_p256_key()
    {
        using var fixture = new Fixture();
        using var original = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = fixture.WriteProtectedKey(fixture.KeyRoot, "manifest.pk8", original);
        using var imported = fixture.Provider.OpenKey(keyPath);

        CollectionAssert.AreEqual(original.ExportSubjectPublicKeyInfo(),
            imported.ExportSubjectPublicKeyInfo());
        var message = "ephemeral test message"u8.ToArray();
        var signature = imported.SignData(message, HashAlgorithmName.SHA256);
        Assert.IsTrue(original.VerifyData(message, signature, HashAlgorithmName.SHA256));
    }

    [TestMethod]
    public void A_metadata_purpose_key_cannot_create_a_manifest_sidecar()
    {
        using var fixture = new Fixture();
        using var manifest = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var metadata = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var metadataPath = fixture.WriteProtectedKey(fixture.KeyRoot, "metadata.pk8", metadata);
        using var wrongPurpose = fixture.Provider.OpenKey(metadataPath);

        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateSignedManifest("0.1.0-beta.1", 1,
            [new TrustedManifestV2File("Vantrel.Security.Service.exe", new string('A', 64))],
            wrongPurpose, manifest.ExportSubjectPublicKeyInfo()));
        Assert.IsFalse(File.Exists(Path.Combine(fixture.OutputRoot,
            ServiceReleaseV2RecordGate.ManifestFileName)));
    }

    [TestMethod]
    public void Key_paths_inside_the_source_or_release_parent_are_rejected()
    {
        using var fixture = new Fixture();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var sourceKeys = Path.Combine(fixture.SourceRoot, "keys");
        var releaseKeys = Path.Combine(fixture.ReleaseParent, "keys");
        ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(sourceKeys);
        ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(releaseKeys);

        foreach (var path in new[]
        {
            fixture.WriteProtectedKey(sourceKeys, "source.pk8", key),
            fixture.WriteProtectedKey(releaseKeys, "release.pk8", key)
        })
            Assert.ThrowsException<IOException>(() => fixture.Provider.OpenKey(path));

        Assert.ThrowsException<IOException>(() => fixture.Provider.OpenKey("relative.pk8"));
        Assert.ThrowsException<IOException>(() => fixture.Provider.OpenKey(
            Path.Combine(fixture.KeyRoot, "..", "keys", "noncanonical.pk8")));
    }

    [TestMethod]
    public void Inherited_parent_or_file_acl_and_malformed_pkcs8_fail_closed()
    {
        using var fixture = new Fixture();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var inheritedParent = Path.Combine(fixture.Root, "inherited-keys");
        Directory.CreateDirectory(inheritedParent);
        var protectedFileWithInheritedParent = fixture.WriteProtectedKey(
            inheritedParent, "parent.pk8", key);
        Assert.ThrowsException<IOException>(() => fixture.Provider.OpenKey(
            protectedFileWithInheritedParent));

        var inheritedFile = fixture.WriteKey(fixture.KeyRoot, "file.pk8", key);
        Assert.ThrowsException<IOException>(() => fixture.Provider.OpenKey(inheritedFile));

        var malformed = Path.Combine(fixture.KeyRoot, "malformed.pk8");
        File.WriteAllBytes(malformed, [1, 2, 3, 4, 5]);
        ServiceReleaseV2FileSystemSecurity.ProtectFile(malformed);
        Assert.ThrowsException<IOException>(() => fixture.Provider.OpenKey(malformed));
    }

    [TestMethod]
    public void Protected_p384_pkcs8_is_rejected_by_the_external_key_provider()
    {
        using var fixture = new Fixture();
        using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var path = fixture.WriteProtectedKey(fixture.KeyRoot, "wrong-curve.pk8", wrongCurve);

        Assert.ThrowsException<IOException>(() => fixture.Provider.OpenKey(path));
    }

    [TestMethod]
    public void A_reparse_key_leaf_is_rejected_when_file_symlink_privilege_is_available()
    {
        using var fixture = new Fixture();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var target = fixture.WriteProtectedKey(fixture.KeyRoot, "target.pk8", key);
        var link = Path.Combine(fixture.KeyRoot, "link.pk8");
        try { File.CreateSymbolicLink(link, target); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeld)
        {
            Assert.Inconclusive("File-symbolic-link privilege unavailable.");
            return;
        }

        Assert.IsTrue((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0);
        Assert.ThrowsException<IOException>(() => fixture.Provider.OpenKey(link));
    }

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(),
            "vantrel-task074-keys-" + Guid.NewGuid().ToString("N"));
        internal string SourceRoot { get; }
        internal string ReleaseParent { get; }
        internal string OutputRoot { get; }
        internal string KeyRoot { get; }
        internal ProtectedExternalV2PrivateKeyProvider Provider { get; }

        internal Fixture()
        {
            Directory.CreateDirectory(Root);
            SourceRoot = Path.Combine(Root, "source");
            ReleaseParent = Path.Combine(Root, "release");
            OutputRoot = Path.Combine(ReleaseParent, "layout");
            KeyRoot = Path.Combine(Root, "external-keys");
            Directory.CreateDirectory(SourceRoot);
            Directory.CreateDirectory(ReleaseParent);
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(KeyRoot);
            Provider = new ProtectedExternalV2PrivateKeyProvider(SourceRoot, OutputRoot);
        }

        internal string WriteProtectedKey(string directory, string name, ECDsa key)
        {
            var path = WriteKey(directory, name, key);
            ServiceReleaseV2FileSystemSecurity.ProtectFile(path);
            return path;
        }

        internal string WriteKey(string directory, string name, ECDsa key)
        {
            var path = Path.Combine(directory, name);
            var privateBytes = key.ExportPkcs8PrivateKey();
            try
            {
                using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
                    FileShare.None);
                stream.Write(privateBytes);
                stream.Flush(flushToDisk: true);
            }
            finally { CryptographicOperations.ZeroMemory(privateBytes); }
            return path;
        }

        public void Dispose()
        {
            var root = Path.GetFullPath(Root);
            var temp = Path.GetFullPath(Path.GetTempPath());
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(root).StartsWith("vantrel-task074-keys-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(root, recursive: true);
        }
    }
}
