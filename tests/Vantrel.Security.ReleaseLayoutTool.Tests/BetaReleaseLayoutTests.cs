using System.Security.Cryptography;
using Vantrel.Security.ManifestTool;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
public sealed class BetaReleaseLayoutTests
{
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);

    [TestMethod]
    public void Canonical_layout_writes_a_relative_complete_record_without_secret_retention()
    {
        using var scope = new LayoutScope();
        var record = scope.Validate();
        var text = File.ReadAllText(Path.Combine(scope.Root, BetaReleaseLayoutValidator.RecordFileName));

        Assert.AreEqual(13, record.Artifacts.Count);
        Assert.IsTrue(record.Artifacts.Any(item => item.RelativePath == "desktop/Vantrel.Security.Desktop.exe"));
        Assert.IsTrue(record.Artifacts.Any(item => item.RelativePath == "offline-update-tool/Vantrel.Security.OfflineUpdateTool.exe"));
        Assert.IsFalse(text.Contains(scope.Root, StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(text.Contains("private", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(text.Contains("exception", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Raw_service_publish_residue_projects_exact_components_then_supports_a_nine_file_layout()
    {
        using var scope = new LayoutScope(rawServicePublish: true);
        new ServicePayloadProjector().Project(scope.RawServicePublishDirectory, Path.Combine(scope.Root, "service"));
        Directory.Delete(scope.RawServicePublishDirectory, recursive: true);

        CollectionAssert.AreEquivalent(ReleasePayloadVerifier.ServiceComponents.Select(component => component.FileName).ToArray(),
            Directory.EnumerateFiles(Path.Combine(scope.Root, "service")).Select(Path.GetFileName).ToArray());
        scope.AddSyntheticServicePublicArtifacts();

        var record = scope.Validate();
        Assert.AreEqual(13, record.Artifacts.Count);
    }

    [TestMethod]
    public void Missing_projected_component_fails_closed_without_a_final_service_directory()
    {
        using var scope = new LayoutScope(rawServicePublish: true);
        File.Delete(Path.Combine(scope.RawServicePublishDirectory, ReleasePayloadVerifier.ServiceComponentFileNames[0]));

        Assert.ThrowsException<IOException>(() => new ServicePayloadProjector().Project(scope.RawServicePublishDirectory, Path.Combine(scope.Root, "service")));
        Assert.IsFalse(Directory.Exists(Path.Combine(scope.Root, "service")));
    }

    [TestMethod]
    public void Reparse_projected_component_fails_closed_when_symbolic_links_are_permitted()
    {
        using var scope = new LayoutScope(rawServicePublish: true);
        var component = Path.Combine(scope.RawServicePublishDirectory, ReleasePayloadVerifier.ServiceComponentFileNames[0]);
        var target = Path.Combine(scope.Root, "component-target.bin");
        File.WriteAllText(target, "target");
        File.Delete(component);
        try { File.CreateSymbolicLink(component, target); }
        catch (Exception error) when (IsPrivilegeNotHeld(error)) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }

        Assert.ThrowsException<IOException>(() => new ServicePayloadProjector().Project(scope.RawServicePublishDirectory, Path.Combine(scope.Root, "service")));
        Assert.IsFalse(Directory.Exists(Path.Combine(scope.Root, "service")));
    }
    [TestMethod]
    public void Unexpected_service_file_fails_closed_without_a_record()
    {
        using var scope = new LayoutScope();
        scope.File("service/unexpected.dll", "unexpected");

        scope.AssertRejected();
    }

    [TestMethod]
    public void Missing_desktop_artifact_fails_closed_without_a_record()
    {
        using var scope = new LayoutScope();
        File.Delete(Path.Combine(scope.Root, "desktop", "Vantrel.Security.Desktop.exe"));

        scope.AssertRejected();
    }

    [TestMethod]
    public void Release_notes_hash_mismatch_fails_closed_without_a_record()
    {
        using var scope = new LayoutScope();
        File.AppendAllText(Path.Combine(scope.Root, BetaReleaseLayoutValidator.ReleaseNotesFileName), "changed");

        scope.AssertRejected();
    }

    [TestMethod]
    public void Manifest_or_metadata_version_mismatch_fails_closed_without_a_record()
    {
        using var scope = new LayoutScope(new StubVerifier(new VerifiedServicePayload("0.1.1-beta.1", "0.1.1-beta.1", 7, new string('B', 64))));

        scope.AssertRejected();
    }
    [TestMethod]
    public void Service_payload_hash_mismatch_fails_closed_without_a_record()
    {
        using var scope = new LayoutScope();
        var verifier = new HashCheckingVerifier(scope.Root);
        File.AppendAllText(Path.Combine(scope.Root, "service", "Vantrel.Security.Service.exe"), "changed");

        Assert.ThrowsException<IOException>(() => new BetaReleaseLayoutValidator(verifier).ValidateAndWriteRecord(scope.Root));
        Assert.IsFalse(File.Exists(Path.Combine(scope.Root, BetaReleaseLayoutValidator.RecordFileName)));
    }


    [TestMethod]
    public void Malformed_descriptor_rejects_extra_and_noncanonical_fields()
    {
        var descriptor = new BetaReleaseDescriptor(new string('a', 40), "0.1.0-beta.1", 7,
            new DateTimeOffset(2026, 10, 3, 12, 0, 0, TimeSpan.Zero), "Release", "win-x64", "10.0.401", new string('A', 64));
        var canonical = System.Text.Encoding.UTF8.GetString(BetaReleaseDescriptorCodec.CreateCanonical(descriptor));

        Assert.IsTrue(BetaReleaseDescriptorCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(canonical), out var parsed));
        Assert.AreEqual(descriptor, parsed);
        Assert.IsFalse(BetaReleaseDescriptorCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(canonical + "extra=value\n"), out _));
        Assert.IsFalse(BetaReleaseDescriptorCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(canonical.Replace("release-sequence=7", "release-sequence=07", StringComparison.Ordinal)), out _));
    }

    [TestMethod]
    public void Secret_like_artifact_is_rejected_and_never_enters_the_record()
    {
        using var scope = new LayoutScope();
        scope.File("desktop/forbidden.pem", "not-a-key");

        scope.AssertRejected();
    }

    [TestMethod]
    public void Signature_verification_failure_fails_closed_without_raw_diagnostics_or_record()
    {
        using var scope = new LayoutScope(new ThrowingVerifier());

        scope.AssertRejected();
    }

    [TestMethod]
    public void Reparse_directory_substitution_is_rejected_when_symbolic_links_are_permitted()
    {
        using var scope = new LayoutScope();
        var desktop = Path.Combine(scope.Root, "desktop");
        var target = Path.Combine(scope.Root, "replacement");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "Vantrel.Security.Desktop.exe"), "replacement");
        Directory.Delete(desktop, recursive: true);
        try { Directory.CreateSymbolicLink(desktop, target); }
        catch (Exception error) when (IsPrivilegeNotHeld(error)) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }

        scope.AssertRejected();
    }

    [TestMethod]
    public void Reparse_artifact_is_rejected_when_symbolic_links_are_permitted()
    {
        using var scope = new LayoutScope();
        var target = Path.Combine(scope.Root, "target.bin");
        File.WriteAllText(target, "target");
        var link = Path.Combine(scope.Root, "desktop", "linked.dll");
        try { File.CreateSymbolicLink(link, target); }
        catch (Exception error) when (IsPrivilegeNotHeld(error)) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }

        scope.AssertRejected();
    }

    private static bool IsPrivilegeNotHeld(Exception error) => error.HResult == PrivilegeNotHeldHResult;

    private sealed class LayoutScope : IDisposable
    {
        private const string Version = "0.1.0-beta.1";
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-beta-layout-" + Guid.NewGuid().ToString("N"));
        private readonly IServicePayloadSignatureVerifier _verifier;
        internal string RawServicePublishDirectory => Path.Combine(Root, "service-publish");

        internal LayoutScope(IServicePayloadSignatureVerifier? verifier = null, bool rawServicePublish = false)
        {
            Directory.CreateDirectory(Root);
            _verifier = verifier ?? new StubVerifier(new VerifiedServicePayload(Version, Version, 7, new string('B', 64)));
            File(BetaReleaseLayoutValidator.ReleaseNotesFileName, "# Beta notes\n");
            var notesHash = Hash(Path.Combine(Root, BetaReleaseLayoutValidator.ReleaseNotesFileName));
            var descriptor = new BetaReleaseDescriptor(new string('a', 40), Version, 7,
                new DateTimeOffset(2026, 10, 3, 12, 0, 0, TimeSpan.Zero), "Release", "win-x64", "10.0.401", notesHash);
            System.IO.File.WriteAllBytes(Path.Combine(Root, BetaReleaseDescriptorCodec.FileName), BetaReleaseDescriptorCodec.CreateCanonical(descriptor));
            if (rawServicePublish)
            {
                foreach (var name in ReleasePayloadVerifier.ServiceComponentFileNames) File(Path.Combine("service-publish", name), name);
                File("service-publish/Vantrel.Security.Service.pdb", "debug");
                File("service-publish/appsettings.json", "settings");
                File("service-publish/Microsoft.Extensions.Hosting.dll", "dependency");
            }
            else foreach (var name in ReleasePayloadVerifier.ExactFileNames) File(Path.Combine("service", name), name);
            File("desktop/Vantrel.Security.Desktop.exe", "desktop");
            File("offline-update-tool/Vantrel.Security.OfflineUpdateTool.exe", "tool");
        }

        internal void File(string relative, string contents)
        {
            var path = Path.Combine(Root, relative); Directory.CreateDirectory(Path.GetDirectoryName(path)!); System.IO.File.WriteAllText(path, contents);
        }
        internal void AddSyntheticServicePublicArtifacts()
        {
            File("service/Vantrel.Security.TrustedManifest", "manifest");
            File("service/Vantrel.Security.ReleaseMetadata", "metadata");
        }
        internal BetaReleaseRecord Validate() => new BetaReleaseLayoutValidator(_verifier).ValidateAndWriteRecord(Root);
        internal void AssertRejected()
        {
            Assert.ThrowsException<IOException>(() => Validate());
            Assert.IsFalse(System.IO.File.Exists(Path.Combine(Root, BetaReleaseLayoutValidator.RecordFileName)));
        }
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }
        private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(System.IO.File.ReadAllBytes(path)));
    }

    private sealed class StubVerifier(VerifiedServicePayload payload) : IServicePayloadSignatureVerifier
    {
        public VerifiedServicePayload Verify(string payloadDirectory) => payload;
    }
    private sealed class ThrowingVerifier : IServicePayloadSignatureVerifier
    {
        public VerifiedServicePayload Verify(string payloadDirectory) => throw new InvalidDataException("synthetic failure");
    }
    private sealed class HashCheckingVerifier : IServicePayloadSignatureVerifier
    {
        private readonly IReadOnlyDictionary<string, string> _expected;

        internal HashCheckingVerifier(string root)
        {
            _expected = ReleasePayloadVerifier.ExactFileNames.ToDictionary(
                name => name,
                name => Hash(Path.Combine(root, "service", name)),
                StringComparer.Ordinal);
        }

        public VerifiedServicePayload Verify(string payloadDirectory)
        {
            foreach (var pair in _expected)
                if (!string.Equals(pair.Value, Hash(Path.Combine(payloadDirectory, pair.Key)), StringComparison.Ordinal))
                    throw new InvalidDataException("Synthetic service signature hash mismatch.");
            return new VerifiedServicePayload("0.1.0-beta.1", "0.1.0-beta.1", 7, new string('B', 64));
        }

        private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    }
}
