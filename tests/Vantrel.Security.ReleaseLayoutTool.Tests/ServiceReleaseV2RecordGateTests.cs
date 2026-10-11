using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2RecordGateTests
{
    private const string Commit = "0123456789abcdef0123456789abcdef01234567";
    private const string Version = "0.1.0-beta.1";
    private const string LockHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static readonly DateTimeOffset Published = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);
    private const string RuntimeConfig =
        "{\"runtimeOptions\":{\"tfm\":\"net10.0\",\"framework\":{\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.0\"}}}";
    private const string Dependencies = """
        {"runtimeTarget":{"name":".NETCoreApp,Version=v10.0/win-x64","signature":""},"compilationOptions":{},"targets":{".NETCoreApp,Version=v10.0/win-x64":{
        "Vantrel.Security.Service/0.1.0":{"dependencies":{"Microsoft.Extensions.Hosting.WindowsServices":"10.0.12","System.ServiceProcess.ServiceController":"10.0.12","Vantrel.Security.Core":"0.1.0","Vantrel.Security.Infrastructure":"0.1.0"},"runtime":{"Vantrel.Security.Service.dll":{}}},
        "Microsoft.Extensions.Hosting.WindowsServices/10.0.12":{"dependencies":{"Microsoft.Extensions.Hosting":"10.0.12"},"runtime":{"lib/net10.0/Microsoft.Extensions.Hosting.WindowsServices.dll":{}}},
        "Microsoft.Extensions.Hosting/10.0.12":{"runtime":{"lib/net10.0/Microsoft.Extensions.Hosting.dll":{}}},
        "System.ServiceProcess.ServiceController/10.0.12":{"runtime":{"runtimes/win/lib/net10.0/System.ServiceProcess.ServiceController.dll":{}}},
        "Vantrel.Security.Core/0.1.0":{"runtime":{"Vantrel.Security.Core.dll":{}}},
        "Vantrel.Security.Infrastructure/0.1.0":{"runtime":{"Vantrel.Security.Infrastructure.dll":{}}}
        }},"libraries":{"Vantrel.Security.Service/0.1.0":{"type":"project"},"Microsoft.Extensions.Hosting.WindowsServices/10.0.12":{"type":"package"},"Microsoft.Extensions.Hosting/10.0.12":{"type":"package"},"System.ServiceProcess.ServiceController/10.0.12":{"type":"package"},"Vantrel.Security.Core/0.1.0":{"type":"project"},"Vantrel.Security.Infrastructure/0.1.0":{"type":"project"}}}
        """;

    [TestMethod]
    public void Complete_layout_emits_only_canonical_v2_record_after_four_bound_PE_checks()
    {
        using var fixture = new Fixture();
        var signatures = new SyntheticSignatures();
        var authenticode = new SyntheticAuthenticode();
        var source = new SyntheticSourceBinding();
        var record = new ServiceReleaseV2RecordGate(source, signatures, authenticode)
            .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance);

        Assert.AreEqual(1, source.Calls);
        Assert.AreEqual(4, authenticode.Paths.Count);
        CollectionAssert.AreEqual(new[] { "service/Vantrel.Security.Service.exe",
            "service/Vantrel.Security.Service.dll", "service/Vantrel.Security.Infrastructure.dll",
            "service/Vantrel.Security.Core.dll" }, authenticode.Paths.ToArray());
        Assert.AreEqual(2, signatures.Calls);
        Assert.AreEqual(LockHash, record.SourceLockSha256);
        Assert.AreEqual(10, record.ServiceFiles.Count);
        Assert.AreEqual(3, record.DiagnosticSymbols.Count);
        var bytes = File.ReadAllBytes(fixture.RecordPath);
        Assert.IsTrue(BetaReleaseRecordV2Codec.TryParse(bytes, out var parsed));
        CollectionAssert.AreEqual(BetaReleaseRecordV2Codec.CreateCanonical(parsed!), bytes);
        Assert.IsFalse(File.Exists(Path.Combine(fixture.Layout, BetaReleaseLayoutValidator.RecordFileName)));
    }

    [TestMethod]
    public void Invalid_signature_pair_or_metadata_binding_cannot_write_record()
    {
        using (var fixture = new Fixture())
        {
            var signatures = new SyntheticSignatures { Accept = false };
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(), signatures,
                new SyntheticAuthenticode()).ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            fixture.ReplaceMetadataManifestHash(new string('F', 64));
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(), new SyntheticSignatures(),
                new SyntheticAuthenticode()).ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
    }

    [TestMethod]
    public void Wrong_authenticode_category_or_incomplete_service_inventory_writes_no_record()
    {
        using (var fixture = new Fixture())
        {
            var authenticode = new SyntheticAuthenticode
            {
                Category = AuthenticodeVerificationCategory.MissingTimestamp
            };
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(),
                new SyntheticSignatures(), authenticode)
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.AreEqual(1, authenticode.Paths.Count);
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            File.Delete(Path.Combine(fixture.Layout, "service", "Microsoft.Extensions.Hosting.dll"));
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(),
                new SyntheticSignatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
    }

    [TestMethod]
    public void Unexpected_file_or_preexisting_record_blocks_publication()
    {
        using (var fixture = new Fixture())
        {
            fixture.WriteProtected("service/unrecorded.dll", "unrecorded"u8.ToArray());
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(),
                new SyntheticSignatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            fixture.WriteProtected(BetaReleaseRecordV2Codec.FileName, "existing"u8.ToArray());
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(),
                new SyntheticSignatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            CollectionAssert.AreEqual("existing"u8.ToArray(), File.ReadAllBytes(fixture.RecordPath));
        }
    }

    [TestMethod]
    public void PE_bytes_are_write_denied_while_injected_authenticode_gate_holds_binding()
    {
        using var fixture = new Fixture();
        var authenticode = new SyntheticAuthenticode { AttemptMutation = true,
            Category = AuthenticodeVerificationCategory.InvalidTimestamp };
        Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(),
            new SyntheticSignatures(), authenticode)
            .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
        Assert.IsTrue(authenticode.MutationDenied);
        Assert.IsFalse(File.Exists(fixture.RecordPath));
    }

    [TestMethod]
    public void Manifest_or_post_signature_Service_mutation_cannot_publish_a_record()
    {
        using (var fixture = new Fixture())
        {
            File.AppendAllText(Path.Combine(fixture.Layout,
                ServiceReleaseV2RecordGate.ManifestFileName), "changed");
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), new SyntheticSignatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            File.AppendAllText(Path.Combine(fixture.Layout, "service",
                "Vantrel.Security.Service.dll"), "changed");
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), new SyntheticSignatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
    }

    [TestMethod]
    public void Wrong_signed_sequence_or_version_cannot_publish_a_record()
    {
        using (var fixture = new Fixture())
        {
            fixture.ReplaceMetadataIdentity(2, Version);
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), new SyntheticSignatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            fixture.ReplaceMetadataIdentity(1, "0.1.0-beta.2");
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), new SyntheticSignatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
    }

    private sealed class SyntheticSignatures : IServiceReleaseV2SignatureGate
    {
        internal bool Accept { get; set; } = true;
        internal int Calls { get; private set; }
        public bool Verify(ReadOnlySpan<byte> manifestBytes, ReadOnlySpan<byte> metadataBytes)
        {
            Calls++;
            Assert.IsTrue(TrustedManifestV2Codec.TryParse(manifestBytes, out _, out _));
            Assert.IsTrue(ReleaseMetadataCodec.TryParse(metadataBytes, out _, out _));
            return Accept;
        }
    }

    private sealed class SyntheticSourceBinding : IServiceReleaseV2SourceBinding
    {
        internal int Calls { get; private set; }
        public void Verify(string outputRoot, BetaReleaseDescriptor descriptor,
            ServiceReleaseV2BuildProvenance provenance,
            IReadOnlyList<TrustedManifestV2File> serviceFiles,
            IReadOnlyList<TrustedManifestV2File> diagnosticSymbols,
            ServiceReleaseV2FinalBinding finalBinding)
        {
            Calls++;
            Assert.AreEqual(Commit, descriptor.SourceCommit);
            Assert.AreEqual(LockHash, provenance.SourceLockSha256);
            Assert.AreEqual(10, serviceFiles.Count);
            Assert.AreEqual(3, diagnosticSymbols.Count);
            finalBinding.Recheck();
        }
    }

    private sealed class SyntheticAuthenticode : IServiceReleaseV2AuthenticodeGate
    {
        internal List<string> Paths { get; } = [];
        internal AuthenticodeVerificationCategory Category { get; set; } = AuthenticodeVerificationCategory.Valid;
        internal bool AttemptMutation { get; set; }
        internal bool MutationDenied { get; private set; }
        public AuthenticodeReleaseEvidence Verify(string relativePath, string absolutePath,
            SafeFileHandle retainedHandle)
        {
            Paths.Add(relativePath);
            Assert.IsFalse(retainedHandle.IsInvalid || retainedHandle.IsClosed);
            if (AttemptMutation)
            {
                try { File.AppendAllText(absolutePath, "altered"); }
                catch (IOException) { MutationDenied = true; }
            }
            return new(relativePath, Category, BetaReleaseRecordV2Codec.SigningPolicyId,
                PrimarySignatureCountPolicyCategory.ExactlyOne, TimestampPolicyCategory.ValidRfc3161);
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _temporary = Path.Combine(Path.GetTempPath(),
            "vantrel-task073-record-" + Guid.NewGuid().ToString("N"));
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly TrustedManifestV2File[] _files;
        internal string Layout { get; }
        internal string RecordPath => Path.Combine(Layout, BetaReleaseRecordV2Codec.FileName);
        internal ServiceReleaseV2BuildProvenance Provenance { get; } = new(Commit, "10.0.401",
            LockHash, "net10.0-windows", "win-x64", "framework-dependent");

        internal Fixture()
        {
            Directory.CreateDirectory(_temporary);
            var parent = Path.Combine(_temporary, "protected");
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(parent);
            Layout = Path.Combine(parent, "layout");
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Layout);
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Path.Combine(Layout, "service"));
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Path.Combine(Layout, "diagnostic-symbols"));
            WriteProtected("release-notes.md", "# Synthetic v2 notes\n"u8.ToArray());
            WriteProtected("service/" + ServicePublishFileSnapshot.DepsFileName,
                Encoding.UTF8.GetBytes(Dependencies));
            WriteProtected("service/" + ServicePublishFileSnapshot.RuntimeConfigFileName,
                Encoding.UTF8.GetBytes(RuntimeConfig));
            foreach (var name in new[] { "Vantrel.Security.Service.exe", "Vantrel.Security.Service.dll",
                "Vantrel.Security.Core.dll", "Vantrel.Security.Infrastructure.dll",
                "Microsoft.Extensions.Hosting.WindowsServices.dll", "Microsoft.Extensions.Hosting.dll",
                "System.ServiceProcess.ServiceController.dll", "appsettings.json" })
                WriteProtected("service/" + name, Encoding.ASCII.GetBytes(name));
            foreach (var name in new[] { "Vantrel.Security.Core.pdb",
                "Vantrel.Security.Infrastructure.pdb", "Vantrel.Security.Service.pdb" })
                WriteProtected("diagnostic-symbols/" + name, Encoding.ASCII.GetBytes(name));
            _files = Directory.EnumerateFiles(Path.Combine(Layout, "service"))
                .Select(path => new TrustedManifestV2File(Path.GetFileName(path), Hash(File.ReadAllBytes(path))))
                .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
            var notesHash = Hash(File.ReadAllBytes(Path.Combine(Layout, "release-notes.md")));
            WriteProtected(BetaReleaseDescriptorCodec.FileName, BetaReleaseDescriptorCodec.CreateCanonical(
                new BetaReleaseDescriptor(Commit, Version, 1, Published, "Release", "win-x64",
                    "10.0.401", notesHash)));
            var manifest = TrustedManifestV2Codec.CreateFile(Version, 1, _files, _manifestKey);
            WriteProtected(ServiceReleaseV2RecordGate.ManifestFileName, manifest);
            WriteProtected(ServiceReleaseV2RecordGate.MetadataFileName,
                ReleaseMetadataCodec.CreateFile(1, Hash(manifest), Version, Published, _metadataKey));
        }

        internal void ReplaceMetadataManifestHash(string newHash)
        {
            var path = Path.Combine(Layout, ServiceReleaseV2RecordGate.MetadataFileName);
            File.WriteAllBytes(path, ReleaseMetadataCodec.CreateFile(1, newHash, Version, Published, _metadataKey));
        }

        internal void ReplaceMetadataIdentity(ulong sequence, string displayVersion)
        {
            var manifest = File.ReadAllBytes(Path.Combine(Layout,
                ServiceReleaseV2RecordGate.ManifestFileName));
            var path = Path.Combine(Layout, ServiceReleaseV2RecordGate.MetadataFileName);
            File.WriteAllBytes(path, ReleaseMetadataCodec.CreateFile(sequence, Hash(manifest),
                displayVersion, Published, _metadataKey));
        }

        internal void WriteProtected(string relative, byte[] bytes)
        {
            var path = Path.Combine(Layout, relative.Replace('/', '\\'));
            File.WriteAllBytes(path, bytes);
            ServiceReleaseV2FileSystemSecurity.ProtectFile(path);
        }

        private static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));

        public void Dispose()
        {
            _manifestKey.Dispose();
            _metadataKey.Dispose();
            var temp = Path.GetFullPath(Path.GetTempPath());
            var root = Path.GetFullPath(_temporary);
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(root).StartsWith("vantrel-task073-record-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(root, recursive: true);
        }
    }
}
