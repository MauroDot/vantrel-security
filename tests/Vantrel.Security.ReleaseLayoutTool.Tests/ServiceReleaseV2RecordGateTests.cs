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
    private const string ManifestTestKeyPath = @"C:\synthetic-manifest-key.pk8";
    private const string MetadataTestKeyPath = @"C:\synthetic-metadata-key.pk8";
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
        var signatures = fixture.Signatures();
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
    public void Produced_v2_sidecars_with_two_independent_test_keys_are_accepted_by_Record()
    {
        using var fixture = new Fixture(withSignedSidecars: false);
        var keys = fixture.Keys();
        var producer = fixture.Producer(keys);
        var manifest = producer.SignManifest(fixture.Layout, fixture.Provenance,
            ManifestTestKeyPath);
        Assert.IsTrue(TrustedManifestV2Codec.TryParse(manifest, out var parsed, out _));
        Assert.IsTrue(TrustedManifestV2Codec.Verify(parsed!, fixture.ManifestPublicKey));
        CollectionAssert.AreEqual(manifest, File.ReadAllBytes(fixture.ManifestPath));
        Assert.IsFalse(File.Exists(fixture.MetadataPath));

        var metadata = producer.SignMetadata(fixture.Layout, fixture.Provenance,
            MetadataTestKeyPath);
        Assert.IsTrue(TrustedManifestV2Codec.VerifyBoundMetadata(manifest, metadata,
            fixture.ManifestPublicKey, fixture.MetadataPublicKey));
        CollectionAssert.AreEqual(metadata, File.ReadAllBytes(fixture.MetadataPath));
        Assert.IsFalse(File.Exists(fixture.RecordPath));
        CollectionAssert.AreEquivalent(new[]
        {
            BetaReleaseDescriptorCodec.FileName,
            BetaReleaseLayoutValidator.ReleaseNotesFileName,
            ServiceReleaseV2RecordGate.ManifestFileName,
            ServiceReleaseV2RecordGate.MetadataFileName
        }, Directory.GetFiles(fixture.Layout).Select(Path.GetFileName).ToArray());
        Assert.AreEqual(0, Directory.GetFiles(Path.GetDirectoryName(fixture.Layout)!, "*.tmp").Length);

        var record = new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(),
            fixture.Signatures(), new SyntheticAuthenticode())
            .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance);
        Assert.AreEqual(Convert.ToHexString(SHA256.HashData(manifest)), record.SignedManifestSha256);
        Assert.AreEqual(Convert.ToHexString(SHA256.HashData(metadata)), record.SignedMetadataSha256);
        Assert.IsTrue(BetaReleaseRecordV2Codec.TryParse(File.ReadAllBytes(fixture.RecordPath), out _));
        Assert.AreEqual(2, keys.Calls);
    }

    [TestMethod]
    public void Injected_manifest_prepublication_failures_leave_no_final_or_temporary_sidecar()
    {
        foreach (var stage in Enum.GetValues<ServiceReleaseV2PublicationCheckpoint>()
                     .Where(value => value != ServiceReleaseV2PublicationCheckpoint.ImmediatelyBeforeRename))
        {
            using var fixture = new Fixture(withSignedSidecars: false);
            var producer = fixture.Producer(fixture.Keys(), publicationCheckpoint: (at, temporary, _) =>
            {
                if (at != stage) return;
                if (at == ServiceReleaseV2PublicationCheckpoint.BeforeTemporaryReadback)
                    File.AppendAllText(temporary, "changed after protected write");
                else if (at == ServiceReleaseV2PublicationCheckpoint.BeforeFinalConsistency)
                    File.WriteAllText(Path.Combine(fixture.Layout, "unrecorded.txt"), "unexpected");
                else
                    throw new IOException("Injected verification failure.");
            });

            Assert.ThrowsException<IOException>(() => producer.SignManifest(fixture.Layout,
                fixture.Provenance, ManifestTestKeyPath), stage.ToString());
            Assert.IsFalse(File.Exists(fixture.ManifestPath), stage.ToString());
            Assert.AreEqual(0, Directory.GetFiles(Path.GetDirectoryName(fixture.Layout)!, "*.tmp").Length);
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), fixture.Signatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
    }

    [TestMethod]
    public void Injected_metadata_prepublication_failures_leave_no_final_or_temporary_sidecar()
    {
        foreach (var stage in Enum.GetValues<ServiceReleaseV2PublicationCheckpoint>()
                     .Where(value => value != ServiceReleaseV2PublicationCheckpoint.ImmediatelyBeforeRename))
        {
            using var fixture = new Fixture(withSignedSidecars: false);
            var keys = fixture.Keys();
            _ = fixture.Producer(keys).SignManifest(fixture.Layout, fixture.Provenance,
                ManifestTestKeyPath);
            var producer = fixture.Producer(keys, publicationCheckpoint: (at, temporary, _) =>
            {
                if (at != stage) return;
                if (at == ServiceReleaseV2PublicationCheckpoint.BeforeTemporaryReadback)
                    File.AppendAllText(temporary, "changed after protected write");
                else if (at == ServiceReleaseV2PublicationCheckpoint.BeforeFinalConsistency)
                    File.WriteAllText(Path.Combine(fixture.Layout, "unrecorded.txt"), "unexpected");
                else
                    throw new IOException("Injected verification failure.");
            });

            Assert.ThrowsException<IOException>(() => producer.SignMetadata(fixture.Layout,
                fixture.Provenance, MetadataTestKeyPath), stage.ToString());
            Assert.IsFalse(File.Exists(fixture.MetadataPath), stage.ToString());
            Assert.AreEqual(0, Directory.GetFiles(Path.GetDirectoryName(fixture.Layout)!, "*.tmp").Length);
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), fixture.Signatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
    }

    [TestMethod]
    public void Mutated_temporary_file_and_competing_final_destination_fail_closed()
    {
        using (var fixture = new Fixture(withSignedSidecars: false))
        {
            var producer = fixture.Producer(fixture.Keys(), publicationCheckpoint: (at, temporary, _) =>
            {
                if (at == ServiceReleaseV2PublicationCheckpoint.BeforeFinalMove)
                    File.AppendAllText(temporary, "late mutation");
            });
            Assert.ThrowsException<IOException>(() => producer.SignManifest(fixture.Layout,
                fixture.Provenance, ManifestTestKeyPath));
            Assert.IsFalse(File.Exists(fixture.ManifestPath));
            Assert.AreEqual(0, Directory.GetFiles(Path.GetDirectoryName(fixture.Layout)!, "*.tmp").Length);
        }
        using (var fixture = new Fixture(withSignedSidecars: false))
        {
            var competitor = "competing destination"u8.ToArray();
            var producer = fixture.Producer(fixture.Keys(), publicationCheckpoint: (at, _, final) =>
            {
                if (at == ServiceReleaseV2PublicationCheckpoint.ImmediatelyBeforeRename)
                    fixture.WriteProtected(ServiceReleaseV2RecordGate.ManifestFileName, competitor);
            });
            Assert.ThrowsException<IOException>(() => producer.SignManifest(fixture.Layout,
                fixture.Provenance, ManifestTestKeyPath));
            CollectionAssert.AreEqual(competitor, File.ReadAllBytes(fixture.ManifestPath));
            Assert.AreEqual(0, Directory.GetFiles(Path.GetDirectoryName(fixture.Layout)!, "*.tmp").Length);
        }
        using (var fixture = new Fixture(withSignedSidecars: false))
        {
            var keys = fixture.Keys();
            _ = fixture.Producer(keys).SignManifest(fixture.Layout, fixture.Provenance,
                ManifestTestKeyPath);
            var competitor = "competing metadata destination"u8.ToArray();
            var producer = fixture.Producer(keys, publicationCheckpoint: (at, _, _) =>
            {
                if (at == ServiceReleaseV2PublicationCheckpoint.ImmediatelyBeforeRename)
                    fixture.WriteProtected(ServiceReleaseV2RecordGate.MetadataFileName, competitor);
            });
            Assert.ThrowsException<IOException>(() => producer.SignMetadata(fixture.Layout,
                fixture.Provenance, MetadataTestKeyPath));
            CollectionAssert.AreEqual(competitor, File.ReadAllBytes(fixture.MetadataPath));
            Assert.AreEqual(0, Directory.GetFiles(Path.GetDirectoryName(fixture.Layout)!, "*.tmp").Length);
        }
    }

    [TestMethod]
    public void A_competing_reparse_destination_is_not_replaced_when_privilege_is_available()
    {
        using var fixture = new Fixture(withSignedSidecars: false);
        var target = Path.Combine(fixture.Layout, BetaReleaseLayoutValidator.ReleaseNotesFileName);
        var original = File.ReadAllBytes(target);
        var probe = Path.Combine(Path.GetDirectoryName(fixture.Layout)!, "symlink-probe-" +
            Guid.NewGuid().ToString("N"));
        try { File.CreateSymbolicLink(probe, target); }
        catch (Exception failure) when (failure.HResult == unchecked((int)0x80070522))
        {
            Assert.Inconclusive("File-symbolic-link privilege unavailable.");
            return;
        }
        File.Delete(probe);
        var producer = fixture.Producer(fixture.Keys(), publicationCheckpoint: (at, _, final) =>
        {
            if (at == ServiceReleaseV2PublicationCheckpoint.ImmediatelyBeforeRename)
                File.CreateSymbolicLink(final, target);
        });

        Assert.ThrowsException<IOException>(() => producer.SignManifest(fixture.Layout,
            fixture.Provenance, ManifestTestKeyPath));
        Assert.IsTrue((File.GetAttributes(fixture.ManifestPath) & FileAttributes.ReparsePoint) != 0);
        CollectionAssert.AreEqual(original, File.ReadAllBytes(target));
        Assert.AreEqual(0, Directory.GetFiles(Path.GetDirectoryName(fixture.Layout)!, "*.tmp").Length);
    }

    [TestMethod]
    public void Failed_temporary_cleanup_cannot_create_final_sidecar_or_Record_evidence()
    {
        using var fixture = new Fixture(withSignedSidecars: false);
        FileStream? held = null;
        var producer = fixture.Producer(fixture.Keys(), publicationCheckpoint: (at, temporary, _) =>
        {
            if (at != ServiceReleaseV2PublicationCheckpoint.BeforeTemporaryVerification) return;
            held = new FileStream(temporary, FileMode.Open, FileAccess.Read, FileShare.None);
            throw new IOException("Injected verification failure with locked temporary.");
        });
        try
        {
            Assert.ThrowsException<IOException>(() => producer.SignManifest(fixture.Layout,
                fixture.Provenance, ManifestTestKeyPath));
            Assert.IsFalse(File.Exists(fixture.ManifestPath));
            var temporary = Directory.GetFiles(Path.GetDirectoryName(fixture.Layout)!, "*.tmp");
            Assert.AreEqual(1, temporary.Length);
            Assert.IsFalse(Path.GetFullPath(temporary[0]).StartsWith(
                Path.GetFullPath(fixture.Layout) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase));
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), fixture.Signatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        finally { held?.Dispose(); }
    }

    [TestMethod]
    public void Explicit_sidecar_cli_runs_both_producer_paths_without_signing_processes_or_v1_fallback()
    {
        using var fixture = new Fixture(withSignedSidecars: false);
        var keys = fixture.Keys();
        var producer = fixture.Producer(keys);
        var signer = new ForbiddenProcessRunner();
        var builder = new ForbiddenBuildRunner();
        var sourceRoot = Path.Combine(Path.GetDirectoryName(fixture.Layout)!, "synthetic-source");
        (ServiceReleaseV2BuildProvenance, ServiceReleaseV2SidecarProducer) Factory(
            string source, string commit, string outputRoot)
        {
            Assert.AreEqual(sourceRoot, source);
            Assert.AreEqual(Commit, commit);
            Assert.AreEqual(fixture.Layout, outputRoot);
            return (fixture.Provenance, producer);
        }
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.AreEqual(0, ReleaseLayoutToolCommand.RunForV2Tests(
            ["sign-v2-service-manifest", "--source-root", sourceRoot, "--source-commit", Commit,
                "--output-root", fixture.Layout, "--private-key", ManifestTestKeyPath],
            signer, output, error, builder, Factory));
        Assert.AreEqual("V2 Service manifest signature and final inventory verified. Use a separate clean source checkout to sign bound release metadata."
            + Environment.NewLine, output.ToString());
        Assert.AreEqual(string.Empty, error.ToString());
        output.GetStringBuilder().Clear();
        Assert.AreEqual(0, ReleaseLayoutToolCommand.RunForV2Tests(
            ["sign-v2-release-metadata", "--source-root", sourceRoot, "--source-commit", Commit,
                "--output-root", fixture.Layout, "--private-key", MetadataTestKeyPath],
            signer, output, error, builder, Factory));
        Assert.AreEqual("V2 release metadata signature and full signed-manifest binding verified. Invoke record-v2-service separately from a clean source checkout."
            + Environment.NewLine, output.ToString());
        Assert.AreEqual(string.Empty, error.ToString());
        Assert.IsFalse((output.ToString() + error).Contains("synthetic-", StringComparison.Ordinal));
        Assert.IsFalse(File.Exists(fixture.RecordPath));
        Assert.AreEqual(0, signer.Calls);
        Assert.AreEqual(0, builder.Calls);
        Assert.AreEqual(2, keys.Calls);
    }

    [TestMethod]
    public void Explicit_sidecar_cli_reports_only_sanitized_failure_for_a_wrong_purpose_key()
    {
        using var fixture = new Fixture(withSignedSidecars: false);
        var keys = fixture.Keys();
        keys.WrongManifestKey = true;
        var sourceRoot = Path.Combine(Path.GetDirectoryName(fixture.Layout)!, "synthetic-source");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var status = ReleaseLayoutToolCommand.RunForV2Tests(
            ["sign-v2-service-manifest", "--source-root", sourceRoot, "--source-commit", Commit,
                "--output-root", fixture.Layout, "--private-key", ManifestTestKeyPath],
            new ForbiddenProcessRunner(), output, error, new ForbiddenBuildRunner(),
            (_, _, _) => (fixture.Provenance, fixture.Producer(keys)));

        Assert.AreEqual(1, status);
        Assert.AreEqual(string.Empty, output.ToString());
        Assert.AreEqual("Beta release layout operation failed." + Environment.NewLine,
            error.ToString());
        Assert.IsFalse(error.ToString().Contains(ManifestTestKeyPath, StringComparison.Ordinal));
        Assert.IsFalse(File.Exists(fixture.ManifestPath));
    }

    [TestMethod]
    public void A_failed_completion_message_cannot_report_failure_after_publication()
    {
        using var fixture = new Fixture(withSignedSidecars: false);
        var producer = fixture.Producer(fixture.Keys());
        var sourceRoot = Path.Combine(Path.GetDirectoryName(fixture.Layout)!, "synthetic-source");
        using var output = new FailingCompletionWriter();
        using var error = new StringWriter();
        foreach (var (verb, keyPath, finalPath) in new[]
        {
            ("sign-v2-service-manifest", ManifestTestKeyPath, fixture.ManifestPath),
            ("sign-v2-release-metadata", MetadataTestKeyPath, fixture.MetadataPath)
        })
        {
            var status = ReleaseLayoutToolCommand.RunForV2Tests(
                [verb, "--source-root", sourceRoot, "--source-commit", Commit,
                    "--output-root", fixture.Layout, "--private-key", keyPath],
                new ForbiddenProcessRunner(), output, error, new ForbiddenBuildRunner(),
                (_, _, _) => (fixture.Provenance, producer));
            Assert.AreEqual(0, status);
            Assert.IsTrue(File.Exists(finalPath));
        }
        Assert.AreEqual(string.Empty, error.ToString());
        Assert.IsFalse(File.Exists(fixture.RecordPath));
    }

    [TestMethod]
    public void Metadata_cannot_precede_verified_manifest_and_sidecars_cannot_be_overwritten()
    {
        using var fixture = new Fixture(withSignedSidecars: false);
        var keys = fixture.Keys();
        var producer = fixture.Producer(keys);
        Assert.ThrowsException<IOException>(() => producer.SignMetadata(fixture.Layout,
            fixture.Provenance, MetadataTestKeyPath));
        Assert.AreEqual(0, keys.Calls);
        Assert.IsFalse(File.Exists(fixture.MetadataPath));

        var manifest = producer.SignManifest(fixture.Layout, fixture.Provenance,
            ManifestTestKeyPath);
        Assert.ThrowsException<IOException>(() => producer.SignManifest(fixture.Layout,
            fixture.Provenance, ManifestTestKeyPath));
        CollectionAssert.AreEqual(manifest, File.ReadAllBytes(fixture.ManifestPath));

        var metadata = producer.SignMetadata(fixture.Layout, fixture.Provenance,
            MetadataTestKeyPath);
        Assert.ThrowsException<IOException>(() => producer.SignMetadata(fixture.Layout,
            fixture.Provenance, MetadataTestKeyPath));
        CollectionAssert.AreEqual(metadata, File.ReadAllBytes(fixture.MetadataPath));
        Assert.AreEqual(2, keys.Calls);
    }

    [TestMethod]
    public void Wrong_test_key_cannot_publish_either_v2_sidecar()
    {
        using (var fixture = new Fixture(withSignedSidecars: false))
        {
            var keys = fixture.Keys();
            keys.WrongManifestKey = true;
            Assert.ThrowsException<IOException>(() => fixture.Producer(keys).SignManifest(
                fixture.Layout, fixture.Provenance, ManifestTestKeyPath));
            Assert.IsFalse(File.Exists(fixture.ManifestPath));
        }
        using (var fixture = new Fixture(withSignedSidecars: false))
        {
            var keys = fixture.Keys();
            var producer = fixture.Producer(keys);
            _ = producer.SignManifest(fixture.Layout, fixture.Provenance, ManifestTestKeyPath);
            keys.WrongMetadataKey = true;
            Assert.ThrowsException<IOException>(() => producer.SignMetadata(
                fixture.Layout, fixture.Provenance, MetadataTestKeyPath));
            Assert.IsFalse(File.Exists(fixture.MetadataPath));
        }
    }

    [TestMethod]
    public void Invalid_Authenticode_blocks_manifest_before_key_acquisition()
    {
        using var fixture = new Fixture(withSignedSidecars: false);
        var keys = fixture.Keys();
        var authenticode = new SyntheticAuthenticode
        {
            Category = AuthenticodeVerificationCategory.MissingTimestamp
        };
        Assert.ThrowsException<IOException>(() => fixture.Producer(keys, authenticode).SignManifest(
            fixture.Layout, fixture.Provenance, ManifestTestKeyPath));
        Assert.AreEqual(1, authenticode.Paths.Count);
        Assert.AreEqual(0, keys.Calls);
        Assert.IsFalse(File.Exists(fixture.ManifestPath));
    }

    [TestMethod]
    public void Malformed_or_v1_manifest_blocks_metadata_before_key_acquisition()
    {
        foreach (var replacement in new[]
        {
            "malformed\n"u8.ToArray(),
            "schema=vantrel-trusted-manifest-v1\n"u8.ToArray()
        })
        {
            using var fixture = new Fixture(withSignedSidecars: false);
            var keys = fixture.Keys();
            var producer = fixture.Producer(keys);
            _ = producer.SignManifest(fixture.Layout, fixture.Provenance, ManifestTestKeyPath);
            Assert.AreEqual(1, keys.Calls);
            fixture.WriteProtected(ServiceReleaseV2RecordGate.ManifestFileName, replacement);
            Assert.ThrowsException<IOException>(() => producer.SignMetadata(fixture.Layout,
                fixture.Provenance, MetadataTestKeyPath));
            Assert.AreEqual(1, keys.Calls);
            Assert.IsFalse(File.Exists(fixture.MetadataPath));
        }
    }

    [TestMethod]
    public void Mutated_final_Service_or_descriptor_fails_before_external_key_is_opened()
    {
        using (var fixture = new Fixture(withSignedSidecars: false))
        {
            fixture.WriteProtected("service/Microsoft.Extensions.Hosting.dll", "altered"u8.ToArray());
            var keys = fixture.Keys();
            Assert.ThrowsException<IOException>(() => fixture.Producer(keys).SignManifest(
                fixture.Layout, fixture.Provenance, ManifestTestKeyPath));
            Assert.AreEqual(0, keys.Calls);
            Assert.IsFalse(File.Exists(fixture.ManifestPath));
        }
        using (var fixture = new Fixture(withSignedSidecars: false))
        {
            fixture.WriteProtected("service/" + ServicePublishFileSnapshot.RuntimeConfigFileName,
                Encoding.UTF8.GetBytes(RuntimeConfig.Replace("Microsoft.NETCore.App", "Wrong.Framework",
                    StringComparison.Ordinal)));
            var keys = fixture.Keys();
            Assert.ThrowsException<IOException>(() => fixture.Producer(keys).SignManifest(
                fixture.Layout, fixture.Provenance, ManifestTestKeyPath));
            Assert.AreEqual(0, keys.Calls);
            Assert.IsFalse(File.Exists(fixture.ManifestPath));
        }
        using (var fixture = new Fixture(withSignedSidecars: false))
        {
            fixture.WriteProtected(BetaReleaseDescriptorCodec.FileName, "invalid"u8.ToArray());
            var keys = fixture.Keys();
            Assert.ThrowsException<IOException>(() => fixture.Producer(keys).SignManifest(
                fixture.Layout, fixture.Provenance, ManifestTestKeyPath));
            Assert.AreEqual(0, keys.Calls);
            Assert.IsFalse(File.Exists(fixture.ManifestPath));
        }
    }

    [TestMethod]
    public void Post_manifest_Service_mutation_blocks_metadata_and_Record()
    {
        using var fixture = new Fixture(withSignedSidecars: false);
        var keys = fixture.Keys();
        var producer = fixture.Producer(keys);
        _ = producer.SignManifest(fixture.Layout, fixture.Provenance, ManifestTestKeyPath);
        fixture.WriteProtected("service/Microsoft.Extensions.Hosting.dll", "changed"u8.ToArray());
        Assert.ThrowsException<IOException>(() => producer.SignMetadata(fixture.Layout,
            fixture.Provenance, MetadataTestKeyPath));
        Assert.AreEqual(1, keys.Calls);
        Assert.IsFalse(File.Exists(fixture.MetadataPath));
        Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
            new SyntheticSourceBinding(), fixture.Signatures(), new SyntheticAuthenticode())
            .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
        Assert.IsFalse(File.Exists(fixture.RecordPath));
    }

    [TestMethod]
    public void Wrong_manifest_signature_or_metadata_binding_cannot_write_record()
    {
        using (var fixture = new Fixture())
        {
            fixture.ReplaceManifestSignedByWrongKey();
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(), fixture.Signatures(),
                new SyntheticAuthenticode()).ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            fixture.ReplaceMetadataManifestHash(new string('F', 64));
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(), fixture.Signatures(),
                new SyntheticAuthenticode()).ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
    }

    [TestMethod]
    public void Wrong_metadata_signature_cannot_write_record()
    {
        using var fixture = new Fixture();
        fixture.ReplaceMetadataSignedByWrongKey();
        Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(),
            fixture.Signatures(), new SyntheticAuthenticode())
            .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
        Assert.IsFalse(File.Exists(fixture.RecordPath));
    }

    [TestMethod]
    public void Different_valid_signature_over_same_manifest_payload_breaks_full_file_metadata_binding()
    {
        using var fixture = new Fixture();
        fixture.ResignManifestWithoutUpdatingMetadata();
        Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(),
            fixture.Signatures(), new SyntheticAuthenticode())
            .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
        Assert.IsFalse(File.Exists(fixture.RecordPath));
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
                fixture.Signatures(), authenticode)
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.AreEqual(1, authenticode.Paths.Count);
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            File.Delete(Path.Combine(fixture.Layout, "service", "Microsoft.Extensions.Hosting.dll"));
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(),
                fixture.Signatures(), new SyntheticAuthenticode())
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
                fixture.Signatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            fixture.WriteProtected(BetaReleaseRecordV2Codec.FileName, "existing"u8.ToArray());
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(new SyntheticSourceBinding(),
                fixture.Signatures(), new SyntheticAuthenticode())
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
            fixture.Signatures(), authenticode)
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
                new SyntheticSourceBinding(), fixture.Signatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            File.AppendAllText(Path.Combine(fixture.Layout, "service",
                "Vantrel.Security.Service.dll"), "changed");
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), fixture.Signatures(), new SyntheticAuthenticode())
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
                new SyntheticSourceBinding(), fixture.Signatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            fixture.ReplaceMetadataIdentity(1, "0.1.0-beta.2");
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), fixture.Signatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            fixture.ReplaceSignedPairIdentity(2, Version);
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), fixture.Signatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
        using (var fixture = new Fixture())
        {
            fixture.ReplaceSignedPairIdentity(1, "0.1.0-beta.2");
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2RecordGate(
                new SyntheticSourceBinding(), fixture.Signatures(), new SyntheticAuthenticode())
                .ValidateAndWriteRecord(fixture.Layout, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.RecordPath));
        }
    }

    private sealed class SyntheticSignatures : IServiceReleaseV2SignatureGate
    {
        private readonly byte[] _manifestPublicKey;
        private readonly byte[] _metadataPublicKey;

        internal SyntheticSignatures(byte[] manifestPublicKey, byte[] metadataPublicKey)
        {
            _manifestPublicKey = manifestPublicKey.ToArray();
            _metadataPublicKey = metadataPublicKey.ToArray();
        }

        internal int Calls { get; private set; }
        public bool Verify(ReadOnlySpan<byte> manifestBytes, ReadOnlySpan<byte> metadataBytes)
        {
            Calls++;
            return TrustedManifestV2Codec.VerifyBoundMetadata(manifestBytes, metadataBytes,
                _manifestPublicKey, _metadataPublicKey);
        }
    }

    private sealed class SyntheticPrivateKeys(Fixture fixture) : IServiceReleaseV2PrivateKeyProvider
    {
        internal int Calls { get; private set; }
        internal bool WrongManifestKey { get; set; }
        internal bool WrongMetadataKey { get; set; }

        public ECDsa OpenKey(string absolutePath)
        {
            Calls++;
            return absolutePath switch
            {
                ManifestTestKeyPath => WrongManifestKey ? ECDsa.Create(ECCurve.NamedCurves.nistP256) :
                    fixture.CloneManifestKey(),
                MetadataTestKeyPath => WrongMetadataKey ? ECDsa.Create(ECCurve.NamedCurves.nistP256) :
                    fixture.CloneMetadataKey(),
                _ => throw new IOException("An unexpected synthetic key path was requested.")
            };
        }
    }

    private sealed class ForbiddenProcessRunner : IAzureArtifactSigningProcessRunner
    {
        internal int Calls { get; private set; }
        public int Run(string executablePath, IReadOnlyList<string> arguments)
        {
            Calls++;
            throw new IOException("No process execution is expected.");
        }
    }

    private sealed class FailingCompletionWriter : StringWriter
    {
        public override void WriteLine(string? value) =>
            throw new IOException("Injected completion-output failure.");
    }

    private sealed class ForbiddenBuildRunner : IReleaseV2CommandRunner
    {
        internal int Calls { get; private set; }
        public ReleaseV2CommandResult Run(string executable, IReadOnlyList<string> arguments,
            string workingDirectory, bool captureStandardOutput)
        {
            Calls++;
            throw new IOException("No build execution is expected.");
        }
        public ReleaseV2CommandResult RunWithInput(string executable,
            IReadOnlyList<string> arguments, string workingDirectory, Stream standardInput)
        {
            Calls++;
            throw new IOException("No build execution is expected.");
        }
    }

    private sealed class SyntheticSourceBinding : IServiceReleaseV2SourceBinding
    {
        private readonly TrustedManifestV2File[]? _expectedService;

        internal SyntheticSourceBinding(IReadOnlyList<TrustedManifestV2File>? expectedService = null) =>
            _expectedService = expectedService?.ToArray();

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
            if (_expectedService is not null && !_expectedService.SequenceEqual(serviceFiles))
                throw new IOException("Synthetic source inventory changed.");
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
        internal string ManifestPath => Path.Combine(Layout, ServiceReleaseV2RecordGate.ManifestFileName);
        internal string MetadataPath => Path.Combine(Layout, ServiceReleaseV2RecordGate.MetadataFileName);
        internal ServiceReleaseV2BuildProvenance Provenance { get; } = new(Commit, "10.0.401",
            LockHash, "net10.0-windows", "win-x64", "framework-dependent");
        internal byte[] ManifestPublicKey => _manifestKey.ExportSubjectPublicKeyInfo();
        internal byte[] MetadataPublicKey => _metadataKey.ExportSubjectPublicKeyInfo();
        internal SyntheticSignatures Signatures() => new(_manifestKey.ExportSubjectPublicKeyInfo(),
            _metadataKey.ExportSubjectPublicKeyInfo());
        internal SyntheticPrivateKeys Keys() => new(this);
        internal ServiceReleaseV2SidecarProducer Producer(SyntheticPrivateKeys keys,
            SyntheticAuthenticode? authenticode = null,
            Action<ServiceReleaseV2PublicationCheckpoint, string, string>? publicationCheckpoint = null) =>
            new(new SyntheticSourceBinding(_files), authenticode ?? new SyntheticAuthenticode(), keys,
                ManifestPublicKey, MetadataPublicKey, publicationCheckpoint);
        internal ECDsa CloneManifestKey() => CloneKey(_manifestKey);
        internal ECDsa CloneMetadataKey() => CloneKey(_metadataKey);

        internal Fixture(bool withSignedSidecars = true)
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
            if (withSignedSidecars)
            {
                var manifest = TrustedManifestV2Codec.CreateFile(Version, 1, _files, _manifestKey);
                WriteProtected(ServiceReleaseV2RecordGate.ManifestFileName, manifest);
                WriteProtected(ServiceReleaseV2RecordGate.MetadataFileName,
                    ReleaseMetadataCodec.CreateFile(1, Hash(manifest), Version, Published, _metadataKey));
            }
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

        internal void ReplaceManifestSignedByWrongKey()
        {
            using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            WriteProtected(ServiceReleaseV2RecordGate.ManifestFileName,
                TrustedManifestV2Codec.CreateFile(Version, 1, _files, wrongKey));
        }

        internal void ReplaceMetadataSignedByWrongKey()
        {
            using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var manifest = File.ReadAllBytes(Path.Combine(Layout,
                ServiceReleaseV2RecordGate.ManifestFileName));
            WriteProtected(ServiceReleaseV2RecordGate.MetadataFileName,
                ReleaseMetadataCodec.CreateFile(1, Hash(manifest), Version, Published, wrongKey));
        }

        internal void ResignManifestWithoutUpdatingMetadata()
        {
            var path = Path.Combine(Layout, ServiceReleaseV2RecordGate.ManifestFileName);
            var original = File.ReadAllBytes(path);
            var canonical = TrustedManifestV2Codec.CreateCanonicalPayload(Version, 1, _files);
            byte[] replacement = [];
            for (var attempt = 0; attempt < 16; attempt++)
            {
                replacement = TrustedManifestV2Codec.CreateFile(Version, 1, _files, _manifestKey);
                if (!replacement.AsSpan().SequenceEqual(original)) break;
            }
            Assert.IsFalse(replacement.AsSpan().SequenceEqual(original));
            Assert.IsTrue(original.AsSpan(0, canonical.Length).SequenceEqual(canonical));
            Assert.IsTrue(replacement.AsSpan(0, canonical.Length).SequenceEqual(canonical));
            Assert.IsTrue(TrustedManifestV2Codec.TryParse(replacement, out var parsed, out _));
            Assert.IsTrue(TrustedManifestV2Codec.Verify(parsed!, _manifestKey.ExportSubjectPublicKeyInfo()));
            Assert.AreNotEqual(Hash(original), Hash(replacement));
            var metadata = File.ReadAllBytes(Path.Combine(Layout,
                ServiceReleaseV2RecordGate.MetadataFileName));
            Assert.IsTrue(ReleaseMetadataCodec.TryParse(metadata, out var parsedMetadata, out _));
            Assert.IsTrue(ReleaseMetadataCodec.Verify(parsedMetadata!,
                _metadataKey.ExportSubjectPublicKeyInfo()));
            Assert.AreEqual(Hash(original), parsedMetadata!.ManifestSha256);
            WriteProtected(ServiceReleaseV2RecordGate.ManifestFileName, replacement);
        }

        internal void ReplaceSignedPairIdentity(ulong sequence, string version)
        {
            var manifest = TrustedManifestV2Codec.CreateFile(version, sequence, _files, _manifestKey);
            WriteProtected(ServiceReleaseV2RecordGate.ManifestFileName, manifest);
            WriteProtected(ServiceReleaseV2RecordGate.MetadataFileName,
                ReleaseMetadataCodec.CreateFile(sequence, Hash(manifest), version, Published,
                    _metadataKey));
        }

        internal void WriteProtected(string relative, byte[] bytes)
        {
            var path = Path.Combine(Layout, relative.Replace('/', '\\'));
            File.WriteAllBytes(path, bytes);
            ServiceReleaseV2FileSystemSecurity.ProtectFile(path);
        }

        private static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));

        private static ECDsa CloneKey(ECDsa source)
        {
            var clone = ECDsa.Create();
            try { clone.ImportParameters(source.ExportParameters(true)); return clone; }
            catch { clone.Dispose(); throw; }
        }

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
