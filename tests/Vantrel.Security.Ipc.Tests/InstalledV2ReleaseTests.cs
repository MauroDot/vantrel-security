using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class InstalledV2ReleaseTests
{
    [TestMethod]
    public async Task Complete_nested_v2_tree_authenticates_and_bootstraps_generation_policy()
    {
        using var scope = new Scope();
        scope.WriteV2();
        var evidence = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
        Assert.AreEqual(TrustedManifestSignatureState.Valid, evidence.Snapshot.SignatureState);
        Assert.AreEqual(TrustedManifestInstallationEvaluation.AllMatch, evidence.Snapshot.Evaluation);
        Assert.AreEqual(ReleaseGeneration.V2, evidence.Identity?.Generation);
        Assert.AreEqual(7UL, evidence.Identity?.ReleaseSequence);
        Assert.AreEqual(scope.ManifestHash, evidence.Identity?.ManifestSha256);
        Assert.IsTrue(StatusProtocol.TryReadTrustedManifestIntegrityResponse(
            StatusProtocol.CreateTrustedManifestIntegrityResponse(evidence.Snapshot), out var wireIntegrity, out _));
        Assert.AreEqual(StatusProtocol.TrustedManifestIntegrityPolicyRevisionV2, wireIntegrity!.PolicyRevision);
        var provenance = await scope.Provenance.CollectAsync(CancellationToken.None);
        Assert.AreEqual(ReleaseManifestBindingState.Bound, provenance.ManifestBindingState);
        Assert.AreEqual(ReleasePolicyDecision.BootstrapAccepted, provenance.PolicyDecision);
        Assert.IsTrue(StatusProtocol.TryReadReleaseMetadataResponse(
            StatusProtocol.CreateReleaseMetadataResponse(provenance), out _, out _));
        var persisted = File.ReadAllBytes(scope.PolicyPath);
        Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease,
            (await scope.Provenance.CollectAsync(CancellationToken.None)).PolicyDecision);
        CollectionAssert.AreEqual(persisted, File.ReadAllBytes(scope.PolicyPath));
        Assert.IsTrue(GenerationAwareReleasePolicyCodec.TryParse(persisted, out var policy, out _));
        Assert.AreEqual(ReleaseGeneration.V2, policy!.Identity.Generation);
        Assert.AreEqual(scope.ManifestHash, policy.Identity.ManifestSha256);
        Assert.IsFalse(ReleasePolicyCodec.TryParse(persisted, out _, out _));
    }

    [TestMethod]
    public async Task Missing_changed_extra_and_build_residue_files_fail_closed()
    {
        foreach (var mutation in new Action<Scope>[]
        {
            scope => File.Delete(Path.Combine(scope.Install, "deps", "Microsoft.Extensions.Hosting.dll")),
            scope => File.WriteAllText(Path.Combine(scope.Install, "deps", "Microsoft.Extensions.Hosting.dll"), "changed"),
            scope => File.WriteAllText(Path.Combine(scope.Install, "extra.dll"), "extra"),
            scope => File.WriteAllText(Path.Combine(scope.Install, "symbols.pdb"), "pdb"),
            scope => File.WriteAllText(Path.Combine(scope.Install, "packages.lock.json"), "lock"),
            scope => Directory.CreateDirectory(Path.Combine(scope.Install, "unexpected"))
        })
        {
            using var scope = new Scope();
            scope.WriteV2(); mutation(scope);
            var result = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
            Assert.AreNotEqual(TrustedManifestInstallationEvaluation.AllMatch, result.Snapshot.Evaluation);
            Assert.IsTrue(StatusProtocol.TryReadTrustedManifestIntegrityResponse(
                StatusProtocol.CreateTrustedManifestIntegrityResponse(result.Snapshot), out _, out _));
            Assert.IsNull(result.Identity);
            Assert.IsFalse(File.Exists(scope.PolicyPath));
        }
    }

    [TestMethod]
    public async Task Metadata_and_manifest_signature_and_binding_failures_cannot_bootstrap()
    {
        var caseIndex = 0;
        foreach (var mutation in new Action<Scope>[]
        {
            scope => File.Delete(scope.MetadataPath),
            scope => File.WriteAllText(scope.MetadataPath, "invalid"),
            scope => scope.WriteMetadata(version: "0.1.0-beta.3"),
            scope => scope.WriteMetadata(sequence: 8),
            scope => scope.WriteMetadata(hash: new string('A', 64)),
            scope => scope.WriteMetadata(wrongKey: true),
            scope => scope.CorruptManifestSignature(),
            scope => scope.WriteUnknownManifestSchema()
        })
        {
            using var scope = new Scope();
            scope.WriteV2(); mutation(scope);
            var integrity = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
            Assert.AreNotEqual(TrustedManifestInstallationEvaluation.AllMatch, integrity.Snapshot.Evaluation);
            Assert.IsTrue(StatusProtocol.TryReadTrustedManifestIntegrityResponse(
                StatusProtocol.CreateTrustedManifestIntegrityResponse(integrity.Snapshot), out _, out _),
                "mutation=" + caseIndex + " state=" + integrity.Snapshot.SignatureState + "/" + integrity.Snapshot.Evaluation);
            var provenance = await scope.Provenance.CollectAsync(CancellationToken.None);
            Assert.AreNotEqual(ReleasePolicyDecision.BootstrapAccepted, provenance.PolicyDecision);
            Assert.IsFalse(File.Exists(scope.PolicyPath));
            caseIndex++;
        }
    }

    [TestMethod]
    public async Task Wrong_manifest_and_metadata_signatures_are_distinguished_from_missing_inventory()
    {
        using (var scope = new Scope())
        {
            scope.WriteV2(); scope.CorruptManifestSignature();
            var result = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
            Assert.AreEqual(TrustedManifestSignatureState.SignatureInvalid, result.Snapshot.SignatureState);
            Assert.IsNull(result.Identity);
        }
        using (var scope = new Scope())
        {
            scope.WriteV2(); scope.WriteMetadata(wrongKey: true);
            var result = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
            Assert.AreEqual(TrustedManifestSignatureState.Valid, result.Snapshot.SignatureState);
            Assert.AreEqual(TrustedManifestInstallationEvaluation.ManifestInvalid, result.Snapshot.Evaluation);
            var provenance = await scope.Provenance.CollectAsync(CancellationToken.None);
            Assert.AreEqual(ReleaseMetadataSignatureState.SignatureInvalid, provenance.MetadataSignatureState);
            Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, provenance.PolicyDecision);
        }
    }

    [TestMethod]
    public async Task V2_policy_does_not_get_created_over_existing_v1_policy()
    {
        using var scope = new Scope(); scope.WriteV2();
        Directory.CreateDirectory(Path.GetDirectoryName(scope.PolicyPath)!);
        var historical = ReleasePolicyCodec.Serialize(new(7, scope.ManifestHash));
        File.WriteAllBytes(scope.PolicyPath, historical);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var provenance = await scope.Provenance.CollectAsync(CancellationToken.None);
            Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, provenance.PolicyDecision);
            CollectionAssert.AreEqual(historical, File.ReadAllBytes(scope.PolicyPath));
        }
        Assert.IsTrue(ReleasePolicyCodec.TryParse(File.ReadAllBytes(scope.PolicyPath), out _, out _));
        Assert.IsFalse(GenerationAwareReleasePolicyCodec.TryParse(File.ReadAllBytes(scope.PolicyPath), out _, out _));
    }

    [TestMethod]
    public async Task Physical_case_variant_cannot_match_signed_inventory()
    {
        using var scope = new Scope(); scope.WriteV2(physicalHostingName: "microsoft.extensions.hosting.dll");
        var result = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
        Assert.AreNotEqual(TrustedManifestInstallationEvaluation.AllMatch, result.Snapshot.Evaluation);
    }

    [TestMethod]
    public async Task Signed_inventory_cannot_promote_pdb_or_lockfile_to_runtime_payload()
    {
        foreach (var name in new[] { "symbols.pdb", "packages.lock.json" })
        {
            using var scope = new Scope(); scope.WriteV2WithSignedResidue(name);
            var result = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
            Assert.AreEqual(TrustedManifestInstallationEvaluation.ManifestInvalid, result.Snapshot.Evaluation);
            Assert.IsNull(result.Identity);
        }
    }

    [TestMethod]
    public async Task Authenticated_v1_policy_is_projected_and_evaluated_without_rewriting_historical_bytes()
    {
        using var scope = new Scope(); scope.WriteV1();
        var trusted = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
        Assert.AreEqual(TrustedManifestInstallationEvaluation.AllMatch, trusted.Snapshot.Evaluation);
        Assert.IsTrue(ReleaseMetadataCodec.TryParse(File.ReadAllBytes(scope.MetadataPath), out var metadata, out _));
        var verified = AuthenticatedInstalledRelease.FromVerifiedObservation(trusted, metadata!, scope.MetadataPublicKey);
        Assert.IsNotNull(verified);
        Assert.AreEqual(ReleaseGeneration.V1, verified.Identity.Generation);
        var store = scope.NewPolicyStore();
        Directory.CreateDirectory(Path.GetDirectoryName(scope.PolicyPath)!);
        var mismatchBytes = ReleasePolicyCodec.Serialize(new(7, new string('A', 64)));
        File.WriteAllBytes(scope.PolicyPath, mismatchBytes);
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict,
            await store.EvaluateAuthenticatedV1Async(verified, CancellationToken.None));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict,
            (await scope.Provenance.CollectAsync(CancellationToken.None)).PolicyDecision);
        CollectionAssert.AreEqual(mismatchBytes, File.ReadAllBytes(scope.PolicyPath));

        var historicalBytes = ReleasePolicyCodec.Serialize(new(7, scope.ManifestHash));
        File.WriteAllBytes(scope.PolicyPath, historicalBytes);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease,
                await store.EvaluateAuthenticatedV1Async(verified, CancellationToken.None));
            Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease,
                (await scope.Provenance.CollectAsync(CancellationToken.None)).PolicyDecision);
            Assert.AreEqual(TrustedManifestInstallationEvaluation.AllMatch,
                (await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None)).Snapshot.Evaluation);
            CollectionAssert.AreEqual(historicalBytes, File.ReadAllBytes(scope.PolicyPath));
        }
        Assert.AreEqual(new GenerationAwareReleasePolicyRecord(new(ReleaseGeneration.V1, 7, scope.ManifestHash)),
            store.GenerationSnapshot());
        var durable = await scope.NewPolicyStore().ReadDurableAsync(CancellationToken.None);
        Assert.AreEqual(ReleasePolicyParseFailure.None, durable.Failure);
        Assert.AreEqual(new ReleasePolicyRecord(7, scope.ManifestHash), durable.Record);
        var offline = new OfflineReleaseVerifier(scope.MetadataPublicKey, scope.ManifestPublicKey);
        var legacyBaseline = await offline.VerifyInstalledBaselineAsync(scope.Install, store, CancellationToken.None);
        Assert.AreEqual(OfflineReleaseVerificationResult.Verified, legacyBaseline.Result);
        Assert.IsFalse(GenerationAwareReleasePolicyCodec.TryParse(historicalBytes, out _, out _));
    }

    [TestMethod]
    public async Task V1_fixed_component_mismatch_and_unsupported_schema_remain_distinct()
    {
        using var scope = new Scope(); scope.WriteV1();
        File.WriteAllText(Path.Combine(scope.Install, "Vantrel.Security.Core.dll"), "tampered");
        var mismatch = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
        Assert.AreEqual(TrustedManifestSignatureState.Valid, mismatch.Snapshot.SignatureState);
        Assert.AreEqual(TrustedManifestInstallationEvaluation.ComponentMismatch, mismatch.Snapshot.Evaluation);
        Assert.AreEqual(TrustedManifestComponent.CoreAssembly, mismatch.Snapshot.MismatchedComponent);
        var bytes = File.ReadAllText(scope.ManifestPath).Replace("schema=vantrel-trusted-manifest-v1",
            "schema=vantrel-trusted-manifest-v3", StringComparison.Ordinal);
        File.WriteAllText(scope.ManifestPath, bytes);
        var unsupported = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
        Assert.AreEqual(TrustedManifestSignatureState.UnsupportedSchema, unsupported.Snapshot.SignatureState);
        Assert.AreEqual(StatusProtocol.TrustedManifestIntegrityPolicyRevision, unsupported.Snapshot.PolicyRevision);
    }

    [TestMethod]
    public async Task Corrupt_existing_policy_blocks_v2_bootstrap_without_replacement()
    {
        foreach (var existing in new[]
        {
            System.Text.Encoding.UTF8.GetBytes("partial-policy"),
            System.Text.Encoding.UTF8.GetBytes("{\"schema\":\"unknown\"}\n"),
            Array.Empty<byte>()
        })
        {
            using var scope = new Scope(); scope.WriteV2();
            Directory.CreateDirectory(Path.GetDirectoryName(scope.PolicyPath)!);
            File.WriteAllBytes(scope.PolicyPath, existing);
            var provenance = await scope.Provenance.CollectAsync(CancellationToken.None);
            Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, provenance.PolicyDecision);
            CollectionAssert.AreEqual(existing, File.ReadAllBytes(scope.PolicyPath));
        }
    }

    [TestMethod]
    public async Task Reparse_file_and_directory_are_rejected_when_symlink_privilege_is_available()
    {
        foreach (var directoryLink in new[] { false, true })
        {
            using var scope = new Scope(); scope.WriteV2();
            var dependency = Path.Combine(scope.Install, "deps", "Microsoft.Extensions.Hosting.dll");
            var external = Path.Combine(scope.TempRoot, "external");
            if (directoryLink)
            {
                Directory.Move(Path.Combine(scope.Install, "deps"), external);
                try { Directory.CreateSymbolicLink(Path.Combine(scope.Install, "deps"), external); }
                catch (Exception error) when (error is UnauthorizedAccessException or IOException)
                { Assert.Inconclusive("File symlink privilege is unavailable."); return; }
            }
            else
            {
                Directory.CreateDirectory(external);
                var externalFile = Path.Combine(external, "hosting.dll");
                File.Move(dependency, externalFile);
                try { File.CreateSymbolicLink(dependency, externalFile); }
                catch (Exception error) when (error is UnauthorizedAccessException or IOException)
                { Assert.Inconclusive("File symlink privilege is unavailable."); return; }
            }
            var result = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
            Assert.AreNotEqual(TrustedManifestInstallationEvaluation.AllMatch, result.Snapshot.Evaluation);
            Assert.IsNull(result.Identity);
        }
    }

    [TestMethod]
    public void V2_protected_native_handle_denies_writes_and_replacement()
    {
        using var scope = new Scope(); scope.WriteV2();
        var path = Path.Combine(scope.Install, "deps", "Microsoft.Extensions.Hosting.dll");
        using var handle = ComponentInspectionNative.OpenProtected(path);
        Assert.ThrowsException<IOException>(() => File.WriteAllText(path, "mutated"));
        Assert.ThrowsException<IOException>(() => File.Move(path, path + ".moved"));
        Assert.AreEqual("hosting", File.ReadAllText(path));
    }

    [TestMethod]
    public async Task Named_data_stream_on_signed_runtime_file_fails_closed_when_supported()
    {
        using var scope = new Scope(); scope.WriteV2();
        var path = Path.Combine(scope.Install, "deps", "Microsoft.Extensions.Hosting.dll");
        try { File.WriteAllText(path + ":unrecorded", "hidden"); }
        catch (Exception error) when (error is IOException or NotSupportedException or UnauthorizedAccessException)
        { Assert.Inconclusive("Named data streams are unavailable on this volume."); return; }
        var result = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
        Assert.AreNotEqual(TrustedManifestInstallationEvaluation.AllMatch, result.Snapshot.Evaluation);
        Assert.IsNull(result.Identity);
    }

    [TestMethod]
    public async Task Named_data_stream_on_installed_directory_fails_closed_when_supported()
    {
        using var scope = new Scope(); scope.WriteV2();
        try { File.WriteAllText(Path.Combine(scope.Install, "deps") + ":unrecorded", "hidden"); }
        catch (Exception error) when (error is IOException or NotSupportedException or UnauthorizedAccessException)
        { Assert.Inconclusive("Directory data streams are unavailable on this volume."); return; }
        var result = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
        Assert.AreNotEqual(TrustedManifestInstallationEvaluation.AllMatch, result.Snapshot.Evaluation);
        Assert.IsNull(result.Identity);
    }

    [DataTestMethod]
    [DataRow("manifest")]
    [DataRow("metadata")]
    [DataRow("root")]
    [DataRow("nested")]
    public async Task Named_data_stream_on_each_sidecar_and_directory_fails_closed(string target)
    {
        using var scope = new Scope(); scope.WriteV2();
        var path = target switch
        {
            "manifest" => scope.ManifestPath,
            "metadata" => scope.MetadataPath,
            "root" => scope.Install,
            _ => Path.Combine(scope.Install, "deps")
        };
        try { File.WriteAllText(path + ":unrecorded", "hidden"); }
        catch (Exception error) when (error is IOException or NotSupportedException or UnauthorizedAccessException)
        { Assert.Inconclusive("Named data streams are unavailable on this volume."); return; }
        var result = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
        Assert.AreNotEqual(TrustedManifestInstallationEvaluation.AllMatch, result.Snapshot.Evaluation);
        Assert.IsNull(result.Identity);
    }

    [TestMethod]
    public async Task Changed_stream_state_on_retained_file_or_directory_handle_fails_closed()
    {
        foreach (var directory in new[] { false, true })
        {
            using var scope = new Scope(); scope.WriteV2();
            var target = directory ? scope.Install : Path.Combine(scope.Install, "deps", "Microsoft.Extensions.Hosting.dll");
            var calls = 0;
            var source = scope.IntegrityWithStreamInspector((handle, isDirectory) =>
            {
                if (string.Equals(ComponentInspectionNative.FinalPath(handle), target, StringComparison.OrdinalIgnoreCase))
                    return ++calls == 1;
                return ComponentInspectionNative.HasOnlyDefaultDataStream(handle, isDirectory);
            });
            var result = await source.CollectWithEvidenceAsync(CancellationToken.None);
            Assert.AreEqual(2, calls);
            Assert.AreNotEqual(TrustedManifestInstallationEvaluation.AllMatch, result.Snapshot.Evaluation);
            Assert.IsNull(result.Identity);
        }
    }

    [TestMethod]
    public async Task Failed_protected_manifest_open_never_claims_verified_signature()
    {
        using var scope = new Scope(); scope.WriteV2();
        using var incompatible = new FileStream(scope.ManifestPath, FileMode.Open, FileAccess.Write,
            FileShare.ReadWrite | FileShare.Delete);
        var result = await scope.Integrity.CollectWithEvidenceAsync(CancellationToken.None);
        Assert.AreEqual(TrustedManifestSignatureState.ManifestUnavailable, result.Snapshot.SignatureState);
        Assert.AreEqual(TrustedManifestInstallationEvaluation.ManifestUnavailable, result.Snapshot.Evaluation);
        Assert.IsNull(result.Identity);
        Assert.IsTrue(StatusProtocol.TryReadTrustedManifestIntegrityResponse(
            StatusProtocol.CreateTrustedManifestIntegrityResponse(result.Snapshot), out _, out _));
    }

    private sealed class Scope : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "vantrel-installed-v2-" + Guid.NewGuid().ToString("N"));
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal string TempRoot => _root;
        internal string Install => Path.Combine(_root, "Service");
        internal string ManifestPath => Path.Combine(Install, "Vantrel.Security.TrustedManifest");
        internal string MetadataPath => Path.Combine(Install, "Vantrel.Security.ReleaseMetadata");
        internal string PolicyPath => Path.Combine(_root, "Policy", "ReleasePolicy", ReleasePolicyStore.PolicyFileName);
        internal string ManifestHash => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(ManifestPath)));
        internal byte[] MetadataPublicKey => _metadataKey.ExportSubjectPublicKeyInfo();
        internal byte[] ManifestPublicKey => _manifestKey.ExportSubjectPublicKeyInfo();
        internal ReleasePolicyStore NewPolicyStore() => new(Path.Combine(_root, "Policy"), applyAcls: false);
        internal TrustedManifestIntegritySource Integrity => new(new NativeComponentInspectionHandleOperations(), () => true,
            () => new ComponentInspectionTargetIdentity(ManifestPath, Install), null,
            () => _manifestKey.ExportSubjectPublicKeyInfo(), () => _metadataKey.ExportSubjectPublicKeyInfo());
        internal TrustedManifestIntegritySource IntegrityWithStreamInspector(
            Func<Microsoft.Win32.SafeHandles.SafeFileHandle, bool, bool> inspector) =>
            new TrustedManifestIntegritySource(new NativeComponentInspectionHandleOperations(), () => true,
                () => new ComponentInspectionTargetIdentity(ManifestPath, Install), null,
                () => _manifestKey.ExportSubjectPublicKeyInfo(), () => _metadataKey.ExportSubjectPublicKeyInfo())
            { StreamInspector = inspector };
        internal ReleaseProvenanceSource Provenance => new(new NativeComponentInspectionHandleOperations(), () => true,
            () => new ComponentInspectionTargetIdentity(MetadataPath, Install), null, Integrity,
            NewPolicyStore(),
            () => _metadataKey.ExportSubjectPublicKeyInfo());

        internal void WriteV2(string physicalHostingName = "Microsoft.Extensions.Hosting.dll")
        {
            Directory.CreateDirectory(Path.Combine(Install, "deps"));
            File.WriteAllText(Path.Combine(Install, "Vantrel.Security.Service.exe"), "apphost");
            File.WriteAllText(Path.Combine(Install, "deps", physicalHostingName), "hosting");
            var files = new[]
            {
                Entry("Vantrel.Security.Service.exe", "apphost"),
                Entry("deps/Microsoft.Extensions.Hosting.dll", "hosting")
            }.OrderBy(static file => file.Path, StringComparer.Ordinal).ToArray();
            File.WriteAllBytes(ManifestPath, TrustedManifestV2Codec.CreateFile("0.1.0-beta.2", 7, files, _manifestKey));
            WriteMetadata();
        }
        internal void WriteV2WithSignedResidue(string name)
        {
            WriteV2();
            File.WriteAllText(Path.Combine(Install, name), "residue");
            var files = new[]
            {
                Entry("Vantrel.Security.Service.exe", "apphost"),
                Entry("deps/Microsoft.Extensions.Hosting.dll", "hosting"),
                Entry(name, "residue")
            }.OrderBy(static file => file.Path, StringComparer.Ordinal).ToArray();
            File.WriteAllBytes(ManifestPath, TrustedManifestV2Codec.CreateFile("0.1.0-beta.2", 7, files, _manifestKey));
            WriteMetadata();
        }
        internal void WriteV1()
        {
            Directory.CreateDirectory(Install);
            var names = new Dictionary<TrustedManifestComponent, string>
            {
                [TrustedManifestComponent.ServiceExe] = "Vantrel.Security.Service.exe",
                [TrustedManifestComponent.ServiceAssembly] = "Vantrel.Security.Service.dll",
                [TrustedManifestComponent.InfrastructureAssembly] = "Vantrel.Security.Infrastructure.dll",
                [TrustedManifestComponent.CoreAssembly] = "Vantrel.Security.Core.dll",
                [TrustedManifestComponent.Deps] = "Vantrel.Security.Service.deps.json",
                [TrustedManifestComponent.RuntimeConfig] = "Vantrel.Security.Service.runtimeconfig.json",
                [TrustedManifestComponent.EventLogResource] = "System.Diagnostics.EventLog.Messages.dll"
            };
            foreach (var (component, name) in names) File.WriteAllText(Path.Combine(Install, name), "v1-" + component);
            var hashes = names.ToDictionary(static pair => pair.Key,
                pair => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(Install, pair.Value)))));
            File.WriteAllBytes(ManifestPath, TrustedManifestCodec.CreateFile("0.1.0-beta.1", hashes, _manifestKey));
            WriteMetadata(version: "0.1.0-beta.1");
        }
        internal void WriteMetadata(string version = "0.1.0-beta.2", ulong sequence = 7, string? hash = null, bool wrongKey = false)
        {
            using var alien = wrongKey ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : null;
            var signer = alien ?? _metadataKey;
            File.WriteAllBytes(MetadataPath, ReleaseMetadataCodec.CreateFile(sequence, hash ?? ManifestHash, version,
                new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero), signer));
        }
        internal void CorruptManifestSignature()
        {
            var bytes = File.ReadAllBytes(ManifestPath);
            var signature = System.Text.Encoding.ASCII.GetString(bytes).LastIndexOf("signature=", StringComparison.Ordinal);
            bytes[signature + "signature=".Length] = bytes[signature + "signature=".Length] == (byte)'A' ? (byte)'B' : (byte)'A';
            File.WriteAllBytes(ManifestPath, bytes);
        }
        internal void WriteUnknownManifestSchema()
        {
            var bytes = File.ReadAllText(ManifestPath).Replace("schema=vantrel-trusted-manifest-v2", "schema=vantrel-trusted-manifest-v3");
            File.WriteAllText(ManifestPath, bytes);
        }
        private static TrustedManifestV2File Entry(string path, string content) =>
            new(path, Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(content))));
        public void Dispose()
        {
            _manifestKey.Dispose(); _metadataKey.Dispose();
            if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
        }
    }
}
