using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class GenerationAwareOfflineReleaseVerifierTests
{
    [TestMethod]
    public async Task V1_candidate_preserves_fixed_set_signatures_hashes_and_historical_policy()
    {
        using var scope = new Scope();
        scope.WriteV1();
        var chain = await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated, chain.Result);
        Assert.AreEqual(ReleaseGeneration.V1, chain.Release!.Identity.Generation);
        Assert.AreEqual(scope.ManifestHash, chain.Release.Identity.ManifestSha256);
        Assert.AreEqual(0, chain.Release.RuntimeInventory.Length);
        scope.WriteV1Policy(7, scope.ManifestHash);
        var originalPolicy = File.ReadAllBytes(scope.PolicyPath);
        var same = await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy, CancellationToken.None);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.SameRelease, same.Result);
        Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease, same.PolicyDecision);
        CollectionAssert.AreEqual(originalPolicy, File.ReadAllBytes(scope.PolicyPath));
        Assert.AreEqual(OfflineReleaseVerificationResult.Verified,
            (await scope.Historical.VerifyInstalledBaselineAsync(scope.Candidate, scope.Policy, CancellationToken.None)).Result);
    }

    [DataTestMethod]
    [DataRow("manifest-signature")]
    [DataRow("metadata-signature")]
    [DataRow("changed-component")]
    [DataRow("extra-file")]
    [DataRow("missing-file")]
    public async Task V1_invalid_candidate_never_enters_v2_path(string mutation)
    {
        using var scope = new Scope(); scope.WriteV1();
        switch (mutation)
        {
            case "manifest-signature": scope.WriteV1(wrongManifestSigner: true); break;
            case "metadata-signature": scope.WriteV1(wrongMetadataSigner: true); break;
            case "changed-component": File.AppendAllText(Path.Combine(scope.Candidate, FixedServiceReleaseFiles.Components[0].Name), "changed"); break;
            case "extra-file": File.WriteAllText(Path.Combine(scope.Candidate, "extra.dll"), "extra"); break;
            case "missing-file": File.Delete(Path.Combine(scope.Candidate, FixedServiceReleaseFiles.Components[0].Name)); break;
        }
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease,
            (await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
    }

    [TestMethod]
    public async Task V1_policy_decisions_and_malformed_policy_fail_closed()
    {
        using var scope = new Scope(); scope.WriteV1();
        foreach (var (sequence, hash, expected) in new[]
        {
            (6UL, new string('A', 64), GenerationAwareOfflineVerificationResult.Advancement),
            (7UL, scope.ManifestHash, GenerationAwareOfflineVerificationResult.SameRelease),
            (7UL, new string('A', 64), GenerationAwareOfflineVerificationResult.SequenceConflict),
            (8UL, new string('A', 64), GenerationAwareOfflineVerificationResult.RollbackBlocked)
        })
        {
            scope.WriteV1Policy(sequence, hash);
            Assert.AreEqual(expected, (await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy,
                CancellationToken.None)).Result);
        }
        File.WriteAllText(scope.PolicyPath, "malformed");
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.PolicyUnavailable,
            (await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy, CancellationToken.None)).Result);
    }

    [TestMethod]
    public async Task Complete_nested_v2_candidate_returns_signed_identity_and_immutable_inventory()
    {
        using var scope = new Scope(); scope.WriteV2();
        var result = await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated, result.Result);
        Assert.AreEqual(new ReleaseIdentity(ReleaseGeneration.V2, 7, scope.ManifestHash), result.Release!.Identity);
        CollectionAssert.AreEqual(new[]
        {
            "Vantrel.Security.Service.exe", "deps/Microsoft.Extensions.Hosting.dll", "runtimes/win-x64/native/helper.dll"
        }, result.Release.RuntimeInventory.Select(file => file.Path).ToArray());
        foreach (var entry in result.Release.RuntimeInventory)
            Assert.AreEqual(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(scope.Candidate,
                entry.Path.Replace('/', Path.DirectorySeparatorChar))))), entry.Sha256);
        CollectionAssert.AreEquivalent(new[]
        {
            "Vantrel.Security.TrustedManifest", "Vantrel.Security.ReleaseMetadata"
        }, Directory.GetFiles(scope.Candidate).Select(Path.GetFileName)
            .Where(name => name!.StartsWith("Vantrel.Security.", StringComparison.Ordinal) &&
                name is not "Vantrel.Security.Service.exe").ToArray());
    }

    [DataTestMethod]
    [DataRow("manifest-signature")]
    [DataRow("metadata-signature")]
    [DataRow("metadata-hash")]
    [DataRow("sequence")]
    [DataRow("version")]
    [DataRow("missing-dependency")]
    [DataRow("changed-dependency")]
    [DataRow("extra-file")]
    [DataRow("pdb")]
    [DataRow("lockfile")]
    [DataRow("record")]
    [DataRow("descriptor")]
    [DataRow("notes")]
    [DataRow("wrong-case")]
    public async Task V2_authentication_rejects_bad_signatures_binding_inventory_and_residue(string mutation)
    {
        using var scope = new Scope(); scope.WriteV2();
        var dependency = Path.Combine(scope.Candidate, "deps", "Microsoft.Extensions.Hosting.dll");
        switch (mutation)
        {
            case "manifest-signature": scope.WriteV2(wrongManifestSigner: true); break;
            case "metadata-signature": scope.WriteV2(wrongMetadataSigner: true); break;
            case "metadata-hash": scope.WriteV2(metadataHash: new string('A', 64)); break;
            case "sequence": scope.WriteV2(metadataSequence: 8); break;
            case "version": scope.WriteV2(metadataVersion: "9.9.9"); break;
            case "missing-dependency": File.Delete(dependency); break;
            case "changed-dependency": File.AppendAllText(dependency, "changed"); break;
            case "extra-file": File.WriteAllText(Path.Combine(scope.Candidate, "extra.dll"), "extra"); break;
            case "pdb": File.WriteAllText(Path.Combine(scope.Candidate, "symbols.pdb"), "debug"); break;
            case "lockfile": File.WriteAllText(Path.Combine(scope.Candidate, "packages.lock.json"), "lock"); break;
            case "record": File.WriteAllText(Path.Combine(scope.Candidate, "product-release-record-1.json"), "record"); break;
            case "descriptor": File.WriteAllText(Path.Combine(scope.Candidate, "beta-release-descriptor-1.json"), "descriptor"); break;
            case "notes": File.WriteAllText(Path.Combine(scope.Candidate, "release-notes.md"), "notes"); break;
            case "wrong-case": File.Move(dependency, Path.Combine(scope.Candidate, "deps", "microsoft.extensions.hosting.dll")); break;
        }
        var result = await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease, result.Result, mutation);
        Assert.IsNull(result.Release, mutation);
    }

    [DataTestMethod]
    [DataRow("Vantrel.Security.TrustedManifest")]
    [DataRow("../escape.dll")]
    [DataRow("symbols.pdb")]
    [DataRow("packages.lock.json")]
    [DataRow("beta-release-record-1.json")]
    [DataRow("release-notes.md")]
    [DataRow("deps/Foo.dll|duplicate-case")]
    public async Task Signed_v2_inventory_cannot_claim_forbidden_or_ambiguous_paths(string path)
    {
        using var scope = new Scope(); scope.WriteV2();
        var fileLines = path.EndsWith("|duplicate-case", StringComparison.Ordinal)
            ? new[] { "deps/Foo.dll", "deps/foo.dll" }
            : new[] { path };
        scope.WriteRawV2Manifest(fileLines);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease,
            (await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
    }

    [TestMethod]
    public async Task Unsupported_or_malformed_schema_and_invalid_v2_have_no_v1_fallback()
    {
        using var scope = new Scope(); scope.WriteV2();
        File.WriteAllText(scope.ManifestPath, "schema=vantrel-trusted-manifest-v3\n");
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.UnsupportedGeneration,
            (await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
        File.WriteAllText(scope.ManifestPath, "schema=vantrel-trusted-manifest-v2\r\n");
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease,
            (await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
        scope.WriteV2(wrongManifestSigner: true);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease,
            (await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
        scope.WriteV2();
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
        await Assert.ThrowsExceptionAsync<InvalidDataException>(async () =>
            await scope.Historical.VerifyChainAsync(scope.Candidate, CancellationToken.None));
    }

    [TestMethod]
    public async Task Schema_dispatch_invokes_only_the_selected_generation_verifier()
    {
        using var scope = new Scope();
        var v1Calls = 0;
        var v2Calls = 0;
        var historical = scope.Historical;
        var verifier = new GenerationAwareOfflineReleaseVerifier(scope.MetadataPublicKey, scope.ManifestPublicKey,
            root => { v2Calls++; return scope.CreateV2Source(root); },
            (root, token) => { v1Calls++; return historical.VerifyChainAsync(root, token); });

        scope.WriteV2(wrongManifestSigner: true);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease,
            (await verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
        Assert.AreEqual(0, v1Calls);
        Assert.AreEqual(1, v2Calls);

        scope.WriteV1(wrongManifestSigner: true);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease,
            (await verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
        Assert.AreEqual(1, v1Calls);
        Assert.AreEqual(1, v2Calls);

        File.WriteAllText(scope.ManifestPath, "schema=vantrel-trusted-manifest-v3\n");
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.UnsupportedGeneration,
            (await verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
        Assert.AreEqual(1, v1Calls);
        Assert.AreEqual(1, v2Calls);
    }

    [TestMethod]
    public async Task Policy_v1_and_v2_evaluate_cross_generation_without_rewriting_policy()
    {
        using var scope = new Scope(); scope.WriteV2();
        scope.WriteV1Policy(6, new string('A', 64));
        var historical = File.ReadAllBytes(scope.PolicyPath);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.MigrationRequired,
            (await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy, CancellationToken.None)).Result);
        CollectionAssert.AreEqual(historical, File.ReadAllBytes(scope.PolicyPath));
        scope.WriteV1Policy(7, new string('A', 64));
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.SequenceConflict,
            (await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy, CancellationToken.None)).Result);
        scope.WriteV2Policy(new(ReleaseGeneration.V2, 6, new string('A', 64)));
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Advancement,
            (await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy, CancellationToken.None)).Result);
        scope.WriteV2Policy(new(ReleaseGeneration.V2, 7, scope.ManifestHash));
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.SameRelease,
            (await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy, CancellationToken.None)).Result);
        scope.WriteV2Policy(new(ReleaseGeneration.V2, 7, new string('A', 64)));
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.SequenceConflict,
            (await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy, CancellationToken.None)).Result);
        scope.WriteV2Policy(new(ReleaseGeneration.V2, 8, new string('A', 64)));
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.RollbackBlocked,
            (await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy, CancellationToken.None)).Result);
        File.WriteAllText(scope.PolicyPath, "malformed");
        var malformed = File.ReadAllBytes(scope.PolicyPath);
        var unavailable = await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy, CancellationToken.None);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.PolicyUnavailable, unavailable.Result);
        Assert.IsNotNull(unavailable.Release); // Authenticated bytes do not imply update authorization.
        CollectionAssert.AreEqual(malformed, File.ReadAllBytes(scope.PolicyPath));
        scope.WriteV1();
        scope.WriteV2Policy(new(ReleaseGeneration.V2, 6, new string('A', 64)));
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.GenerationDowngradeBlocked,
            (await scope.Verifier.VerifyCandidateAsync(scope.Candidate, scope.Policy, CancellationToken.None)).Result);
    }

    [TestMethod]
    public async Task Each_root_is_independently_authenticated_after_copy()
    {
        using var scope = new Scope(); scope.WriteV2();
        var copy = Path.Combine(scope.TempRoot, "private-copy");
        foreach (var file in Directory.GetFiles(scope.Candidate, "*", SearchOption.AllDirectories))
        {
            var destination = Path.Combine(copy, Path.GetRelativePath(scope.Candidate, file));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(file, destination);
        }
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(copy, CancellationToken.None)).Result);
        File.AppendAllText(Path.Combine(copy, "deps", "Microsoft.Extensions.Hosting.dll"), "changed");
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease,
            (await scope.Verifier.VerifyChainAsync(copy, CancellationToken.None)).Result);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
    }

    [TestMethod]
    public async Task Offline_v2_stream_mutation_on_retained_handle_fails_closed()
    {
        using var scope = new Scope(); scope.WriteV2();
        var target = Path.Combine(scope.Candidate, "deps", "Microsoft.Extensions.Hosting.dll");
        var inspections = 0;
        var verifier = scope.VerifierWithStreamInspector((handle, directory) =>
        {
            if (string.Equals(ComponentInspectionNative.FinalPath(handle), target, StringComparison.OrdinalIgnoreCase))
                return ++inspections == 1;
            return ComponentInspectionNative.HasOnlyDefaultDataStream(handle, directory);
        });
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease,
            (await verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
        Assert.AreEqual(2, inspections);
    }

    [DataTestMethod]
    [DataRow("file")]
    [DataRow("directory")]
    public async Task Offline_v2_reparse_path_fails_closed_when_symlink_privilege_is_available(string kind)
    {
        using var scope = new Scope(); scope.WriteV2();
        var external = Path.Combine(scope.TempRoot, "outside");
        if (kind == "file")
        {
            Directory.CreateDirectory(external);
            var target = Path.Combine(scope.Candidate, "deps", "Microsoft.Extensions.Hosting.dll");
            var outside = Path.Combine(external, "hosting.dll");
            File.Move(target, outside);
            try { File.CreateSymbolicLink(target, outside); }
            catch (Exception error) when (error is UnauthorizedAccessException or IOException)
            { Assert.Inconclusive("File symlink privilege is unavailable."); return; }
        }
        else
        {
            var target = Path.Combine(scope.Candidate, "deps");
            Directory.Move(target, external);
            try { Directory.CreateSymbolicLink(target, external); }
            catch (Exception error) when (error is UnauthorizedAccessException or IOException)
            { Assert.Inconclusive("Directory symlink privilege is unavailable."); return; }
        }
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease,
            (await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
    }

    [DataTestMethod]
    [DataRow("runtime")]
    [DataRow("manifest-sidecar")]
    [DataRow("metadata-sidecar")]
    [DataRow("directory")]
    [DataRow("root-directory")]
    public async Task Offline_v2_named_stream_fails_closed_when_volume_supports_it(string target)
    {
        using var scope = new Scope(); scope.WriteV2();
        var path = target switch
        {
            "runtime" => Path.Combine(scope.Candidate, "deps", "Microsoft.Extensions.Hosting.dll"),
            "manifest-sidecar" => scope.ManifestPath,
            "metadata-sidecar" => scope.MetadataPath,
            "root-directory" => scope.Candidate,
            _ => Path.Combine(scope.Candidate, "deps")
        };
        try { File.WriteAllText(path + ":unrecorded", "hidden"); }
        catch (Exception error) when (error is IOException or NotSupportedException or UnauthorizedAccessException)
        { Assert.Inconclusive("Named streams are unavailable on this volume."); return; }
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.InvalidRelease,
            (await scope.Verifier.VerifyChainAsync(scope.Candidate, CancellationToken.None)).Result);
    }

    private sealed class Scope : IDisposable
    {
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal string TempRoot { get; } = Path.Combine(Path.GetTempPath(), "vantrel-offline-generation-" + Guid.NewGuid().ToString("N"));
        internal string Candidate => Path.Combine(TempRoot, "candidate");
        internal string ManifestPath => Path.Combine(Candidate, "Vantrel.Security.TrustedManifest");
        internal string MetadataPath => Path.Combine(Candidate, "Vantrel.Security.ReleaseMetadata");
        internal string PolicyPath => Path.Combine(TempRoot, "policy", "ReleasePolicy", ReleasePolicyStore.PolicyFileName);
        internal string ManifestHash => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(ManifestPath)));
        internal ReleasePolicyStore Policy => new(Path.Combine(TempRoot, "policy"), applyAcls: false);
        internal byte[] ManifestPublicKey => _manifestKey.ExportSubjectPublicKeyInfo();
        internal byte[] MetadataPublicKey => _metadataKey.ExportSubjectPublicKeyInfo();
        internal OfflineReleaseVerifier Historical => new(_metadataKey.ExportSubjectPublicKeyInfo(), _manifestKey.ExportSubjectPublicKeyInfo());
        internal GenerationAwareOfflineReleaseVerifier Verifier => new(_metadataKey.ExportSubjectPublicKeyInfo(), _manifestKey.ExportSubjectPublicKeyInfo());

        internal TrustedManifestIntegritySource CreateV2Source(string root,
            Func<SafeFileHandle, bool, bool>? inspector = null) =>
            new TrustedManifestIntegritySource(new NativeComponentInspectionHandleOperations(), () => true,
                () => new ComponentInspectionTargetIdentity(Path.Combine(root, "Vantrel.Security.TrustedManifest"), root),
                manifestPublicKey: () => ManifestPublicKey, metadataPublicKey: () => MetadataPublicKey)
            { StreamInspector = inspector ?? ComponentInspectionNative.HasOnlyDefaultDataStream };

        internal GenerationAwareOfflineReleaseVerifier VerifierWithStreamInspector(Func<SafeFileHandle, bool, bool> inspector) =>
            new(MetadataPublicKey, ManifestPublicKey, root => CreateV2Source(root, inspector));

        internal void WriteV1(bool wrongManifestSigner = false, bool wrongMetadataSigner = false)
        {
            Directory.CreateDirectory(Candidate);
            foreach (var entry in Directory.EnumerateFileSystemEntries(Candidate))
            {
                if (Directory.Exists(entry)) Directory.Delete(entry, recursive: true);
                else File.Delete(entry);
            }
            var hashes = new Dictionary<TrustedManifestComponent, string>();
            foreach (var (component, name) in FixedServiceReleaseFiles.Components)
            {
                var bytes = Encoding.UTF8.GetBytes("v1:" + name);
                File.WriteAllBytes(Path.Combine(Candidate, name), bytes);
                hashes.Add(component, Convert.ToHexString(SHA256.HashData(bytes)));
            }
            var manifest = TrustedManifestCodec.CreateFile("1.2.3", hashes,
                wrongManifestSigner ? _wrongKey : _manifestKey);
            File.WriteAllBytes(ManifestPath, manifest);
            File.WriteAllBytes(MetadataPath, ReleaseMetadataCodec.CreateFile(7,
                Convert.ToHexString(SHA256.HashData(manifest)), "1.2.3", Published,
                wrongMetadataSigner ? _wrongKey : _metadataKey));
        }

        internal void WriteV2(bool wrongManifestSigner = false, bool wrongMetadataSigner = false,
            string? metadataHash = null, ulong? metadataSequence = null, string? metadataVersion = null)
        {
            Directory.CreateDirectory(Path.Combine(Candidate, "deps"));
            Directory.CreateDirectory(Path.Combine(Candidate, "runtimes", "win-x64", "native"));
            File.WriteAllText(Path.Combine(Candidate, "Vantrel.Security.Service.exe"), "apphost");
            File.WriteAllText(Path.Combine(Candidate, "deps", "Microsoft.Extensions.Hosting.dll"), "hosting");
            File.WriteAllText(Path.Combine(Candidate, "runtimes", "win-x64", "native", "helper.dll"), "native");
            var files = new[]
            {
                Entry("Vantrel.Security.Service.exe"),
                Entry("deps/Microsoft.Extensions.Hosting.dll"),
                Entry("runtimes/win-x64/native/helper.dll")
            };
            var manifest = TrustedManifestV2Codec.CreateFile("1.2.3", 7, files,
                wrongManifestSigner ? _wrongKey : _manifestKey);
            File.WriteAllBytes(ManifestPath, manifest);
            WriteMetadata(metadataSequence ?? 7, metadataHash ?? Convert.ToHexString(SHA256.HashData(manifest)),
                metadataVersion ?? "1.2.3", wrongMetadataSigner ? _wrongKey : _metadataKey);
        }

        internal void WriteRawV2Manifest(string[] paths)
        {
            var lines = new StringBuilder("schema=vantrel-trusted-manifest-v2\nrelease=1.2.3\nrelease-sequence=7\narchitecture=win-x64\ndeployment=framework-dependent\n")
                .Append("file-count=").Append(paths.Length).Append('\n');
            foreach (var path in paths)
                lines.Append("file=").Append(path).Append('|').Append(new string('A', 64)).Append('\n');
            var canonical = Encoding.ASCII.GetBytes(lines.ToString());
            var signature = _manifestKey.SignData(canonical, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            var manifest = Encoding.ASCII.GetBytes(lines + "signature=" + Convert.ToBase64String(signature) + "\n");
            File.WriteAllBytes(ManifestPath, manifest);
            WriteMetadata(7, Convert.ToHexString(SHA256.HashData(manifest)), "1.2.3", _metadataKey);
        }

        internal void WriteV1Policy(ulong sequence, string hash) => WritePolicy(ReleasePolicyCodec.Serialize(new(sequence, hash)));
        internal void WriteV2Policy(ReleaseIdentity identity) => WritePolicy(GenerationAwareReleasePolicyCodec.Serialize(new(identity)));
        private void WritePolicy(byte[] bytes)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PolicyPath)!);
            File.WriteAllBytes(PolicyPath, bytes);
        }
        private TrustedManifestV2File Entry(string path) => new(path, Convert.ToHexString(SHA256.HashData(
            File.ReadAllBytes(Path.Combine(Candidate, path.Replace('/', Path.DirectorySeparatorChar))))));
        private void WriteMetadata(ulong sequence, string hash, string version, ECDsa signer) =>
            File.WriteAllBytes(MetadataPath, ReleaseMetadataCodec.CreateFile(sequence, hash, version, Published, signer));
        private static DateTimeOffset Published => new(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);

        public void Dispose()
        {
            _manifestKey.Dispose(); _metadataKey.Dispose(); _wrongKey.Dispose();
            if (Directory.Exists(TempRoot)) Directory.Delete(TempRoot, recursive: true);
        }
    }
}
