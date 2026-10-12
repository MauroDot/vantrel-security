using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class V1OfflineReleaseVerifierCompatibilityTests
{
    [TestMethod]
    public async Task Historical_v1_candidate_authenticates_full_manifest_hash_and_preserves_policy_bytes()
    {
        await using var fixture = await Fixture.CreateAsync();
        var before = await File.ReadAllBytesAsync(fixture.PolicyPath);

        var verified = await fixture.Verifier.VerifyCandidateAsync(fixture.Staged, fixture.Policy, CancellationToken.None);

        Assert.AreEqual(2UL, verified.Sequence);
        Assert.AreEqual(await fixture.StagedManifestHashAsync(), verified.ManifestSha256);
        Assert.AreEqual(ReleasePolicyDecision.HigherRelease, verified.PolicyDecision);
        CollectionAssert.AreEqual(before, await File.ReadAllBytesAsync(fixture.PolicyPath));
        Assert.IsTrue(ReleasePolicyCodec.TryParse(before, out var historical, out _));
        Assert.AreEqual(1UL, historical!.HighestAcceptedReleaseSequence);
        CollectionAssert.AreEquivalent(FixedServiceReleaseFiles.AllNames,
            Directory.GetFiles(fixture.Staged).Select(Path.GetFileName).ToArray());
    }

    [DataTestMethod]
    [DataRow("manifest-signature")]
    [DataRow("metadata-signature")]
    [DataRow("component-hash")]
    [DataRow("extra-file")]
    [DataRow("missing-file")]
    public async Task Historical_v1_chain_rejects_invalid_signature_content_or_exact_set(string mutation)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.MutateStagedAsync(mutation);

        await Assert.ThrowsExceptionAsync<InvalidDataException>(() =>
            fixture.Verifier.VerifyChainAsync(fixture.Staged, CancellationToken.None));
    }

    [DataTestMethod]
    [DataRow("same", ReleasePolicyDecision.SameAcceptedRelease)]
    [DataRow("conflict", ReleasePolicyDecision.SequenceConflict)]
    [DataRow("rollback", ReleasePolicyDecision.RollbackBlocked)]
    public async Task Historical_v1_candidate_retains_sequence_and_hash_policy_decisions(string policyState,
        ReleasePolicyDecision expected)
    {
        await using var fixture = await Fixture.CreateAsync();
        var manifestHash = await fixture.StagedManifestHashAsync();
        var record = policyState switch
        {
            "same" => new ReleasePolicyRecord(2, manifestHash),
            "conflict" => new ReleasePolicyRecord(2, new string('A', 64)),
            "rollback" => new ReleasePolicyRecord(3, manifestHash),
            _ => throw new ArgumentOutOfRangeException(nameof(policyState))
        };
        await fixture.WritePolicyAsync(record);
        var before = await File.ReadAllBytesAsync(fixture.PolicyPath);

        var verified = await fixture.Verifier.VerifyCandidateAsync(fixture.Staged, fixture.Policy, CancellationToken.None);

        Assert.AreEqual(2UL, verified.Sequence);
        Assert.AreEqual(manifestHash, verified.ManifestSha256);
        Assert.AreEqual(expected, verified.PolicyDecision);
        CollectionAssert.AreEqual(before, await File.ReadAllBytesAsync(fixture.PolicyPath));
    }

    [TestMethod]
    public async Task Malformed_historical_policy_is_unavailable_without_rewriting_it()
    {
        await using var fixture = await Fixture.CreateAsync();
        await File.WriteAllTextAsync(fixture.PolicyPath, "not-json");
        var before = await File.ReadAllBytesAsync(fixture.PolicyPath);

        var verified = await fixture.Verifier.VerifyCandidateAsync(fixture.Staged, fixture.Policy, CancellationToken.None);

        Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, verified.PolicyDecision);
        CollectionAssert.AreEqual(before, await File.ReadAllBytesAsync(fixture.PolicyPath));
    }

    [TestMethod]
    public async Task Historical_v1_installed_baseline_requires_the_accepted_sequence_and_manifest_hash()
    {
        await using var fixture = await Fixture.CreateAsync();

        var verified = await fixture.Verifier.VerifyInstalledBaselineAsync(fixture.Installed, fixture.Policy, CancellationToken.None);

        Assert.AreEqual(OfflineReleaseVerificationResult.Verified, verified.Result);
        Assert.IsNotNull(verified.Release);
        Assert.AreEqual(1UL, verified.Release.Sequence);
        Assert.AreEqual(await fixture.InstalledManifestHashAsync(), verified.Release.ManifestSha256);

        await fixture.WritePolicyAsync(new ReleasePolicyRecord(1, new string('A', 64)));
        var mismatch = await fixture.Verifier.VerifyInstalledBaselineAsync(fixture.Installed, fixture.Policy, CancellationToken.None);
        Assert.AreEqual(OfflineReleaseVerificationResult.SequenceConflict, mismatch.Result);
        Assert.IsNull(mismatch.Release);
    }

    [TestMethod]
    public async Task V2_style_additional_runtime_file_is_rejected_by_v1_transaction_before_service_stop()
    {
        await using var fixture = await Fixture.CreateAsync();
        await File.WriteAllTextAsync(Path.Combine(fixture.Staged, "Vantrel.Security.AdditionalRuntime.dll"), "v2-runtime");
        var predecessor = await fixture.Verifier.VerifyChainAsync(fixture.Installed, CancellationToken.None);
        var targetHash = await fixture.StagedManifestHashAsync();
        var journal = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", predecessor.Sequence,
            predecessor.ManifestSha256, 2, targetHash, UpdateTransactionPhase.Prepared,
            "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));
        var storage = new OfflineUpdateStorage(fixture.Updates, fixture.Installed, applyAcls: false,
            WindowsOfflineUpdateFileOperations.Instance);
        var service = new ServiceProbe();
        var files = new FilesProbe();
        var health = new HealthProbe();
        var persisted = new JournalProbe();
        var engine = new OfflineUpdateTransactionEngine(
            new FixedOfflineUpdatePreflight(fixture.Verifier, fixture.Policy, storage), service, files, health, persisted);

        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(journal, CancellationToken.None));
        Assert.AreEqual(0, service.StopCount);
        Assert.AreEqual(0, files.ReplaceCount);
        Assert.AreEqual(0, health.TargetVerificationCount);
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.Failed }, persisted.Phases);
        Assert.IsFalse(Directory.Exists(storage.PrivateCandidate(journal.TransactionId)));
        Assert.IsFalse(Directory.Exists(storage.Backup(journal.BackupId)));
    }

    [TestMethod]
    public async Task Signed_v2_candidate_authenticates_but_fixed_admission_rejects_before_transaction_effects()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.WriteSignedV2StagedAsync();
        var policyBefore = await File.ReadAllBytesAsync(fixture.PolicyPath);
        var targetHash = await fixture.StagedManifestHashAsync();
        var generationAware = new GenerationAwareOfflineReleaseVerifier(fixture.MetadataPublicKey,
            fixture.ManifestPublicKey);

        var authenticated = await generationAware.VerifyChainAsync(fixture.Staged, CancellationToken.None);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated, authenticated.Result);
        Assert.AreEqual(new ReleaseIdentity(ReleaseGeneration.V2, 2, targetHash), authenticated.Release!.Identity);
        Assert.AreEqual(3, authenticated.Release.RuntimeInventory.Length);
        var migration = await generationAware.VerifyCandidateAsync(fixture.Staged, fixture.Policy, CancellationToken.None);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.MigrationRequired, migration.Result);

        // ExecuteValidatedAsync uses this historical verifier before persisting a Prepared journal.
        // The genuinely signed V2 bytes must fail its fixed V1 exact-set admission check.
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() =>
            fixture.Verifier.VerifyCandidateAsync(fixture.Staged, fixture.Policy, CancellationToken.None));

        var predecessor = await fixture.Verifier.VerifyChainAsync(fixture.Installed, CancellationToken.None);
        var journal = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", predecessor.Sequence,
            predecessor.ManifestSha256, 2, targetHash, UpdateTransactionPhase.Prepared,
            "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));
        var storage = new OfflineUpdateStorage(fixture.Updates, fixture.Installed, applyAcls: false,
            WindowsOfflineUpdateFileOperations.Instance);
        var preflight = new FixedOfflineUpdatePreflight(fixture.Verifier, fixture.Policy, storage);
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() =>
            preflight.VerifyCandidateAndBaselineAsync(journal, CancellationToken.None));
        Assert.IsFalse(Directory.Exists(storage.PrivateCandidate(journal.TransactionId)));
        Assert.IsFalse(Directory.Exists(storage.Backup(journal.BackupId)));

        var service = new ServiceProbe();
        var files = new FilesProbe();
        var health = new HealthProbe();
        var persisted = new JournalProbe();
        // A separately injected Prepared journal probes the later preflight boundary; the
        // production Administrator rejects the same staged tree before creating that journal.
        var engine = new OfflineUpdateTransactionEngine(preflight, service, files, health, persisted);
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(journal, CancellationToken.None));
        Assert.AreEqual(0, service.StopCount);
        Assert.AreEqual(0, files.ReplaceCount);
        Assert.AreEqual(0, health.TargetVerificationCount);
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.Failed }, persisted.Phases);
        CollectionAssert.AreEqual(policyBefore, await File.ReadAllBytesAsync(fixture.PolicyPath));
        Assert.IsFalse(Directory.Exists(storage.PrivateCandidate(journal.TransactionId)));
        Assert.IsFalse(Directory.Exists(storage.Backup(journal.BackupId)));
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        private Fixture()
        {
            Policy = new ReleasePolicyStore(Root, applyAcls: false);
            Verifier = new OfflineReleaseVerifier(_metadataKey.ExportSubjectPublicKeyInfo(),
                _manifestKey.ExportSubjectPublicKeyInfo());
        }

        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-v1-offline-verifier-" + Guid.NewGuid().ToString("N"));
        internal string Updates => Path.Combine(Root, "Updates");
        internal string Installed => Path.Combine(Root, "Installed");
        internal string Staged => Path.Combine(Updates, "Staged", "candidate");
        internal string PolicyPath => Path.Combine(Root, "ReleasePolicy", ReleasePolicyStore.PolicyFileName);
        internal ReleasePolicyStore Policy { get; }
        internal OfflineReleaseVerifier Verifier { get; }
        internal byte[] MetadataPublicKey => _metadataKey.ExportSubjectPublicKeyInfo();
        internal byte[] ManifestPublicKey => _manifestKey.ExportSubjectPublicKeyInfo();

        internal static async Task<Fixture> CreateAsync()
        {
            var fixture = new Fixture();
            await fixture.WriteReleaseAsync(fixture.Installed, 1, "installed");
            await fixture.WriteReleaseAsync(fixture.Staged, 2, "candidate");
            await fixture.WritePolicyAsync(new ReleasePolicyRecord(1, await fixture.InstalledManifestHashAsync()));
            return fixture;
        }

        internal Task<string> StagedManifestHashAsync() => ManifestHashAsync(Staged);
        internal Task<string> InstalledManifestHashAsync() => ManifestHashAsync(Installed);

        internal async Task WritePolicyAsync(ReleasePolicyRecord record)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PolicyPath)!);
            await File.WriteAllBytesAsync(PolicyPath, ReleasePolicyCodec.Serialize(record));
        }

        internal async Task MutateStagedAsync(string mutation)
        {
            switch (mutation)
            {
                case "manifest-signature":
                    using (var wrongSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256))
                        await WriteManifestAsync(Staged, wrongSigner);
                    await WriteMetadataAsync(Staged, 2, _metadataKey);
                    break;
                case "metadata-signature":
                    using (var wrongSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256))
                        await WriteMetadataAsync(Staged, 2, wrongSigner);
                    break;
                case "component-hash":
                    await File.AppendAllTextAsync(Path.Combine(Staged, FixedServiceReleaseFiles.Components[0].Name), "tampered");
                    break;
                case "extra-file":
                    await File.WriteAllTextAsync(Path.Combine(Staged, "unexpected.dll"), "extra");
                    break;
                case "missing-file":
                    File.Delete(Path.Combine(Staged, FixedServiceReleaseFiles.Components[0].Name));
                    break;
                default: throw new ArgumentOutOfRangeException(nameof(mutation));
            }
        }

        internal async Task WriteSignedV2StagedAsync()
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(Staged))
                File.Delete(entry);
            var files = new[]
            {
                "Vantrel.Security.Service.exe",
                "deps/Microsoft.Extensions.Hosting.dll",
                "runtimes/win-x64/native/helper.dll"
            };
            var inventory = new List<TrustedManifestV2File>();
            foreach (var relative in files)
            {
                var path = Path.Combine(Staged, relative.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                var bytes = System.Text.Encoding.UTF8.GetBytes("signed-v2:" + relative);
                await File.WriteAllBytesAsync(path, bytes);
                inventory.Add(new TrustedManifestV2File(relative, Convert.ToHexString(SHA256.HashData(bytes))));
            }
            var manifest = TrustedManifestV2Codec.CreateFile("0.1.0", 2, inventory, _manifestKey);
            await File.WriteAllBytesAsync(Path.Combine(Staged, "Vantrel.Security.TrustedManifest"), manifest);
            await WriteMetadataAsync(Staged, 2, _metadataKey);
        }

        private async Task WriteReleaseAsync(string root, ulong sequence, string marker)
        {
            Directory.CreateDirectory(root);
            foreach (var (_, name) in FixedServiceReleaseFiles.Components)
                await File.WriteAllTextAsync(Path.Combine(root, name), marker + ":" + name);
            await WriteManifestAsync(root, _manifestKey);
            await WriteMetadataAsync(root, sequence, _metadataKey);
        }

        private static async Task WriteManifestAsync(string root, ECDsa signer)
        {
            var hashes = new Dictionary<TrustedManifestComponent, string>();
            foreach (var (component, name) in FixedServiceReleaseFiles.Components)
                hashes.Add(component, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(root, name)))));
            await File.WriteAllBytesAsync(Path.Combine(root, "Vantrel.Security.TrustedManifest"),
                TrustedManifestCodec.CreateFile("0.1.0", hashes, signer));
        }

        private static async Task WriteMetadataAsync(string root, ulong sequence, ECDsa signer) =>
            await File.WriteAllBytesAsync(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"),
                ReleaseMetadataCodec.CreateFile(sequence, await ManifestHashAsync(root), "0.1.0",
                    new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero), signer));

        private static async Task<string> ManifestHashAsync(string root) => Convert.ToHexString(
            SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(root, "Vantrel.Security.TrustedManifest"))));

        public ValueTask DisposeAsync()
        {
            _metadataKey.Dispose();
            _manifestKey.Dispose();
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ServiceProbe : IOfflineUpdateServiceControl
    {
        internal int StopCount;
        public Task StopAsync(CancellationToken token) { StopCount++; return Task.CompletedTask; }
        public Task StartAsync(CancellationToken token) => Task.CompletedTask;
        public Task RequireStoppedAsync(CancellationToken token) => Task.CompletedTask;
    }

    private sealed class FilesProbe : IOfflineUpdateReleaseFiles
    {
        internal int ReplaceCount;
        public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token)
        { ReplaceCount++; return Task.CompletedTask; }
        public Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
    }

    private sealed class HealthProbe : IOfflineUpdateHealth
    {
        internal int TargetVerificationCount;
        public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token)
        { TargetVerificationCount++; return Task.CompletedTask; }
        public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token) =>
            Task.FromResult(PolicyCommitObservation.Unavailable);
    }

    private sealed class JournalProbe : IOfflineUpdateJournal
    {
        internal List<UpdateTransactionPhase> Phases { get; } = [];
        public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token)
        { Phases.Add(journal.Phase); return Task.CompletedTask; }
    }
}
