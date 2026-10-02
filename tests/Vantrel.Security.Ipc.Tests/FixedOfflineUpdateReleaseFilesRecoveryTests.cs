using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class FixedOfflineUpdateReleaseFilesRecoveryTests
{
    [TestMethod]
    public async Task Service_stopped_recovery_reauthenticates_matching_backup_and_restores_it()
    {
        await using var fixture = await RecoveryFixture.CreateAsync();

        var result = await fixture.RecoverAsync();

        Assert.AreEqual(UpdateTransactionPhase.RolledBack, result);
        Assert.AreEqual(1, fixture.Service.StartCount);
        Assert.AreEqual(1, fixture.Health.PredecessorVerificationCount);
        Assert.AreEqual(1UL, (await fixture.Verifier.VerifyChainAsync(fixture.Installed, CancellationToken.None)).Sequence);
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.RollbackRequired, UpdateTransactionPhase.RolledBack }, fixture.Journal.Phases);
    }

    [DataTestMethod]
    [DataRow("component")]
    [DataRow("metadata")]
    [DataRow("manifest")]
    [DataRow("missing")]
    [DataRow("extra")]
    [DataRow("directory")]
    public async Task Tampered_or_invalid_backup_retains_rollback_required_before_restore(string kind)
    {
        await using var fixture = await RecoveryFixture.CreateAsync();
        await fixture.TamperBackupAsync(kind);

        await fixture.AssertRestoreRejectedAsync();
    }

    [TestMethod]
    public async Task Reparse_backup_retains_rollback_required_before_restore()
    {
        await using var fixture = await RecoveryFixture.CreateAsync();
        try
        {
            await fixture.ReplaceBackupComponentWithReparseAsync();
        }
        catch (UnauthorizedAccessException)
        {
            Assert.Inconclusive("Symbolic-link creation is unavailable in this test environment.");
        }
        catch (IOException error) when ((uint)error.HResult == 0x80070522)
        {
            Assert.Inconclusive("Symbolic-link privilege is unavailable in this test environment.");
        }

        await fixture.AssertRestoreRejectedAsync();
    }

    [TestMethod]
    public async Task Different_valid_signed_predecessor_retains_rollback_required_before_restore()
    {
        await using var fixture = await RecoveryFixture.CreateAsync();
        await fixture.WriteReleaseAsync(fixture.Backup, 3, "different-predecessor");

        await fixture.AssertRestoreRejectedAsync();
    }

    [DataTestMethod]
    [DataRow("unavailable")]
    [DataRow("target")]
    [DataRow("unrelated")]
    public async Task Unavailable_or_nonpredecessor_durable_policy_retains_rollback_required_before_restore(string kind)
    {
        await using var fixture = await RecoveryFixture.CreateAsync();
        await fixture.WritePolicyAsync(kind);

        await fixture.AssertRestoreRejectedAsync();
    }

    [TestMethod]
    public async Task Policy_committed_recovery_never_calls_restore()
    {
        await using var fixture = await RecoveryFixture.CreateAsync();
        var before = await fixture.InstalledFingerprintAsync();

        var result = await fixture.Engine.RecoverAsync(fixture.Transaction with { Phase = UpdateTransactionPhase.PolicyCommitted }, CancellationToken.None);

        Assert.AreEqual(UpdateTransactionPhase.Completed, result);
        Assert.AreEqual(0, fixture.Service.StartCount);
        Assert.AreEqual(0, fixture.Health.PredecessorVerificationCount);
        Assert.AreEqual(before, await fixture.InstalledFingerprintAsync());
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.Completed }, fixture.Journal.Phases);
    }

    private sealed class RecoveryFixture : IAsyncDisposable
    {
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private RecoveryFixture()
        {
            Storage = new OfflineUpdateStorage(Updates, Installed, applyAcls: false, WindowsOfflineUpdateFileOperations.Instance);
            Policy = new ReleasePolicyStore(Root, applyAcls: false);
            Verifier = new OfflineReleaseVerifier(_metadataKey.ExportSubjectPublicKeyInfo(), _manifestKey.ExportSubjectPublicKeyInfo());
            Service = new ServiceProbe();
            Health = new HealthProbe();
            Journal = new JournalProbe();
            Files = new FixedOfflineUpdateReleaseFiles(Verifier, Policy, Storage, Service);
            Engine = new OfflineUpdateTransactionEngine(new EmptyPreflight(), Service, Files, Health, Journal);
        }

        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-task018-" + Guid.NewGuid().ToString("N"));
        private string Updates => Path.Combine(Root, "Updates");
        internal string Installed => Path.Combine(Root, "Installed");
        internal string Backup => Storage.Backup(Transaction.BackupId);
        internal OfflineUpdateStorage Storage { get; }
        internal ReleasePolicyStore Policy { get; }
        internal OfflineReleaseVerifier Verifier { get; }
        internal ServiceProbe Service { get; }
        internal HealthProbe Health { get; }
        internal JournalProbe Journal { get; }
        internal FixedOfflineUpdateReleaseFiles Files { get; }
        internal OfflineUpdateTransactionEngine Engine { get; }
        internal UpdateTransactionJournal Transaction { get; private set; } = null!;

        internal static async Task<RecoveryFixture> CreateAsync()
        {
            var fixture = new RecoveryFixture();
            await fixture.WriteReleaseAsync(fixture.Installed, 1, "predecessor");
            var predecessor = await fixture.Verifier.VerifyChainAsync(fixture.Installed, CancellationToken.None);
            Assert.AreEqual(ReleasePolicyDecision.BootstrapAccepted, await fixture.Policy.BootstrapVerifiedSequenceOneAsync(
                VerifiedRelease.FromVerifiedEvidence(predecessor.Sequence, predecessor.ManifestSha256), CancellationToken.None));
            await fixture.Storage.CopyInstalledToBackupAsync("fedcba9876543210fedcba9876543210", CancellationToken.None);
            await fixture.WriteReleaseAsync(fixture.Installed, 2, "target");
            var target = await fixture.Verifier.VerifyChainAsync(fixture.Installed, CancellationToken.None);
            fixture.Transaction = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", predecessor.Sequence,
                predecessor.ManifestSha256, target.Sequence, target.ManifestSha256, UpdateTransactionPhase.ServiceStopped,
                "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));
            return fixture;
        }

        internal async Task AssertRestoreRejectedAsync()
        {
            var before = await InstalledFingerprintAsync();
            Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await RecoverAsync());
            Assert.AreEqual(0, Service.StartCount);
            Assert.AreEqual(0, Health.PredecessorVerificationCount);
            Assert.AreEqual(before, await InstalledFingerprintAsync(), "Restore must not begin before backup reauthentication succeeds.");
            CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.RollbackRequired }, Journal.Phases);
        }

        internal Task<UpdateTransactionPhase> RecoverAsync() => Engine.RecoverAsync(Transaction, CancellationToken.None);

        internal async Task TamperBackupAsync(string kind)
        {
            var metadata = Path.Combine(Backup, "Vantrel.Security.ReleaseMetadata");
            var manifest = Path.Combine(Backup, "Vantrel.Security.TrustedManifest");
            switch (kind)
            {
                case "component": await File.AppendAllTextAsync(Path.Combine(Backup, FixedServiceReleaseFiles.Components[0].Name), "tamper"); break;
                case "metadata": await File.AppendAllTextAsync(metadata, "tamper"); break;
                case "manifest": await File.AppendAllTextAsync(manifest, "tamper"); break;
                case "missing": File.Delete(metadata); break;
                case "extra": await File.WriteAllTextAsync(Path.Combine(Backup, "unexpected"), "x"); break;
                case "directory": File.Delete(Path.Combine(Backup, FixedServiceReleaseFiles.Components[0].Name)); Directory.CreateDirectory(Path.Combine(Backup, FixedServiceReleaseFiles.Components[0].Name)); break;
                default: throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        internal async Task ReplaceBackupComponentWithReparseAsync()
        {
            var component = Path.Combine(Backup, FixedServiceReleaseFiles.Components[0].Name);
            var target = Path.Combine(Root, "reparse-target");
            await File.WriteAllTextAsync(target, "not-a-release-component");
            File.Delete(component);
            File.CreateSymbolicLink(component, target);
        }

        internal async Task WritePolicyAsync(string kind)
        {
            var path = Path.Combine(Root, "ReleasePolicy", ReleasePolicyStore.PolicyFileName);
            if (kind == "unavailable") { File.Delete(path); return; }
            var record = kind == "target"
                ? new ReleasePolicyRecord(Transaction.TargetReleaseSequence, Transaction.TargetManifestSha256)
                : new ReleasePolicyRecord(99, new string('A', 64));
            await File.WriteAllBytesAsync(path, ReleasePolicyCodec.Serialize(record));
        }

        internal async Task WriteReleaseAsync(string root, ulong sequence, string marker)
        {
            Directory.CreateDirectory(root);
            var hashes = new Dictionary<TrustedManifestComponent, string>();
            foreach (var (component, name) in FixedServiceReleaseFiles.Components)
            {
                await File.WriteAllTextAsync(Path.Combine(root, name), marker + ":" + name);
                hashes.Add(component, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(root, name)))));
            }
            var manifest = TrustedManifestCodec.CreateFile("0.1.0", hashes, _manifestKey);
            await File.WriteAllBytesAsync(Path.Combine(root, "Vantrel.Security.TrustedManifest"), manifest);
            await File.WriteAllBytesAsync(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"), ReleaseMetadataCodec.CreateFile(sequence,
                Convert.ToHexString(SHA256.HashData(manifest)), "0.1.0", new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero), _metadataKey));
        }

        internal async Task<string> InstalledFingerprintAsync()
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var name in FixedServiceReleaseFiles.AllNames)
                hash.AppendData(await File.ReadAllBytesAsync(Path.Combine(Installed, name)));
            return Convert.ToHexString(hash.GetHashAndReset());
        }

        public ValueTask DisposeAsync()
        {
            _metadataKey.Dispose(); _manifestKey.Dispose();
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class EmptyPreflight : IOfflineUpdatePreflight
    {
        public Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
    }
    private sealed class ServiceProbe : IOfflineUpdateServiceControl
    {
        public Task RequireStoppedAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.CompletedTask; }
        internal int StartCount;
        public Task StopAsync(CancellationToken token) => Task.CompletedTask;
        public Task StartAsync(CancellationToken token) { StartCount++; return Task.CompletedTask; }
    }
    private sealed class HealthProbe : IOfflineUpdateHealth
    {
        internal int PredecessorVerificationCount;
        public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { PredecessorVerificationCount++; return Task.CompletedTask; }
        public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token) =>
            Task.FromResult(journal.Phase == UpdateTransactionPhase.PolicyCommitted ? PolicyCommitObservation.TargetCommitted : PolicyCommitObservation.PredecessorRetained);
    }
    private sealed class JournalProbe : IOfflineUpdateJournal
    {
        internal List<UpdateTransactionPhase> Phases { get; } = [];
        public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token) { Phases.Add(journal.Phase); return Task.CompletedTask; }
    }
}
