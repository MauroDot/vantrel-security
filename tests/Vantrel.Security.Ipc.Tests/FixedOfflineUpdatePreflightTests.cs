using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class FixedOfflineUpdatePreflightTests
{
    [TestMethod]
    public async Task Verified_staged_candidate_is_copied_and_independently_verified_in_private_transaction_storage()
    {
        await using var fixture = await Fixture.CreateAsync();

        await fixture.Preflight.VerifyCandidateAndBaselineAsync(fixture.Journal, CancellationToken.None);

        var copied = await fixture.Verifier.VerifyCandidateAsync(fixture.Storage.PrivateCandidate(fixture.Journal.TransactionId), fixture.Policy, CancellationToken.None);
        Assert.AreEqual(fixture.Journal.TargetReleaseSequence, copied.Sequence);
        Assert.AreEqual(fixture.Journal.TargetManifestSha256, copied.ManifestSha256);
        Assert.AreEqual(ReleasePolicyDecision.HigherRelease, copied.PolicyDecision);
        foreach (var name in FixedServiceReleaseFiles.AllNames)
            CollectionAssert.AreEqual(await File.ReadAllBytesAsync(Path.Combine(fixture.Staged, name)),
                await File.ReadAllBytesAsync(Path.Combine(fixture.Storage.PrivateCandidate(fixture.Journal.TransactionId), name)));
    }

    [TestMethod]
    public async Task Replacement_probe_uses_verified_private_candidate_after_staged_content_changes()
    {
        await using var fixture = await Fixture.CreateAsync();
        var service = new MutatingServiceProbe(fixture.Staged);
        var files = new PrivateCandidateFilesProbe(fixture.Storage, fixture.Verifier, fixture.Policy, fixture.Journal);
        var journal = new JournalProbe();
        var engine = new OfflineUpdateTransactionEngine(fixture.Preflight, service, files,
            new TargetCommittedHealthProbe(), journal);

        Assert.AreEqual(UpdateTransactionPhase.Completed, await engine.ExecuteAsync(fixture.Journal, CancellationToken.None));

        Assert.AreEqual(1, service.StopCount);
        Assert.AreEqual(1, files.ReplaceCount);
        Assert.IsTrue(files.PrivateCandidateVerified);
        Assert.IsTrue(files.StagedCandidateRejected);
        Assert.AreEqual(0, files.RestoreCount);
    }

    [TestMethod]
    public async Task Staged_candidate_mutation_after_admission_is_rejected_before_service_stop()
    {
        await using var fixture = await Fixture.CreateAsync();
        await File.AppendAllTextAsync(Path.Combine(fixture.Staged, FixedServiceReleaseFiles.Components[0].Name), "tampered");
        var service = new CountingServiceProbe(); var files = new CountingFilesProbe(); var health = new TargetCommittedHealthProbe(); var journal = new JournalProbe();
        var engine = new OfflineUpdateTransactionEngine(fixture.Preflight, service, files, health, journal);

        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(fixture.Journal, CancellationToken.None));

        AssertPreStopFailure(service, files, health, journal);
        Assert.IsFalse(Directory.Exists(fixture.Storage.PrivateCandidate(fixture.Journal.TransactionId)));
        Assert.IsFalse(Directory.Exists(fixture.Storage.Backup(fixture.Journal.BackupId)));
    }

    [TestMethod]
    public async Task Private_candidate_identity_mismatch_is_rejected_before_service_stop()
    {
        var operations = new MetadataSubstitutionOperations();
        await using var fixture = await Fixture.CreateAsync(applyAcls: true, operations: operations);
        operations.Replacement = await fixture.CreateAlternateMetadataAsync();
        var service = new CountingServiceProbe(); var files = new CountingFilesProbe(); var health = new TargetCommittedHealthProbe(); var journal = new JournalProbe();
        var engine = new OfflineUpdateTransactionEngine(fixture.Preflight, service, files, health, journal);

        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(fixture.Journal, CancellationToken.None));

        AssertPreStopFailure(service, files, health, journal);
        Assert.IsTrue(Directory.Exists(fixture.Storage.PrivateCandidate(fixture.Journal.TransactionId)));
        var privateCandidate = await fixture.Verifier.VerifyCandidateAsync(fixture.Storage.PrivateCandidate(fixture.Journal.TransactionId), fixture.Policy, CancellationToken.None);
        Assert.AreNotEqual(fixture.Journal.TargetReleaseSequence, privateCandidate.Sequence);
        Assert.IsFalse(Directory.Exists(fixture.Storage.Backup(fixture.Journal.BackupId)));
    }

    [DataTestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task Candidate_copy_or_flush_failure_is_failed_before_service_stop(bool flushFailure)
    {
        await using var fixture = await Fixture.CreateAsync(operations: new FailingContentOperations(flushFailure));
        var service = new CountingServiceProbe(); var files = new CountingFilesProbe(); var health = new TargetCommittedHealthProbe(); var journal = new JournalProbe();
        var engine = new OfflineUpdateTransactionEngine(fixture.Preflight, service, files, health, journal);

        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(fixture.Journal, CancellationToken.None));

        AssertPreStopFailure(service, files, health, journal);
        Assert.IsFalse(Directory.Exists(fixture.Storage.PrivateCandidate(fixture.Journal.TransactionId)));
        Assert.IsFalse(Directory.Exists(fixture.Storage.Backup(fixture.Journal.BackupId)));
    }

    private static void AssertPreStopFailure(CountingServiceProbe service, CountingFilesProbe files, TargetCommittedHealthProbe health, JournalProbe journal)
    {
        Assert.AreEqual(0, service.StopCount); Assert.AreEqual(0, service.StartCount);
        Assert.AreEqual(0, files.ReplaceCount); Assert.AreEqual(0, files.RestoreCount); Assert.AreEqual(0, health.PolicyObservationCount);
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.Failed }, journal.Phases);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private Fixture(IOfflineUpdateFileOperations operations, bool applyAcls)
        {
            Storage = new OfflineUpdateStorage(Updates, Installed, applyAcls, operations);
            Policy = new ReleasePolicyStore(Root, applyAcls: false);
            Verifier = new OfflineReleaseVerifier(_metadataKey.ExportSubjectPublicKeyInfo(), _manifestKey.ExportSubjectPublicKeyInfo());
            Preflight = new FixedOfflineUpdatePreflight(Verifier, Policy, Storage);
        }

        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-task017-" + Guid.NewGuid().ToString("N"));
        internal string Updates => Path.Combine(Root, "Updates");
        internal string Installed => Path.Combine(Root, "Installed");
        internal string Staged => Path.Combine(Updates, "Staged", "candidate");
        internal OfflineUpdateStorage Storage { get; }
        internal ReleasePolicyStore Policy { get; }
        internal OfflineReleaseVerifier Verifier { get; }
        internal FixedOfflineUpdatePreflight Preflight { get; }
        internal UpdateTransactionJournal Journal { get; private set; } = null!;

        internal static async Task<Fixture> CreateAsync(bool applyAcls = false, IOfflineUpdateFileOperations? operations = null)
        {
            var fixture = new Fixture(operations ?? WindowsOfflineUpdateFileOperations.Instance, applyAcls);
            await fixture.WriteReleaseAsync(fixture.Installed, 1, "predecessor");
            await fixture.WriteReleaseAsync(fixture.Staged, 2, "target");
            var predecessor = await fixture.Verifier.VerifyChainAsync(fixture.Installed, CancellationToken.None);
            var target = await fixture.Verifier.VerifyChainAsync(fixture.Staged, CancellationToken.None);
            Assert.AreEqual(ReleasePolicyDecision.BootstrapAccepted, await fixture.Policy.BootstrapVerifiedSequenceOneAsync(
                VerifiedRelease.FromVerifiedEvidence(predecessor.Sequence, predecessor.ManifestSha256), CancellationToken.None));
            fixture.Journal = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", predecessor.Sequence, predecessor.ManifestSha256,
                target.Sequence, target.ManifestSha256, UpdateTransactionPhase.Prepared, "fedcba9876543210fedcba9876543210",
                new DateTimeOffset(2026, 9, 30, 0, 0, 0, TimeSpan.Zero));
            return fixture;
        }

        internal async Task<byte[]> CreateAlternateMetadataAsync()
        {
            var manifest = await File.ReadAllBytesAsync(Path.Combine(Staged, "Vantrel.Security.TrustedManifest"));
            return ReleaseMetadataCodec.CreateFile(3, Convert.ToHexString(SHA256.HashData(manifest)), "0.1.0",
                new DateTimeOffset(2026, 9, 30, 0, 0, 0, TimeSpan.Zero), _metadataKey);
        }

        private async Task WriteReleaseAsync(string root, ulong sequence, string marker)
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
                Convert.ToHexString(SHA256.HashData(manifest)), "0.1.0", new DateTimeOffset(2026, 9, 30, 0, 0, 0, TimeSpan.Zero), _metadataKey));
        }

        public ValueTask DisposeAsync()
        {
            _metadataKey.Dispose(); _manifestKey.Dispose();
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
            return ValueTask.CompletedTask;
        }
    }

    private class PassThroughOperations : IOfflineUpdateFileOperations
    {
        public void CreateFixedDirectory(string path) => Directory.CreateDirectory(path);
        public FileAttributes GetAttributes(string path) => File.GetAttributes(path);
        public virtual void ApplyProtectedDirectoryAcl(string path, bool allowLocalService) { }
        public virtual void ApplyProtectedFileAcl(string path, bool allowLocalService) { }
        public virtual Task CopyFixedFileContentsAsync(FileStream source, FileStream destination, CancellationToken token) =>
            WindowsOfflineUpdateFileOperations.Instance.CopyFixedFileContentsAsync(source, destination, token);
        public virtual Task FlushFixedFileToDiskAsync(FileStream destination, CancellationToken token) =>
            WindowsOfflineUpdateFileOperations.Instance.FlushFixedFileToDiskAsync(destination, token);
    }

    private sealed class MetadataSubstitutionOperations : PassThroughOperations
    {
        internal byte[] Replacement { get; set; } = null!;
        public override async Task FlushFixedFileToDiskAsync(FileStream destination, CancellationToken token)
        {
            await base.FlushFixedFileToDiskAsync(destination, token);
            if (Path.GetFileName(destination.Name) != "Vantrel.Security.ReleaseMetadata") return;
            destination.Position = 0;
            await destination.WriteAsync(Replacement, token);
            destination.SetLength(Replacement.Length);
            await base.FlushFixedFileToDiskAsync(destination, token);
        }
    }

    private sealed class FailingContentOperations(bool failFlush) : PassThroughOperations
    {
        private int _copies;
        public override async Task CopyFixedFileContentsAsync(FileStream source, FileStream destination, CancellationToken token)
        {
            _copies++;
            if (!failFlush && _copies == 5)
            {
                var bytes = new byte[16];
                await source.ReadExactlyAsync(bytes, token); await destination.WriteAsync(bytes, token);
                throw new IOException("Test-only candidate partial-copy failure.");
            }
            await base.CopyFixedFileContentsAsync(source, destination, token);
        }
        public override Task FlushFixedFileToDiskAsync(FileStream destination, CancellationToken token)
        {
            if (failFlush && _copies == 5) throw new IOException("Test-only candidate flush failure.");
            return base.FlushFixedFileToDiskAsync(destination, token);
        }
    }

    private sealed class MutatingServiceProbe(string staged) : CountingServiceProbe
    {
        public override async Task StopAsync(CancellationToken token)
        {
            await File.AppendAllTextAsync(Path.Combine(staged, FixedServiceReleaseFiles.Components[0].Name), "changed-after-copy", token);
            await base.StopAsync(token);
        }
    }

    private class CountingServiceProbe : IOfflineUpdateServiceControl
    {
        internal int StopCount, StartCount;
        public virtual Task StopAsync(CancellationToken token) { StopCount++; return Task.CompletedTask; }
        public Task StartAsync(CancellationToken token) { StartCount++; return Task.CompletedTask; }
    }

    private sealed class PrivateCandidateFilesProbe(OfflineUpdateStorage storage, OfflineReleaseVerifier verifier, ReleasePolicyStore policy,
        UpdateTransactionJournal expected) : CountingFilesProbe
    {
        internal bool PrivateCandidateVerified, StagedCandidateRejected;
        public override async Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            Assert.AreEqual(expected.TransactionId, journal.TransactionId);
            var privateCandidate = await verifier.VerifyCandidateAsync(storage.PrivateCandidate(journal.TransactionId), policy, token);
            Assert.AreEqual(expected.TargetReleaseSequence, privateCandidate.Sequence);
            Assert.AreEqual(expected.TargetManifestSha256, privateCandidate.ManifestSha256);
            PrivateCandidateVerified = true;
            await Assert.ThrowsExceptionAsync<InvalidDataException>(() => verifier.VerifyChainAsync(storage.StagedCandidate, token));
            StagedCandidateRejected = true;
            await base.ReplaceFromVerifiedPrivateCandidateAsync(journal, token);
        }
    }

    private class CountingFilesProbe : IOfflineUpdateReleaseFiles
    {
        internal int ReplaceCount, RestoreCount;
        public virtual Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) { ReplaceCount++; return Task.CompletedTask; }
        public Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { RestoreCount++; return Task.CompletedTask; }
    }

    private sealed class TargetCommittedHealthProbe : IOfflineUpdateHealth
    {
        internal int PolicyObservationCount;
        public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            PolicyObservationCount++;
            return Task.FromResult(PolicyCommitObservation.TargetCommitted);
        }
    }

    private sealed class JournalProbe : IOfflineUpdateJournal
    {
        internal List<UpdateTransactionPhase> Phases { get; } = [];
        public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token) { Phases.Add(journal.Phase); return Task.CompletedTask; }
    }
}
