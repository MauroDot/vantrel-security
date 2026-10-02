using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class CryptographicRecoveryFixtureTests
{
    [TestMethod]
    public async Task Ephemeral_signed_predecessor_and_target_verify_only_with_test_anchors()
    {
        await using var fixture = await SignedFixture.CreateAsync();
        var verifier = new OfflineReleaseVerifier(fixture.MetadataPublicKey, fixture.ManifestPublicKey);
        var predecessor = await verifier.VerifyChainAsync(fixture.Predecessor, CancellationToken.None);
        var target = await verifier.VerifyChainAsync(fixture.Target, CancellationToken.None);
        Assert.AreEqual(1UL, predecessor.Sequence); Assert.AreEqual(2UL, target.Sequence);
        Assert.AreNotEqual(predecessor.ManifestSha256, target.ManifestSha256);
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => new OfflineReleaseVerifier().VerifyChainAsync(fixture.Predecessor, CancellationToken.None));
    }

    [DataTestMethod]
    [DataRow("metadata-content")]
    [DataRow("metadata-signature")]
    [DataRow("manifest-binding")]
    [DataRow("manifest-signature")]
    [DataRow("component")]
    [DataRow("missing-metadata")]
    [DataRow("extra-file")]
    public async Task Cryptographic_fixture_tampering_is_rejected_before_trust(string kind)
    {
        await using var fixture = await SignedFixture.CreateAsync();
        await fixture.TamperAsync(fixture.Predecessor, kind);
        var verifier = new OfflineReleaseVerifier(fixture.MetadataPublicKey, fixture.ManifestPublicKey);
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => verifier.VerifyChainAsync(fixture.Predecessor, CancellationToken.None));
    }

    [DataTestMethod]
    [DataRow(1)]
    [DataRow(4)]
    [DataRow(8)]
    [DataRow(9)]
    public async Task Interrupted_recovery_restores_test_key_verified_predecessor(int changedFiles)
    {
        await using var fixture = await SignedFixture.CreateAsync();
        var installed = Path.Combine(fixture.Root, "installed");
        CopyDirectory(fixture.Predecessor, installed);
        foreach (var name in FixedServiceReleaseFiles.AllNames.Take(changedFiles)) File.Copy(Path.Combine(fixture.Target, name), Path.Combine(installed, name), true);
        var verifier = new OfflineReleaseVerifier(fixture.MetadataPublicKey, fixture.ManifestPublicKey);
        if (changedFiles < FixedServiceReleaseFiles.AllNames.Length)
            await Assert.ThrowsExceptionAsync<InvalidDataException>(() => verifier.VerifyChainAsync(installed, CancellationToken.None));
        var journal = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", 1, (await verifier.VerifyChainAsync(fixture.Predecessor, CancellationToken.None)).ManifestSha256, 2, (await verifier.VerifyChainAsync(fixture.Target, CancellationToken.None)).ManifestSha256, UpdateTransactionPhase.ServiceStopped, "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 9, 22, 0, 0, 0, TimeSpan.Zero));
        var files = new CryptoFiles(fixture.Predecessor, installed, verifier); var health = new PredecessorHealth(); var journalStore = new CryptoJournal();
        var engine = new OfflineUpdateTransactionEngine(new EmptyPreflight(), new StartProbe(), files, health, journalStore);
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await engine.RecoverAsync(journal, CancellationToken.None));
        Assert.AreEqual(1UL, (await verifier.VerifyChainAsync(installed, CancellationToken.None)).Sequence);
        Assert.AreEqual(1, files.Restores); Assert.AreEqual(UpdateTransactionPhase.RolledBack, journalStore.Phase);
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await engine.RecoverAsync(journal with { Phase = UpdateTransactionPhase.RolledBack }, CancellationToken.None));
        Assert.AreEqual(1, files.Restores);
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var name in FixedServiceReleaseFiles.AllNames) File.Copy(Path.Combine(source, name), Path.Combine(destination, name), true);
    }
    private sealed class EmptyPreflight : IOfflineUpdatePreflight { public Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask; public Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask; }
    private sealed class StartProbe : IOfflineUpdateServiceControl { public Task StopAsync(CancellationToken token) => Task.CompletedTask; public Task StartAsync(CancellationToken token) => Task.CompletedTask; public Task RequireStoppedAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.CompletedTask; } }
    private sealed class CryptoFiles(string backup, string installed, OfflineReleaseVerifier verifier) : IOfflineUpdateReleaseFiles
    {
        internal int Restores;
        public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public async Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            var predecessor = await verifier.VerifyChainAsync(backup, token);
            if (predecessor.Sequence != journal.PriorReleaseSequence || !string.Equals(predecessor.ManifestSha256, journal.PriorManifestSha256, StringComparison.Ordinal)) throw new InvalidDataException("Verified predecessor does not match journal.");
            Restores++; await FixedReleaseFileReplacer.ReplaceExactAsync(backup, installed, token);
        }
    }
    private sealed class PredecessorHealth : IOfflineUpdateHealth { public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask; public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask; public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.FromResult(PolicyCommitObservation.PredecessorRetained); }
    private sealed class CryptoJournal : IOfflineUpdateJournal { internal UpdateTransactionPhase? Phase; public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token) { Phase = journal.Phase; return Task.CompletedTask; } }
    [DataTestMethod]
    [DataRow("metadata-content")]
    [DataRow("metadata-signature")]
    [DataRow("manifest-binding")]
    [DataRow("manifest-signature")]
    [DataRow("component")]
    [DataRow("missing-metadata")]
    [DataRow("extra-file")]
    [DataRow("directory")]
    [DataRow("journal-sequence")]
    [DataRow("journal-manifest")]
    [DataRow("policy-sequence")]
    [DataRow("policy-manifest")]
    public async Task Recovery_refuses_untrusted_or_disagreed_predecessor_before_restore(string kind)
    {
        await using var fixture = await SignedFixture.CreateAsync();
        var installed = Path.Combine(fixture.Root, "installed"); CopyDirectory(fixture.Predecessor, installed);
        File.Copy(Path.Combine(fixture.Target, FixedServiceReleaseFiles.Components[0].Name), Path.Combine(installed, FixedServiceReleaseFiles.Components[0].Name), true);
        var verifier = new OfflineReleaseVerifier(fixture.MetadataPublicKey, fixture.ManifestPublicKey);
        var predecessor = await verifier.VerifyChainAsync(fixture.Predecessor, CancellationToken.None);
        var target = await verifier.VerifyChainAsync(fixture.Target, CancellationToken.None);
        if (kind is not "journal-sequence" and not "journal-manifest" and not "policy-sequence" and not "policy-manifest") await fixture.TamperAsync(fixture.Predecessor, kind);
        var priorSequence = kind == "journal-sequence" ? 9UL : predecessor.Sequence;
        var priorHash = kind == "journal-manifest" ? new string('C', 64) : predecessor.ManifestSha256;
        var policySequence = kind == "policy-sequence" ? 9UL : predecessor.Sequence;
        var policyHash = kind == "policy-manifest" ? new string('D', 64) : predecessor.ManifestSha256;
        var journal = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", priorSequence, priorHash, target.Sequence, target.ManifestSha256, UpdateTransactionPhase.ServiceStopped, "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 9, 22, 0, 0, 0, TimeSpan.Zero));
        var files = new PolicyBoundCryptoFiles(fixture.Predecessor, installed, verifier, policySequence, policyHash); var store = new CryptoJournal();
        var engine = new OfflineUpdateTransactionEngine(new EmptyPreflight(), new StartProbe(), files, new PredecessorHealth(), store);
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await engine.RecoverAsync(journal, CancellationToken.None));
        Assert.AreEqual(0, files.Restores); Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, store.Phase);
        Assert.AreEqual(policySequence, files.PolicySequence); Assert.AreEqual(policyHash, files.PolicyManifestHash);
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => verifier.VerifyChainAsync(installed, CancellationToken.None));
    }

    [TestMethod]
    public async Task Valid_signed_backup_matches_journal_and_policy_then_restores_predecessor()
    {
        await using var fixture = await SignedFixture.CreateAsync();
        var installed = Path.Combine(fixture.Root, "installed"); CopyDirectory(fixture.Predecessor, installed);
        File.Copy(Path.Combine(fixture.Target, FixedServiceReleaseFiles.Components[0].Name), Path.Combine(installed, FixedServiceReleaseFiles.Components[0].Name), true);
        var verifier = new OfflineReleaseVerifier(fixture.MetadataPublicKey, fixture.ManifestPublicKey); var predecessor = await verifier.VerifyChainAsync(fixture.Predecessor, CancellationToken.None); var target = await verifier.VerifyChainAsync(fixture.Target, CancellationToken.None);
        var journal = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", predecessor.Sequence, predecessor.ManifestSha256, target.Sequence, target.ManifestSha256, UpdateTransactionPhase.ServiceStopped, "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 9, 22, 0, 0, 0, TimeSpan.Zero));
        var files = new PolicyBoundCryptoFiles(fixture.Predecessor, installed, verifier, predecessor.Sequence, predecessor.ManifestSha256); var store = new CryptoJournal();
        var engine = new OfflineUpdateTransactionEngine(new EmptyPreflight(), new StartProbe(), files, new PredecessorHealth(), store);
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await engine.RecoverAsync(journal, CancellationToken.None));
        Assert.AreEqual(1, files.Restores); Assert.AreEqual(UpdateTransactionPhase.RolledBack, store.Phase); Assert.AreEqual(1UL, (await verifier.VerifyChainAsync(installed, CancellationToken.None)).Sequence);
    }

    [TestMethod]
    public async Task Target_committed_policy_forbids_restore_even_with_valid_signed_predecessor()
    {
        await using var fixture = await SignedFixture.CreateAsync();
        var installed = Path.Combine(fixture.Root, "installed"); CopyDirectory(fixture.Predecessor, installed);
        File.Copy(Path.Combine(fixture.Target, FixedServiceReleaseFiles.Components[0].Name), Path.Combine(installed, FixedServiceReleaseFiles.Components[0].Name), true);
        var verifier = new OfflineReleaseVerifier(fixture.MetadataPublicKey, fixture.ManifestPublicKey); var predecessor = await verifier.VerifyChainAsync(fixture.Predecessor, CancellationToken.None); var target = await verifier.VerifyChainAsync(fixture.Target, CancellationToken.None);
        var journal = new UpdateTransactionJournal("0123456789abcdef0123456789abcdef", predecessor.Sequence, predecessor.ManifestSha256, target.Sequence, target.ManifestSha256, UpdateTransactionPhase.ServiceStopped, "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 9, 22, 0, 0, 0, TimeSpan.Zero));
        var files = new PolicyBoundCryptoFiles(fixture.Predecessor, installed, verifier, target.Sequence, target.ManifestSha256); var store = new CryptoJournal();
        var engine = new OfflineUpdateTransactionEngine(new EmptyPreflight(), new StartProbe(), files, new TargetCommittedHealth(), store);
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.RecoverAsync(journal, CancellationToken.None));
        Assert.AreEqual(0, files.Restores); Assert.AreEqual(UpdateTransactionPhase.Failed, store.Phase); Assert.AreEqual(target.Sequence, files.PolicySequence);
    }

    private sealed class TargetCommittedHealth : IOfflineUpdateHealth { public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask; public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask; public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.FromResult(PolicyCommitObservation.TargetCommitted); }
    private sealed class PolicyBoundCryptoFiles(string backup, string installed, OfflineReleaseVerifier verifier, ulong policySequence, string policyManifestHash) : IOfflineUpdateReleaseFiles
    {
        internal int Restores; internal ulong PolicySequence => policySequence; internal string PolicyManifestHash => policyManifestHash;
        public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask;
        public async Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            var predecessor = await verifier.VerifyChainAsync(backup, token);
            if (predecessor.Sequence != journal.PriorReleaseSequence || !string.Equals(predecessor.ManifestSha256, journal.PriorManifestSha256, StringComparison.Ordinal) || predecessor.Sequence != policySequence || !string.Equals(predecessor.ManifestSha256, policyManifestHash, StringComparison.Ordinal)) throw new InvalidDataException("Predecessor agreement rejected.");
            Restores++; await FixedReleaseFileReplacer.ReplaceExactAsync(backup, installed, token);
        }
    }
    private sealed class SignedFixture : IAsyncDisposable
    {
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "kestermere-task016-crypto-" + Guid.NewGuid().ToString("N"));
        internal string Predecessor => Path.Combine(Root, "predecessor"); internal string Target => Path.Combine(Root, "target");
        internal byte[] MetadataPublicKey => _metadataKey.ExportSubjectPublicKeyInfo(); internal byte[] ManifestPublicKey => _manifestKey.ExportSubjectPublicKeyInfo();
        internal static async Task<SignedFixture> CreateAsync()
        {
            var fixture = new SignedFixture(); await fixture.WriteReleaseAsync(fixture.Predecessor, 1, "predecessor"); await fixture.WriteReleaseAsync(fixture.Target, 2, "target"); return fixture;
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
            var manifestHash = Convert.ToHexString(SHA256.HashData(manifest));
            await File.WriteAllBytesAsync(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"), ReleaseMetadataCodec.CreateFile(sequence, manifestHash, "0.1.0", new DateTimeOffset(2026, 9, 22, 0, 0, 0, TimeSpan.Zero), _metadataKey));
        }
        internal async Task TamperAsync(string root, string kind)
        {
            var metadata = Path.Combine(root, "Vantrel.Security.ReleaseMetadata"); var manifest = Path.Combine(root, "Vantrel.Security.TrustedManifest");
            switch (kind)
            {
                case "metadata-content": await File.WriteAllTextAsync(metadata, "x\n"); break;
                case "metadata-signature": await ReplaceSignatureAsync(metadata); break;
                case "manifest-binding":
                    var text = await File.ReadAllTextAsync(metadata); await File.WriteAllTextAsync(metadata, text.Replace("manifest-sha256=", "manifest-sha256=" + new string('0', 64)[..1], StringComparison.Ordinal)); break;
                case "manifest-signature": await ReplaceSignatureAsync(manifest); break;
                case "component": await File.AppendAllTextAsync(Path.Combine(root, FixedServiceReleaseFiles.Components[0].Name), "tamper"); break;
                case "missing-metadata": File.Delete(metadata); break;
                case "extra-file": await File.WriteAllTextAsync(Path.Combine(root, "unexpected"), "x"); break;
                case "directory": File.Delete(Path.Combine(root, FixedServiceReleaseFiles.Components[0].Name)); Directory.CreateDirectory(Path.Combine(root, FixedServiceReleaseFiles.Components[0].Name)); break;
                default: throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }
        private static async Task ReplaceSignatureAsync(string path)
        {
            var text = await File.ReadAllTextAsync(path); var marker = "signature="; var start = text.IndexOf(marker, StringComparison.Ordinal) + marker.Length; var end = text.IndexOf('\n', start); var replacement = new string('A', end - start); await File.WriteAllTextAsync(path, text[..start] + replacement + text[end..]);
        }
        public ValueTask DisposeAsync() { _metadataKey.Dispose(); _manifestKey.Dispose(); if (Directory.Exists(Root)) Directory.Delete(Root, true); return ValueTask.CompletedTask; }
    }
}
