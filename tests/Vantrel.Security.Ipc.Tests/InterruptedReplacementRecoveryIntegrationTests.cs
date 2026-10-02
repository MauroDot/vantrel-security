using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class InterruptedReplacementRecoveryIntegrationTests
{
    [DataTestMethod]
    [DataRow(1)]
    [DataRow(4)]
    [DataRow(8)]
    [DataRow(9)]
    public async Task Service_stopped_mixed_release_restores_verified_predecessor_and_is_idempotent(int changedFiles)
    {
        await using var scope = new ReleaseScope();
        await scope.WriteAsync(scope.Installed, "predecessor");
        await scope.WriteAsync(scope.Backup, "predecessor");
        await scope.WriteAsync(scope.Target, "target");
        foreach (var name in FixedServiceReleaseFiles.AllNames.Take(changedFiles))
            File.Copy(Path.Combine(scope.Target, name), Path.Combine(scope.Installed, name), true);

        Assert.AreNotEqual(await scope.FingerprintAsync(scope.Backup), await scope.FingerprintAsync(scope.Installed), "The interrupted installation must be mixed and untrusted.");
        var journal = Journal(scope) with { Phase = UpdateTransactionPhase.ServiceStopped };
        var journalStore = new JournalProbe();
        var files = new FileReleaseFiles(scope, corruptBackup: false);
        var health = new HealthProbe(PolicyCommitObservation.PredecessorRetained);
        var service = new ServiceProbe();
        var engine = new OfflineUpdateTransactionEngine(new PreflightProbe(), service, files, health, journalStore);

        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await engine.RecoverAsync(journal, CancellationToken.None));
        await scope.AssertMatchesAsync(scope.Backup, scope.Installed);
        Assert.AreEqual(1, files.RestoreCalls);
        Assert.AreEqual(1, service.StartCalls);
        Assert.AreEqual(1, health.PredecessorHealthCalls);
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.RollbackRequired, UpdateTransactionPhase.RolledBack }, journalStore.Phases);
        Assert.AreEqual(1UL, health.PolicySequence);

        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await engine.RecoverAsync(journal with { Phase = UpdateTransactionPhase.RolledBack }, CancellationToken.None));
        Assert.AreEqual(1, files.RestoreCalls, "A closed rollback must not restore again.");
        await scope.AssertMatchesAsync(scope.Backup, scope.Installed);
        Assert.AreEqual(1UL, health.PolicySequence);
    }

    [TestMethod]
    public async Task Target_committed_policy_forbids_restore_of_mixed_predecessor()
    {
        await using var scope = new ReleaseScope();
        await scope.WriteAsync(scope.Installed, "predecessor"); await scope.WriteAsync(scope.Backup, "predecessor"); await scope.WriteAsync(scope.Target, "target");
        File.Copy(Path.Combine(scope.Target, FixedServiceReleaseFiles.AllNames[0]), Path.Combine(scope.Installed, FixedServiceReleaseFiles.AllNames[0]), true);
        var files = new FileReleaseFiles(scope, corruptBackup: false); var health = new HealthProbe(PolicyCommitObservation.TargetCommitted);
        var engine = new OfflineUpdateTransactionEngine(new PreflightProbe(), new ServiceProbe(), files, health, new JournalProbe());
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.RecoverAsync(Journal(scope) with { Phase = UpdateTransactionPhase.ServiceStopped }, CancellationToken.None));
        Assert.AreEqual(0, files.RestoreCalls); Assert.AreEqual(2UL, health.PolicySequence);
    }

    [TestMethod]
    public async Task Corrupted_predecessor_backup_fails_closed_without_restore()
    {
        await using var scope = new ReleaseScope();
        await scope.WriteAsync(scope.Installed, "predecessor"); await scope.WriteAsync(scope.Backup, "predecessor"); await scope.WriteAsync(scope.Target, "target");
        File.Copy(Path.Combine(scope.Target, FixedServiceReleaseFiles.AllNames[0]), Path.Combine(scope.Installed, FixedServiceReleaseFiles.AllNames[0]), true);
        var files = new FileReleaseFiles(scope, corruptBackup: true); var store = new JournalProbe();
        var engine = new OfflineUpdateTransactionEngine(new PreflightProbe(), new ServiceProbe(), files, new HealthProbe(PolicyCommitObservation.PredecessorRetained), store);
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, await engine.RecoverAsync(Journal(scope) with { Phase = UpdateTransactionPhase.ServiceStopped }, CancellationToken.None));
        Assert.AreEqual(0, files.RestoreCalls); Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, store.LastPhase);
    }

    private static UpdateTransactionJournal Journal(ReleaseScope scope) => new("0123456789abcdef0123456789abcdef", 1, scope.BackupHash, 2, scope.TargetHash, UpdateTransactionPhase.Prepared, "fedcba9876543210fedcba9876543210", DateTimeOffset.UtcNow);
    private sealed class PreflightProbe : IOfflineUpdatePreflight { public Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask; public Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask; }
    private sealed class ServiceProbe : IOfflineUpdateServiceControl { internal int StartCalls; public Task StopAsync(CancellationToken token) => Task.CompletedTask; public Task StartAsync(CancellationToken token) { StartCalls++; return Task.CompletedTask; } public Task RequireStoppedAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.CompletedTask; } }
    private sealed class HealthProbe(PolicyCommitObservation observation) : IOfflineUpdateHealth { internal int PredecessorHealthCalls; internal ulong PolicySequence = observation == PolicyCommitObservation.TargetCommitted ? 2UL : 1UL; public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.CompletedTask; public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { PredecessorHealthCalls++; return Task.CompletedTask; } public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.FromResult(observation); }
    private sealed class JournalProbe : IOfflineUpdateJournal { internal List<UpdateTransactionPhase> Phases { get; } = []; internal UpdateTransactionPhase? LastPhase => Phases.LastOrDefault(); public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token) { Phases.Add(journal.Phase); return Task.CompletedTask; } }
    private sealed class FileReleaseFiles(ReleaseScope scope, bool corruptBackup) : IOfflineUpdateReleaseFiles
    {
        internal int RestoreCalls;
        public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) => FixedReleaseFileReplacer.ReplaceExactAsync(scope.Target, scope.Installed, token);
        public async Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token)
        {
            await scope.VerifyBackupAsync(corruptBackup, token); RestoreCalls++;
            await FixedReleaseFileReplacer.ReplaceExactAsync(scope.Backup, scope.Installed, token);
        }
    }
    private sealed class ReleaseScope : IAsyncDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "kestermere-task016-recovery-" + Guid.NewGuid().ToString("N"));
        internal string Installed => Path.Combine(Root, "installed"); internal string Backup => Path.Combine(Root, "backup"); internal string Target => Path.Combine(Root, "target");
        internal string BackupHash { get; private set; } = ""; internal string TargetHash { get; private set; } = "";
        internal async Task WriteAsync(string root, string marker)
        {
            Directory.CreateDirectory(root);
            foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(root, name), marker + ":" + name);
            var fingerprint = await HashDirectoryAsync(root); if (root == Backup) BackupHash = fingerprint; if (root == Target) TargetHash = fingerprint;
        }
        internal async Task VerifyBackupAsync(bool corrupt, CancellationToken token)
        {
            if (corrupt) await File.WriteAllTextAsync(Path.Combine(Backup, FixedServiceReleaseFiles.AllNames[0]), "corrupt", token);
            OfflineReleaseVerifier.ValidateExactSet(Backup);
            if (!string.Equals(BackupHash, await HashDirectoryAsync(Backup), StringComparison.Ordinal)) throw new InvalidDataException("Synthetic verified predecessor backup no longer matches.");
        }
        internal async Task AssertMatchesAsync(string expected, string actual)
        {
            OfflineReleaseVerifier.ValidateExactSet(actual);
            foreach (var name in FixedServiceReleaseFiles.AllNames)
                Assert.AreEqual(await HashFileAsync(Path.Combine(expected, name)), await HashFileAsync(Path.Combine(actual, name)), name);
        }
        internal Task<string> FingerprintAsync(string root) => HashDirectoryAsync(root);
        private static async Task<string> HashFileAsync(string path) => Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path)));
        private static async Task<string> HashDirectoryAsync(string root)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var name in FixedServiceReleaseFiles.AllNames) hash.AppendData(await File.ReadAllBytesAsync(Path.Combine(root, name)));
            return Convert.ToHexString(hash.GetHashAndReset());
        }
        public ValueTask DisposeAsync() { if (Directory.Exists(Root)) Directory.Delete(Root, true); return ValueTask.CompletedTask; }
    }
}
