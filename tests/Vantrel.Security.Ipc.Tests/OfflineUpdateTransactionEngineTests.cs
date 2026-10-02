using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class OfflineUpdateTransactionEngineTests
{
    [TestMethod]
    public async Task Forward_transaction_reaches_completed_only_after_policy_observation()
    {
        var probe = new Probe { PolicyObservation = PolicyCommitObservation.TargetCommitted }; var engine = new OfflineUpdateTransactionEngine(probe, probe, probe, probe, probe);
        var result = await engine.ExecuteAsync(Journal(), CancellationToken.None);
        Assert.AreEqual(UpdateTransactionPhase.Completed, result);
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.Verified, UpdateTransactionPhase.ServiceStopped, UpdateTransactionPhase.Replaced, UpdateTransactionPhase.Restarted, UpdateTransactionPhase.PostVerified, UpdateTransactionPhase.PolicyCommitted, UpdateTransactionPhase.Completed }, probe.Phases);
    }

    [TestMethod]
    public async Task Preflight_failure_persists_failed_without_stopping_or_replacing()
    {
        var probe = new Probe { ThrowOnCandidateVerification = true, PolicyObservation = PolicyCommitObservation.PredecessorRetained };
        var engine = new OfflineUpdateTransactionEngine(probe, probe, probe, probe, probe);
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(Journal(), CancellationToken.None));
        Assert.AreEqual(0, probe.StopCount); Assert.AreEqual(0, probe.ReplaceCount); Assert.AreEqual(0, probe.RestoreCount);
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.Failed }, probe.Phases);
    }

    [TestMethod]
    public async Task Backup_verification_failure_persists_failed_without_crossing_service_stopped()
    {
        var probe = new Probe { ThrowOnBackupVerification = true, PolicyObservation = PolicyCommitObservation.PredecessorRetained };
        var engine = new OfflineUpdateTransactionEngine(probe, probe, probe, probe, probe);
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(Journal(), CancellationToken.None));
        Assert.AreEqual(0, probe.StopCount); Assert.AreEqual(0, probe.ReplaceCount); Assert.AreEqual(0, probe.RestoreCount);
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.Failed }, probe.Phases);
    }

    [TestMethod]
    public async Task Pre_policy_failure_rolls_back_only_the_verified_predecessor()
    {
        var probe = new Probe { ThrowOnTargetHealth = true, PolicyObservation = PolicyCommitObservation.PredecessorRetained }; var engine = new OfflineUpdateTransactionEngine(probe, probe, probe, probe, probe);
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await engine.ExecuteAsync(Journal(), CancellationToken.None));
        Assert.AreEqual(1, probe.RestoreCount); Assert.AreEqual(1, probe.PredecessorHealthCount);
    }

    [TestMethod]
    public async Task Failure_after_policy_commit_never_restores_predecessor()
    {
        var probe = new Probe { ThrowOnPersistPhase = UpdateTransactionPhase.Completed, PolicyObservation = PolicyCommitObservation.TargetCommitted }; var engine = new OfflineUpdateTransactionEngine(probe, probe, probe, probe, probe);
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(Journal(), CancellationToken.None));
        Assert.AreEqual(0, probe.RestoreCount); Assert.IsTrue(probe.Phases.Contains(UpdateTransactionPhase.PolicyCommitted));
    }


    [TestMethod]
    public async Task Target_policy_commit_forbids_predecessor_restore_after_target_health_failure()
    {
        var probe = new Probe { ThrowOnTargetHealth = true, PolicyObservation = PolicyCommitObservation.TargetCommitted };
        var engine = new OfflineUpdateTransactionEngine(probe, probe, probe, probe, probe);
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(Journal(), CancellationToken.None));
        Assert.AreEqual(0, probe.RestoreCount);
    }

    [TestMethod]
    public async Task Unavailable_policy_fails_closed_without_predecessor_restore()
    {
        var probe = new Probe { ThrowOnTargetHealth = true, PolicyObservation = PolicyCommitObservation.Unavailable };
        var engine = new OfflineUpdateTransactionEngine(probe, probe, probe, probe, probe);
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(Journal(), CancellationToken.None));
        Assert.AreEqual(0, probe.RestoreCount);
    }

    [TestMethod]
    public async Task Service_stopped_recovery_restores_complete_predecessor_when_policy_is_predecessor()
    {
        var probe = new Probe { PolicyObservation = PolicyCommitObservation.PredecessorRetained };
        var engine = new OfflineUpdateTransactionEngine(probe, probe, probe, probe, probe);
        var interrupted = Journal() with { Phase = UpdateTransactionPhase.ServiceStopped };
        Assert.AreEqual(UpdateTransactionPhase.RolledBack, await engine.RecoverAsync(interrupted, CancellationToken.None));
        Assert.AreEqual(1, probe.RestoreCount);
    }

    [TestMethod]
    public async Task Policy_committed_recovery_with_predecessor_policy_fails_closed()
    {
        var probe = new Probe { PolicyObservation = PolicyCommitObservation.PredecessorRetained };
        var engine = new OfflineUpdateTransactionEngine(probe, probe, probe, probe, probe);
        var committed = Journal() with { Phase = UpdateTransactionPhase.PolicyCommitted };
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.RecoverAsync(committed, CancellationToken.None));
    }
    [DataTestMethod]
    [DataRow(UpdateTransactionPhase.Prepared, UpdateTransactionPhase.Prepared, false)]
    [DataRow(UpdateTransactionPhase.Verified, UpdateTransactionPhase.Verified, false)]
    [DataRow(UpdateTransactionPhase.ServiceStopped, UpdateTransactionPhase.RolledBack, false)]
    [DataRow(UpdateTransactionPhase.Replaced, UpdateTransactionPhase.Completed, true)]
    [DataRow(UpdateTransactionPhase.Restarted, UpdateTransactionPhase.Completed, true)]
    [DataRow(UpdateTransactionPhase.PostVerified, UpdateTransactionPhase.Completed, true)]
    [DataRow(UpdateTransactionPhase.PolicyCommitted, UpdateTransactionPhase.Completed, true)]
    [DataRow(UpdateTransactionPhase.Completed, UpdateTransactionPhase.Completed, true)]
    [DataRow(UpdateTransactionPhase.RollbackRequired, UpdateTransactionPhase.RolledBack, false)]
    [DataRow(UpdateTransactionPhase.RolledBack, UpdateTransactionPhase.RolledBack, false)]
    [DataRow(UpdateTransactionPhase.Failed, UpdateTransactionPhase.Failed, false)]
    public async Task Recovery_phase_matrix_is_closed_and_repeated_invocation_is_idempotent(UpdateTransactionPhase phase, UpdateTransactionPhase expected, bool targetCommitted)
    {
        var probe = new Probe { PolicyObservation = targetCommitted ? PolicyCommitObservation.TargetCommitted : PolicyCommitObservation.PredecessorRetained };
        var engine = new OfflineUpdateTransactionEngine(probe, probe, probe, probe, probe);
        var journal = Journal() with { Phase = phase };
        Assert.AreEqual(expected, await engine.RecoverAsync(journal, CancellationToken.None));
        Assert.AreEqual(expected, await engine.RecoverAsync(journal with { Phase = expected }, CancellationToken.None));
        if (phase is UpdateTransactionPhase.PolicyCommitted or UpdateTransactionPhase.Failed) Assert.AreEqual(0, probe.RestoreCount);
    }
    private static UpdateTransactionJournal Journal() => new("0123456789abcdef0123456789abcdef", 1, new string('A', 64), 2, new string('B', 64), UpdateTransactionPhase.Prepared, "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 9, 21, 12, 0, 0, TimeSpan.Zero));
    [DataTestMethod]
    [DataRow(true, true)] [DataRow(true, false)] [DataRow(false, true)] [DataRow(false, false)]
    public async Task Real_storage_acl_failure_stays_before_service_stop(bool candidate, bool directoryAcl)
    {
        await using var scope = new StorageScope(); var operations = new StorageOperations(directoryAcl ? (candidate ? 3 : 2) : null, directoryAcl ? null : 1);
        var storage = new OfflineUpdateStorage(scope.Updates, scope.Installed, true, operations);
        if (candidate) await scope.WriteAsync(Path.Combine(scope.Updates, "Staged", "candidate")); else await scope.WriteAsync(scope.Installed);
        var preflight = new StoragePreflight(storage, candidate); var service = new ServiceProbe(); var files = new FilesProbe(); var health = new HealthProbe(); var journal = new JournalProbe();
        var engine = new OfflineUpdateTransactionEngine(preflight, service, files, health, journal);
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(Journal(), CancellationToken.None));
        Assert.AreEqual(0, service.Stop); Assert.AreEqual(0, files.Replace); Assert.AreEqual(0, files.Restore); Assert.AreEqual(0, health.Policy); CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.Failed }, journal.Phases);
    }
    [DataTestMethod]
    [DataRow(true, false)] [DataRow(true, true)] [DataRow(false, false)] [DataRow(false, true)]
    public async Task Real_storage_copy_or_flush_failure_stays_before_installation_mutation(bool candidate, bool flushFailure)
    {
        await using var scope = new StorageScope();
        var state = Journal();
        var source = candidate ? Path.Combine(scope.Updates, "Staged", "candidate") : scope.Installed;
        Directory.CreateDirectory(source);
        var originals = new Dictionary<string, byte[]>();
        foreach (var name in FixedServiceReleaseFiles.AllNames)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat(name, 256)));
            originals.Add(name, bytes);
            await File.WriteAllBytesAsync(Path.Combine(source, name), bytes);
        }
        var operations = new StorageOperations(null, null) { ContentFailure = flushFailure ? "flush" : "copy" };
        var storage = new OfflineUpdateStorage(scope.Updates, scope.Installed, true, operations);
        if (!candidate)
        {
            await scope.WriteAsync(storage.StagedCandidate);
            var preparation = new OfflineUpdateStorage(scope.Updates, scope.Installed, false, WindowsOfflineUpdateFileOperations.Instance);
            await preparation.CopyStagedToPrivateAsync(state.TransactionId, CancellationToken.None);
        }
        var destination = candidate ? storage.PrivateCandidate(state.TransactionId) : storage.Backup(state.BackupId);
        var sibling = Path.Combine(Path.GetDirectoryName(destination)!, "unrelated-sibling");
        Directory.CreateDirectory(sibling);
        var sentinel = Path.Combine(sibling, "sentinel");
        await File.WriteAllTextAsync(sentinel, "unchanged");
        var service = new ServiceProbe(); var files = new FilesProbe(); var health = new HealthProbe(); var journal = new JournalProbe();
        var engine = new OfflineUpdateTransactionEngine(new StoragePreflight(storage, candidate), service, files, health, journal);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Assert.AreEqual(UpdateTransactionPhase.Failed, await engine.ExecuteAsync(state, timeout.Token).WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.AreEqual(Path.Combine(destination, FixedServiceReleaseFiles.AllNames[4]), operations.FailurePath);
        Assert.AreEqual(flushFailure ? originals[FixedServiceReleaseFiles.AllNames[4]].LongLength : 4096L, operations.FailureBytes);
        Assert.AreEqual(flushFailure, operations.FailureAfterFlushAsync);
        Assert.IsTrue(operations.ExclusiveHandleObserved);
        Assert.AreEqual(5, operations.Copies.Count);
        Assert.AreEqual(flushFailure ? 5 : 4, operations.AttemptedFlushes.Count);
        Assert.AreEqual(4, operations.CompletedFlushes.Count);
        CollectionAssert.AreEqual(FixedServiceReleaseFiles.AllNames.Take(5).ToArray(), operations.Copies.Select(Path.GetFileName).ToArray());
        CollectionAssert.AreEqual(FixedServiceReleaseFiles.AllNames.Take(4).ToArray(), operations.CompletedFlushes.Select(Path.GetFileName).ToArray());
        Assert.AreEqual(0, service.Stop); Assert.AreEqual(0, service.Start);
        Assert.AreEqual(0, files.Replace); Assert.AreEqual(0, files.Restore); Assert.AreEqual(0, health.Policy);
        CollectionAssert.AreEqual(new[] { UpdateTransactionPhase.Failed }, journal.Phases);
        Assert.IsFalse(Directory.Exists(destination));
        Assert.ThrowsException<DirectoryNotFoundException>(() => OfflineReleaseVerifier.ValidateExactSet(destination));
        foreach (var name in FixedServiceReleaseFiles.AllNames)
        {
            Assert.IsFalse(File.Exists(Path.Combine(destination, name)));
            using var input = new FileStream(Path.Combine(source, name), FileMode.Open, FileAccess.Read, FileShare.None);
            using var contents = new MemoryStream();
            await input.CopyToAsync(contents);
            CollectionAssert.AreEqual(originals[name], contents.ToArray());
            if (!candidate) Assert.AreEqual(name, await File.ReadAllTextAsync(Path.Combine(storage.PrivateCandidate(state.TransactionId), name)));
        }
        if (!candidate) OfflineReleaseVerifier.ValidateExactSet(storage.PrivateCandidate(state.TransactionId));
        OfflineReleaseVerifier.ValidateExactSet(source);
        Assert.AreEqual("unchanged", await File.ReadAllTextAsync(sentinel));
        CollectionAssert.AreEqual(new[] { sentinel }, Directory.GetFileSystemEntries(sibling));
        // Destination denied concurrent opening without delete sharing. Storage's
        // successful deletion proves release before cleanup; source exclusive opens
        // above prove source handles released. Journal observations are in-memory only.
    }

    private sealed class Probe : IOfflineUpdatePreflight, IOfflineUpdateServiceControl, IOfflineUpdateReleaseFiles, IOfflineUpdateHealth, IOfflineUpdateJournal
    {
        public Task RequireStoppedAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.CompletedTask; }
        internal List<UpdateTransactionPhase> Phases { get; } = []; internal bool ThrowOnCandidateVerification; internal bool ThrowOnBackupVerification; internal bool ThrowOnTargetHealth; internal int StopCount; internal int ReplaceCount; internal UpdateTransactionPhase? ThrowOnPersistPhase; internal int RestoreCount; internal int PredecessorHealthCount; internal PolicyCommitObservation PolicyObservation = PolicyCommitObservation.Unavailable;
        public Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal journal, CancellationToken token) { if (ThrowOnCandidateVerification) throw new IOException(); return Task.CompletedTask; } public Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal journal, CancellationToken token) { if (ThrowOnBackupVerification) throw new IOException(); return Task.CompletedTask; }
        public Task StopAsync(CancellationToken token) { StopCount++; return Task.CompletedTask; } public Task StartAsync(CancellationToken token) => Task.CompletedTask; public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal journal, CancellationToken token) { ReplaceCount++; return Task.CompletedTask; }
        public Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { RestoreCount++; return Task.CompletedTask; }
        public Task VerifyTargetAsync(UpdateTransactionJournal journal, CancellationToken token) { if (ThrowOnTargetHealth) throw new IOException(); return Task.CompletedTask; }
        public Task VerifyPredecessorAsync(UpdateTransactionJournal journal, CancellationToken token) { PredecessorHealthCount++; return Task.CompletedTask; } public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal journal, CancellationToken token) => Task.FromResult(PolicyObservation);
        public Task PersistAsync(UpdateTransactionJournal journal, CancellationToken token) { Phases.Add(journal.Phase); if (ThrowOnPersistPhase == journal.Phase) throw new IOException(); return Task.CompletedTask; }
    }
    private sealed class StoragePreflight(OfflineUpdateStorage storage, bool candidate) : IOfflineUpdatePreflight { public Task VerifyCandidateAndBaselineAsync(UpdateTransactionJournal j,CancellationToken t)=>candidate?storage.CopyStagedToPrivateAsync(j.TransactionId,t):Task.CompletedTask; public Task CreateAndVerifyPredecessorBackupAsync(UpdateTransactionJournal j,CancellationToken t)=>candidate?Task.CompletedTask:storage.CopyInstalledToBackupAsync(j.BackupId,t); }
    private sealed class StorageOperations(int? directoryAt,int? fileAt) : IOfflineUpdateFileOperations
    {
        internal string? ContentFailure;
        internal List<string> Copies { get; } = [];
        internal List<string> AttemptedFlushes { get; } = [];
        internal List<string> CompletedFlushes { get; } = [];
        internal string? FailurePath;
        internal long FailureBytes;
        internal bool FailureAfterFlushAsync, ExclusiveHandleObserved;
        public async Task CopyFixedFileContentsAsync(FileStream source, FileStream destination, CancellationToken token)
        {
            Assert.IsTrue(source.CanRead && destination.CanWrite);
            Copies.Add(destination.Name);
            if (ContentFailure == "copy" && Copies.Count == 5)
            {
                var bytes = new byte[4096]; Assert.IsTrue(source.Length > bytes.Length);
                await source.ReadExactlyAsync(bytes, token); await destination.WriteAsync(bytes, token);
                Assert.AreEqual(4096L, destination.Position); Assert.AreEqual(4096L, destination.Length);
                FailContent(destination);
            }
            await WindowsOfflineUpdateFileOperations.Instance.CopyFixedFileContentsAsync(source, destination, token);
            Assert.AreEqual(source.Length, source.Position);
            Assert.AreEqual(source.Length, destination.Position); Assert.AreEqual(source.Length, destination.Length);
        }
        public async Task FlushFixedFileToDiskAsync(FileStream destination, CancellationToken token)
        {
            Assert.IsTrue(destination.CanWrite);
            AttemptedFlushes.Add(destination.Name);
            if (ContentFailure == "flush" && AttemptedFlushes.Count == 5)
            {
                await destination.FlushAsync(token); FailureAfterFlushAsync = true;
                // Inject at the provider boundary before Flush(true), not a hardware failure.
                FailContent(destination);
            }
            await WindowsOfflineUpdateFileOperations.Instance.FlushFixedFileToDiskAsync(destination, token);
            CompletedFlushes.Add(destination.Name);
        }
        private void FailContent(FileStream destination)
        {
            FailurePath = destination.Name; FailureBytes = destination.Length;
            var failure = Assert.ThrowsException<IOException>(() =>
            {
                using var other = new FileStream(destination.Name, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            });
            Assert.AreEqual(0x80070020u, unchecked((uint)failure.HResult));
            ExclusiveHandleObserved = true;
            throw new IOException("Test-only storage content failure.");
        }
        int d,f;
        public void CreateFixedDirectory(string p)=>Directory.CreateDirectory(p);
        public FileAttributes GetAttributes(string p)=>File.GetAttributes(p);
        public void ApplyProtectedDirectoryAcl(string p,bool a){if(++d==directoryAt)throw new IOException();}
        public void ApplyProtectedFileAcl(string p,bool a){if(++f==fileAt)throw new IOException();}
    }
    private sealed class ServiceProbe : IOfflineUpdateServiceControl { internal int Stop, Start; public Task StopAsync(CancellationToken t){Stop++;return Task.CompletedTask;} public Task StartAsync(CancellationToken t){Start++;return Task.CompletedTask;} public Task RequireStoppedAsync(CancellationToken t){t.ThrowIfCancellationRequested();return Task.CompletedTask;} }
    private sealed class FilesProbe : IOfflineUpdateReleaseFiles { internal int Replace,Restore; public Task ReplaceFromVerifiedPrivateCandidateAsync(UpdateTransactionJournal j,CancellationToken t){Replace++;return Task.CompletedTask;} public Task RestoreVerifiedPredecessorAsync(UpdateTransactionJournal j,CancellationToken t){Restore++;return Task.CompletedTask;} }
    private sealed class HealthProbe : IOfflineUpdateHealth { internal int Policy; public Task VerifyTargetAsync(UpdateTransactionJournal j,CancellationToken t)=>Task.CompletedTask; public Task VerifyPredecessorAsync(UpdateTransactionJournal j,CancellationToken t)=>Task.CompletedTask; public Task<PolicyCommitObservation> ObservePolicyCommitAsync(UpdateTransactionJournal j,CancellationToken t){Policy++;return Task.FromResult(PolicyCommitObservation.PredecessorRetained);} }
    private sealed class JournalProbe : IOfflineUpdateJournal { internal List<UpdateTransactionPhase> Phases {get;}=[]; public Task PersistAsync(UpdateTransactionJournal j,CancellationToken t){Phases.Add(j.Phase);return Task.CompletedTask;} }
    private sealed class StorageScope : IAsyncDisposable { internal string Root {get;}=Path.Combine(Path.GetTempPath(),"vantrel-tx-"+Guid.NewGuid().ToString("N")); internal string Updates=>Path.Combine(Root,"Updates"); internal string Installed=>Path.Combine(Root,"Installed"); internal async Task WriteAsync(string root){Directory.CreateDirectory(root);foreach(var n in FixedServiceReleaseFiles.AllNames)await File.WriteAllTextAsync(Path.Combine(root,n),n);} public ValueTask DisposeAsync(){if(Directory.Exists(Root))Directory.Delete(Root,true);return ValueTask.CompletedTask;} }
}
