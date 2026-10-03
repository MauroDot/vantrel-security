using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass, DoNotParallelize]
public sealed class TerminalTransactionRetirementTests
{
    private const string Prior = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string Target = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string TransactionId = "0123456789abcdef0123456789abcdef";
    private const string BackupId = "fedcba9876543210fedcba9876543210";
    private const string Nonce = "0123456789abcdef0123456789abcdef";

    [DataTestMethod]
    [DataRow(UpdateTransactionPhase.Completed)]
    [DataRow(UpdateTransactionPhase.RolledBack)]
    [DataRow(UpdateTransactionPhase.Failed)]
    public async Task Exact_terminal_artifacts_retire_and_restore_fresh_admission(UpdateTransactionPhase phase)
    {
        await using var scope = new Scope(); var journal = Journal(phase); scope.WriteJournal(journal); scope.CreateArtifacts();
        var store = scope.Store(); var storage = scope.Storage();
        using var ownership = scope.OwnerLock().TryAcquire(CancellationToken.None);
        Assert.IsNotNull(ownership);
        Assert.AreEqual(TerminalTransactionRetirementResult.Retired, await store.TryRetireTerminalTransactionAsync(journal, ownership!,
            (current, token) => storage.RetireTerminalArtifactsAsync(current, token), CancellationToken.None));

        Assert.IsFalse(Directory.Exists(scope.PrivateCandidate)); Assert.IsFalse(Directory.Exists(scope.TransactionDirectory));
        Assert.IsFalse(Directory.Exists(scope.Backup)); Assert.IsFalse(File.Exists(scope.JournalPath));
        Assert.IsTrue(File.Exists(scope.StagedMarker)); Assert.IsTrue(File.Exists(scope.PolicyMarker));
        Assert.IsTrue(File.Exists(scope.JournalLockPath)); Assert.IsTrue(File.Exists(scope.OwnerLockPath));
        Assert.AreEqual(JournalReadState.Absent, (await store.ReadAsync(CancellationToken.None)).State);
        var admissions = 0;
        await OfflineUpdateAdministrator.WithValidatedJournalAsync(store, existing =>
        {
            Assert.IsNull(existing); admissions++; return Task.FromResult(UpdateTransactionPhase.Prepared);
        }, CancellationToken.None);
        Assert.AreEqual(1, admissions);
    }

    [TestMethod]
    public async Task Crash_after_each_fixed_artifact_deletion_is_idempotently_retired_before_journal()
    {
        var artifactFiles = FixedServiceReleaseFiles.AllNames.Select(name => (Root: "private", Name: name))
            .Concat(FixedServiceReleaseFiles.AllNames.Select(name => (Root: "backup", Name: name))).ToArray();
        for (var deleted = 0; deleted <= artifactFiles.Length; deleted++)
        {
            await using var scope = new Scope(); var journal = Journal(UpdateTransactionPhase.Completed); scope.WriteJournal(journal); scope.CreateArtifacts();
            foreach (var artifact in artifactFiles.Take(deleted))
                File.Delete(Path.Combine(artifact.Root == "private" ? scope.PrivateCandidate : scope.Backup, artifact.Name));
            if (!Directory.EnumerateFileSystemEntries(scope.PrivateCandidate).Any())
            {
                Directory.Delete(scope.PrivateCandidate, recursive: false);
                Directory.Delete(scope.TransactionDirectory, recursive: false);
            }
            if (!Directory.EnumerateFileSystemEntries(scope.Backup).Any()) Directory.Delete(scope.Backup, recursive: false);
            Assert.IsTrue(File.Exists(scope.JournalPath), "A crash before journal retirement must preserve the terminal journal.");
            using var ownership = scope.OwnerLock().TryAcquire(CancellationToken.None);
            Assert.IsNotNull(ownership);
            Assert.AreEqual(TerminalTransactionRetirementResult.Retired, await scope.Store().TryRetireTerminalTransactionAsync(journal, ownership!,
                (current, token) => scope.Storage().RetireTerminalArtifactsAsync(current, token), CancellationToken.None), deleted.ToString());
        }
    }

    [TestMethod]
    public async Task Failure_after_artifact_retirement_preserves_journal_and_retry_completes()
    {
        await using var scope = new Scope(); var journal = Journal(UpdateTransactionPhase.Completed); scope.WriteJournal(journal); scope.CreateArtifacts();
        var store = scope.Store(); var storage = scope.Storage();
        using var ownership = scope.OwnerLock().TryAcquire(CancellationToken.None);
        await Assert.ThrowsExceptionAsync<IOException>(() => store.TryRetireTerminalTransactionAsync(journal, ownership!, async (current, token) =>
        {
            await storage.RetireTerminalArtifactsAsync(current, token);
            throw new IOException("simulated crash after artifact retirement");
        }, CancellationToken.None));
        Assert.IsTrue(File.Exists(scope.JournalPath)); Assert.IsFalse(Directory.Exists(scope.PrivateCandidate)); Assert.IsFalse(Directory.Exists(scope.Backup));
        Assert.AreEqual(TerminalTransactionRetirementResult.Retired, await store.TryRetireTerminalTransactionAsync(journal, ownership!,
            (current, token) => storage.RetireTerminalArtifactsAsync(current, token), CancellationToken.None));
    }

    [DataTestMethod]
    [DataRow(UpdateTransactionPhase.Prepared)]
    [DataRow(UpdateTransactionPhase.Verified)]
    [DataRow(UpdateTransactionPhase.ServiceStopped)]
    [DataRow(UpdateTransactionPhase.Replaced)]
    [DataRow(UpdateTransactionPhase.Restarted)]
    [DataRow(UpdateTransactionPhase.PostVerified)]
    [DataRow(UpdateTransactionPhase.PolicyCommitted)]
    [DataRow(UpdateTransactionPhase.RollbackRequired)]
    [DataRow(UpdateTransactionPhase.RollbackRestartAuthorized)]
    [DataRow(UpdateTransactionPhase.RollbackRestartConsumed)]
    public async Task Nonterminal_journals_decline_without_deletion(UpdateTransactionPhase phase)
    {
        await using var scope = new Scope(); var journal = Journal(phase); scope.WriteJournal(journal); scope.CreateArtifacts();
        var calls = 0;
        using var ownership = scope.OwnerLock().TryAcquire(CancellationToken.None);
        var result = await scope.Store().TryRetireTerminalTransactionAsync(journal, ownership!, (_, _) =>
        {
            calls++; return Task.CompletedTask;
        }, CancellationToken.None);
        Assert.AreEqual(TerminalTransactionRetirementResult.NotEligible, result); Assert.AreEqual(0, calls);
        Assert.IsTrue(File.Exists(scope.JournalPath)); Assert.IsTrue(Directory.Exists(scope.PrivateCandidate)); Assert.IsTrue(Directory.Exists(scope.Backup));
    }

    [TestMethod]
    public async Task Stale_identity_cannot_retire_current_terminal_artifacts()
    {
        await using var scope = new Scope(); var journal = Journal(UpdateTransactionPhase.Completed); scope.WriteJournal(journal); scope.CreateArtifacts();
        var calls = 0; var stale = journal with { BackupId = "11111111111111111111111111111111" };
        using var ownership = scope.OwnerLock().TryAcquire(CancellationToken.None);
        Assert.AreEqual(TerminalTransactionRetirementResult.NotEligible, await scope.Store().TryRetireTerminalTransactionAsync(stale, ownership!, (_, _) =>
        {
            calls++; return Task.CompletedTask;
        }, CancellationToken.None));
        Assert.AreEqual(0, calls); Assert.IsTrue(File.Exists(scope.JournalPath)); Assert.IsTrue(Directory.Exists(scope.PrivateCandidate));
    }

    [TestMethod]
    public async Task Extra_or_substituted_artifacts_and_transaction_residue_fail_closed()
    {
        await using var scope = new Scope(); var journal = Journal(UpdateTransactionPhase.Failed); scope.WriteJournal(journal); scope.CreateArtifacts();
        File.WriteAllText(Path.Combine(scope.PrivateCandidate, "unexpected"), "x");
        using var ownership = scope.OwnerLock().TryAcquire(CancellationToken.None);
        await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store().TryRetireTerminalTransactionAsync(journal, ownership!,
            (current, token) => scope.Storage().RetireTerminalArtifactsAsync(current, token), CancellationToken.None));
        Assert.IsTrue(File.Exists(scope.JournalPath)); Assert.IsTrue(Directory.Exists(scope.PrivateCandidate));

        File.Delete(Path.Combine(scope.PrivateCandidate, "unexpected"));
        File.WriteAllText(Path.Combine(scope.TransactionDirectory, ".transaction-leftover.tmp"), "residue");
        await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store().TryRetireTerminalTransactionAsync(journal, ownership!,
            (current, token) => scope.Storage().RetireTerminalArtifactsAsync(current, token), CancellationToken.None));
        Assert.IsTrue(File.Exists(scope.JournalPath)); Assert.IsTrue(File.Exists(Path.Combine(scope.TransactionDirectory, ".transaction-leftover.tmp")));
    }

    [TestMethod]
    public async Task Directory_substitution_and_unsafe_ancestor_fail_closed()
    {
        await using var substitution = new Scope(); var journal = Journal(UpdateTransactionPhase.Failed); substitution.WriteJournal(journal); substitution.CreateArtifacts();
        substitution.RemovePrivateCandidate(); File.WriteAllText(substitution.PrivateCandidate, "substituted");
        using var ownership = substitution.OwnerLock().TryAcquire(CancellationToken.None);
        await Assert.ThrowsExceptionAsync<IOException>(() => substitution.Store().TryRetireTerminalTransactionAsync(journal, ownership!,
            (current, token) => substitution.Storage().RetireTerminalArtifactsAsync(current, token), CancellationToken.None));
        Assert.IsTrue(File.Exists(substitution.JournalPath));

        await using var ancestor = new Scope(); ancestor.WriteJournal(journal); ancestor.CreateArtifacts(); ancestor.RemoveBackup();
        Directory.Delete(Path.Combine(ancestor.UpdatesRoot, "Backups"), recursive: false);
        File.WriteAllText(Path.Combine(ancestor.UpdatesRoot, "Backups"), "substituted ancestor");
        using var secondOwnership = ancestor.OwnerLock().TryAcquire(CancellationToken.None);
        await Assert.ThrowsExceptionAsync<IOException>(() => ancestor.Store().TryRetireTerminalTransactionAsync(journal, secondOwnership!,
            (current, token) => ancestor.Storage().RetireTerminalArtifactsAsync(current, token), CancellationToken.None));
        Assert.IsTrue(File.Exists(ancestor.JournalPath));
    }

    [TestMethod]
    public async Task Access_denied_artifact_fails_closed()
    {
        await using var scope = new Scope(); var journal = Journal(UpdateTransactionPhase.Completed); scope.WriteJournal(journal); scope.CreateArtifacts();
        using var ownership = scope.OwnerLock().TryAcquire(CancellationToken.None);
        var backupDirectory = new DirectoryInfo(scope.Backup);
        var original = backupDirectory.GetAccessControl(); var denied = backupDirectory.GetAccessControl();
        using var identity = WindowsIdentity.GetCurrent();
        denied.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.ReadData, AccessControlType.Deny));
        try
        {
            backupDirectory.SetAccessControl(denied);
            await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(() => scope.Store().TryRetireTerminalTransactionAsync(journal, ownership!,
                (current, token) => scope.Storage().RetireTerminalArtifactsAsync(current, token), CancellationToken.None));
            Assert.IsTrue(File.Exists(scope.JournalPath));
        }
        finally
        {
            backupDirectory.SetAccessControl(original);
            var cleanup = new DirectorySecurity(); cleanup.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            cleanup.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(scope.Backup).SetAccessControl(cleanup);
        }

    }

    [TestMethod]
    public async Task Reparse_artifact_fails_closed()
    {
        await using var scope = new Scope(); var journal = Journal(UpdateTransactionPhase.Completed); scope.WriteJournal(journal); scope.CreateArtifacts();
        using var ownership = scope.OwnerLock().TryAcquire(CancellationToken.None);
        scope.RemovePrivateCandidate(); var target = Path.Combine(scope.Root, "reparse-target"); Directory.CreateDirectory(target);
        try { Directory.CreateSymbolicLink(scope.PrivateCandidate, target); }
        catch (UnauthorizedAccessException) { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
        catch (IOException error) when ((uint)error.HResult == 0x80070522) { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
        await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store().TryRetireTerminalTransactionAsync(journal, ownership!,
            (current, token) => scope.Storage().RetireTerminalArtifactsAsync(current, token), CancellationToken.None));
        Assert.IsTrue(File.Exists(scope.JournalPath));
    }

    [TestMethod]
    public async Task Owner_contention_and_nonce_consume_revoke_remain_independent()
    {
        await using var scope = new Scope(); var rollback = Journal(UpdateTransactionPhase.RollbackRequired); scope.WriteJournal(rollback);
        var authorized = UpdateTransactionStateMachine.Transition(rollback with { RecoveryStartNonce = Nonce },
            UpdateTransactionPhase.RollbackRestartAuthorized, rollback.UpdatedAtUtc.AddSeconds(1));
        await scope.Store().PersistAsync(authorized, CancellationToken.None);
        using var owner = scope.OwnerLock().TryAcquire(CancellationToken.None);
        Assert.IsNotNull(owner); Assert.IsNull(scope.OwnerLock().TryAcquire(CancellationToken.None));
        var lease = await scope.Store().TryConsumeRecoveryStartLeaseAsync(Nonce, CancellationToken.None);
        Assert.IsNotNull(lease); await scope.Store().RevokeConsumedRecoveryStartAsync(lease!, CancellationToken.None);
        Assert.AreEqual(UpdateTransactionPhase.RollbackRequired, (await scope.Store().ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    private static UpdateTransactionJournal Journal(UpdateTransactionPhase phase) => new(TransactionId, 1, Prior, 2, Target, phase,
        BackupId, new DateTimeOffset(2026, 10, 2, 0, 0, 0, TimeSpan.Zero),
        phase == UpdateTransactionPhase.RollbackRestartAuthorized ? Nonce : null);

    private sealed class Scope : IAsyncDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-terminal-retirement-" + Guid.NewGuid().ToString("N"));
        internal string UpdatesRoot => Path.Combine(Root, "Updates");
        internal string InstalledRoot => Path.Combine(Root, "Installed");
        internal string TransactionsRoot => Path.Combine(UpdatesRoot, "Transactions");
        internal string TransactionDirectory => Path.Combine(TransactionsRoot, TransactionId);
        internal string PrivateCandidate => Path.Combine(TransactionDirectory, "candidate");
        internal string Backup => Path.Combine(UpdatesRoot, "Backups", BackupId);
        internal string JournalPath => Path.Combine(TransactionsRoot, UpdateTransactionJournalStore.JournalFileName);
        internal string JournalLockPath => Path.Combine(UpdatesRoot, UpdateTransactionJournalStore.LockFileName);
        internal string OwnerLockPath => Path.Combine(UpdatesRoot, OfflineUpdateOwnershipLock.OwnerLockFileName);
        internal string StagedMarker => Path.Combine(UpdatesRoot, "Staged", "candidate", "retain");
        internal string PolicyMarker => Path.Combine(Root, "ReleasePolicy", "retain");
        internal Scope()
        {
            Directory.CreateDirectory(TransactionsRoot); Directory.CreateDirectory(InstalledRoot);
            File.WriteAllBytes(JournalLockPath, []); File.WriteAllBytes(OwnerLockPath, []);
            Directory.CreateDirectory(Path.GetDirectoryName(StagedMarker)!); File.WriteAllText(StagedMarker, "retain");
            Directory.CreateDirectory(Path.GetDirectoryName(PolicyMarker)!); File.WriteAllText(PolicyMarker, "retain");
        }
        internal UpdateTransactionJournalStore Store() => new(Root, applyAcls: false);
        internal OfflineUpdateStorage Storage() => new(UpdatesRoot, InstalledRoot, applyAcls: false, WindowsOfflineUpdateFileOperations.Instance);
        internal OfflineUpdateOwnershipLock OwnerLock() => new(Root, applyAcls: false);
        internal void WriteJournal(UpdateTransactionJournal journal) => File.WriteAllBytes(JournalPath, UpdateTransactionJournalCodec.Serialize(journal));
        internal void CreateArtifacts()
        {
            CreatePrivateCandidate(); CreateRelease(Backup);
        }
        internal void CreatePrivateCandidate() => CreateRelease(PrivateCandidate);
        internal void RemovePrivateCandidate()
        {
            foreach (var name in FixedServiceReleaseFiles.AllNames) File.Delete(Path.Combine(PrivateCandidate, name));
            Directory.Delete(PrivateCandidate, recursive: false);
        }
        internal void RemoveBackup()
        {
            foreach (var name in FixedServiceReleaseFiles.AllNames) File.Delete(Path.Combine(Backup, name));
            Directory.Delete(Backup, recursive: false);
        }
        private static void CreateRelease(string root)
        {
            Directory.CreateDirectory(root);
            foreach (var name in FixedServiceReleaseFiles.AllNames) File.WriteAllText(Path.Combine(root, name), name);
        }
        public ValueTask DisposeAsync() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); return ValueTask.CompletedTask; }
    }
}
