using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class V2PreStopUpdateCoordinatorTests
{
    private const string TransactionId = "11111111111111111111111111111111";
    private const string BackupId = "22222222222222222222222222222222";

    [TestMethod]
    public async Task Signed_v2_admission_creates_only_one_canonical_Admitted_journal()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        var admitted = await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);

        Assert.AreEqual(V2UpdateTransactionPhase.Admitted, admitted.Phase);
        Assert.AreEqual(scope.Predecessor, admitted.Predecessor);
        Assert.AreEqual(scope.Target, admitted.Target);
        Assert.AreEqual(TransactionId, admitted.TransactionId);
        Assert.AreEqual(BackupId, admitted.BackupId);
        Assert.IsNull(admitted.RecoveryStartNonce);
        Assert.AreEqual(TimeSpan.Zero, admitted.UpdatedAtUtc.Offset);
        Assert.AreEqual(0, admitted.UpdatedAtUtc.Ticks % TimeSpan.TicksPerSecond);
        CollectionAssert.AreEqual(V2UpdateTransactionJournalCodec.Serialize(admitted),
            File.ReadAllBytes(scope.V2JournalPath));
        Assert.IsFalse(Directory.Exists(scope.PrivatePath));
        Assert.IsFalse(Directory.Exists(scope.BackupPath));
        Assert.AreEqual(0, Directory.GetFileSystemEntries(scope.ArtifactTransactionsRoot).Length);
        Assert.AreEqual(0, Directory.GetFileSystemEntries(scope.ArtifactBackupsRoot).Length);
    }

    [TestMethod]
    public async Task One_invocation_advances_only_one_phase_and_BackupReady_is_read_only()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        var coordinator = scope.Coordinator();
        var admitted = await coordinator.AdmitAsync(lease, CancellationToken.None);
        Assert.IsFalse(Directory.Exists(scope.PrivatePath));
        var privateReady = await coordinator.AdvancePrivateAsync(lease, CancellationToken.None);
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady, privateReady.Phase);
        Assert.IsFalse(Directory.Exists(scope.BackupPath));
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.PrivatePath, CancellationToken.None)).Result);
        var backupReady = await coordinator.AdvanceBackupAsync(lease, CancellationToken.None);
        Assert.AreEqual(V2UpdateTransactionPhase.BackupReady, backupReady.Phase);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.BackupPath, CancellationToken.None)).Result);
        var journalBytes = File.ReadAllBytes(scope.V2JournalPath);
        var privateFiles = Directory.GetFiles(scope.PrivatePath, "*", SearchOption.AllDirectories);
        var backupFiles = Directory.GetFiles(scope.BackupPath, "*", SearchOption.AllDirectories);
        Assert.AreEqual(backupReady, await coordinator.ObserveBackupReadyAsync(lease, CancellationToken.None));
        CollectionAssert.AreEqual(journalBytes, File.ReadAllBytes(scope.V2JournalPath));
        CollectionAssert.AreEquivalent(privateFiles, Directory.GetFiles(scope.PrivatePath, "*", SearchOption.AllDirectories));
        CollectionAssert.AreEquivalent(backupFiles, Directory.GetFiles(scope.BackupPath, "*", SearchOption.AllDirectories));
        Assert.AreEqual(admitted.TransactionId, backupReady.TransactionId);
        Assert.AreEqual(admitted.BackupId, backupReady.BackupId);
    }

    [TestMethod]
    public async Task Wrong_root_and_disposed_owner_lease_cannot_admit_or_advance()
    {
        using var scope = new Scope();
        using var other = new Scope();
        using var wrong = other.Acquire();
        await RejectAsync(() => scope.Coordinator().AdmitAsync(wrong, CancellationToken.None));
        Assert.IsFalse(File.Exists(scope.V2JournalPath));

        var held = scope.Acquire();
        held.Dispose();
        await RejectAsync(() => scope.Coordinator().AdmitAsync(held, CancellationToken.None));
        Assert.IsFalse(File.Exists(scope.V2JournalPath));

        using var valid = scope.Acquire();
        await scope.Coordinator().AdmitAsync(valid, CancellationToken.None);
        await RejectAsync(() => scope.Coordinator().AdvancePrivateAsync(wrong, CancellationToken.None));
        await RejectAsync(() => scope.Coordinator().AdvancePrivateAsync(held, CancellationToken.None));
        Assert.AreEqual(V2UpdateTransactionPhase.Admitted, (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.IsFalse(Directory.Exists(scope.PrivatePath));
    }

    [DataTestMethod]
    [DataRow("v1-invalid")]
    [DataRow("v1-present")]
    [DataRow("v1-missing-infrastructure")]
    [DataRow("v2-invalid")]
    [DataRow("v2-missing-infrastructure")]
    [DataRow("v2-present")]
    [DataRow("simultaneous-journals")]
    [DataRow("policy-missing")]
    [DataRow("policy-malformed")]
    [DataRow("policy-v1")]
    [DataRow("policy-wrong")]
    [DataRow("installed-tampered")]
    [DataRow("installed-v1")]
    [DataRow("staged-tampered")]
    [DataRow("staged-v1")]
    [DataRow("staged-exact-same")]
    [DataRow("staged-same")]
    [DataRow("staged-lower")]
    public async Task Admission_rejects_conflicting_or_unavailable_durable_and_signed_state(string mutation)
    {
        using var scope = new Scope();
        switch (mutation)
        {
            case "v1-invalid": File.WriteAllText(scope.V1JournalPath, "invalid"); break;
            case "v1-present": scope.WriteV1Journal(); break;
            case "v1-missing-infrastructure": File.Delete(scope.V1LockPath); break;
            case "v2-invalid": File.WriteAllText(scope.V2JournalPath, "invalid"); break;
            case "v2-missing-infrastructure": File.Delete(scope.V2LockPath); break;
            case "v2-present": await scope.V2Journal.PersistAsync(scope.TestJournal(), CancellationToken.None); break;
            case "simultaneous-journals": scope.WriteV1Journal();
                await scope.V2Journal.PersistAsync(scope.TestJournal(), CancellationToken.None); break;
            case "policy-missing": File.Delete(scope.PolicyPath); break;
            case "policy-malformed": File.WriteAllText(scope.PolicyPath, "invalid"); break;
            case "policy-v1": scope.WriteV1Policy(); break;
            case "policy-wrong": scope.WritePolicy(scope.Target); break;
            case "installed-tampered": File.AppendAllText(Path.Combine(scope.InstalledRoot, "Vantrel.Security.Service.exe"), "changed"); break;
            case "installed-v1": scope.WriteSignedV1(scope.InstalledRoot); break;
            case "staged-tampered": File.AppendAllText(Path.Combine(scope.StagedRoot, "Vantrel.Security.Service.exe"), "changed"); break;
            case "staged-v1": scope.WriteSignedV1(scope.StagedRoot); break;
            case "staged-exact-same": scope.CopyInstalledToStaged(); break;
            case "staged-same": scope.WriteSignedV2(scope.StagedRoot, 7, "installed"); break;
            case "staged-lower": scope.WriteSignedV2(scope.StagedRoot, 6, "older"); break;
        }
        var before = File.Exists(scope.V2JournalPath) ? File.ReadAllBytes(scope.V2JournalPath) : null;
        using var lease = scope.Acquire();
        await RejectAsync(() => scope.Coordinator().AdmitAsync(lease, CancellationToken.None));
        if (before is null) Assert.IsFalse(File.Exists(scope.V2JournalPath));
        else CollectionAssert.AreEqual(before, File.ReadAllBytes(scope.V2JournalPath));
        Assert.IsFalse(Directory.Exists(scope.PrivatePath));
    }

    [TestMethod]
    public async Task Fault_before_admission_publication_leaves_no_journal_or_artifact()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await RejectAsync(() => scope.Coordinator(checkpoint: stage =>
        {
            if (stage == "BeforeAdmissionPublication") throw new IOException("injected pre-publication fault");
        }).AdmitAsync(lease, CancellationToken.None));
        Assert.IsFalse(File.Exists(scope.V2JournalPath));
        Assert.IsFalse(Directory.Exists(scope.PrivatePath));
        Assert.IsFalse(Directory.Exists(scope.BackupPath));
    }

    [TestMethod]
    public async Task Admission_publication_attempt_is_ambiguous_and_never_starts_copy()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        var journal = scope.V2JournalWithAfterPublicationFault();
        await Assert.ThrowsExceptionAsync<V2JournalPostPublicationException>(() =>
            scope.Coordinator(v2Journal: journal).AdmitAsync(lease, CancellationToken.None));
        Assert.IsFalse(Directory.Exists(scope.PrivatePath));
        Assert.IsFalse(Directory.Exists(scope.BackupPath));
        Assert.AreEqual(V2JournalReadState.Present, (await scope.V2Journal.ReadAsync(CancellationToken.None)).State);
    }

    [TestMethod]
    public async Task Completed_private_copy_after_transition_fault_is_reconciled_without_recopy()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        await RejectAsync(() => scope.Coordinator(checkpoint: stage =>
        {
            if (stage == "AfterPrivateCopyBeforeTransition") throw new IOException("injected private transition fault");
        }).AdvancePrivateAsync(lease, CancellationToken.None));
        Assert.AreEqual(V2UpdateTransactionPhase.Admitted, (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.PrivatePath, CancellationToken.None)).Result);
        var unchanged = File.ReadAllBytes(Path.Combine(scope.PrivatePath, "Vantrel.Security.TrustedManifest"));
        var noRecopy = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage == "BeforeRoot") throw new IOException("attempted recopy");
        });
        var ready = await scope.Coordinator(artifacts: noRecopy).AdvancePrivateAsync(lease, CancellationToken.None);
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady, ready.Phase);
        CollectionAssert.AreEqual(unchanged,
            File.ReadAllBytes(Path.Combine(scope.PrivatePath, "Vantrel.Security.TrustedManifest")));
    }

    [DataTestMethod]
    [DataRow("policy")]
    [DataRow("private")]
    [DataRow("v1-journal")]
    public async Task Late_private_publication_change_cannot_advance_Admitted(string mutation)
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        var changed = false;
        await RejectAsync(() => scope.Coordinator(checkpoint: stage =>
        {
            if (stage != "BeforePrivatePublication") return;
            changed = true;
            switch (mutation)
            {
                case "policy": scope.WritePolicy(scope.Target); break;
                case "private": File.AppendAllText(Path.Combine(scope.PrivatePath, "Vantrel.Security.Service.exe"), "late mutation"); break;
                case "v1-journal": scope.WriteV1Journal(); break;
            }
        }).AdvancePrivateAsync(lease, CancellationToken.None));
        Assert.IsTrue(changed);
        Assert.AreEqual(V2UpdateTransactionPhase.Admitted,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.IsFalse(Directory.Exists(scope.BackupPath));
    }

    [TestMethod]
    public async Task Ambiguous_private_publication_never_starts_backup_and_requires_fresh_read()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        await Assert.ThrowsExceptionAsync<V2JournalPostPublicationException>(() =>
            scope.Coordinator(v2Journal: scope.V2JournalWithAfterPublicationFault())
                .AdvancePrivateAsync(lease, CancellationToken.None));
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.IsFalse(Directory.Exists(scope.BackupPath));
        await RejectAsync(() => scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None));
    }

    [TestMethod]
    public async Task Private_copy_failure_preserves_partial_residue_and_Admitted_journal()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        var failingStorage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage == "AfterFile") throw new IOException("injected private copy fault");
        });
        await RejectAsync(() => scope.Coordinator(artifacts: failingStorage)
            .AdvancePrivateAsync(lease, CancellationToken.None));
        Assert.AreEqual(V2UpdateTransactionPhase.Admitted,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.IsTrue(Directory.Exists(scope.PrivatePath));
        await RejectAsync(() => scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None));
        Assert.AreEqual(V2UpdateTransactionPhase.Admitted,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [TestMethod]
    public async Task Cancellation_after_private_copy_keeps_reconcilable_residue()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => scope.Coordinator(checkpoint: stage =>
        {
            if (stage == "AfterPrivateCopyBeforeTransition") cancellation.Cancel();
        }).AdvancePrivateAsync(lease, cancellation.Token));
        Assert.AreEqual(V2UpdateTransactionPhase.Admitted,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.IsTrue(Directory.Exists(scope.PrivatePath));
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady,
            (await scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None)).Phase);
    }

    [DataTestMethod]
    [DataRow("partial")]
    [DataRow("wrong-identity")]
    [DataRow("foreign-sibling")]
    [DataRow("staged-changed")]
    [DataRow("policy-changed")]
    [DataRow("v1-journal")]
    [DataRow("v1-missing-infrastructure")]
    [DataRow("v2-invalid")]
    public async Task Admitted_never_advances_through_invalid_residue_or_changed_authority(string mutation)
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        switch (mutation)
        {
            case "partial": Directory.CreateDirectory(scope.PrivatePath); break;
            case "wrong-identity": scope.WriteSignedV2(scope.PrivatePath, 9, "other target"); break;
            case "foreign-sibling": Directory.CreateDirectory(Path.Combine(scope.ArtifactTransactionsRoot, "33333333333333333333333333333333")); break;
            case "staged-changed": File.AppendAllText(Path.Combine(scope.StagedRoot, "Vantrel.Security.Service.exe"), "tampered"); break;
            case "policy-changed": scope.WritePolicy(scope.Target); break;
            case "v1-journal": scope.WriteV1Journal(); break;
            case "v1-missing-infrastructure": File.Delete(scope.V1LockPath); break;
            case "v2-invalid": File.WriteAllText(scope.V2JournalPath, "invalid"); break;
        }
        await RejectAsync(() => scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None));
        if (mutation != "v2-invalid")
            Assert.AreEqual(V2UpdateTransactionPhase.Admitted, (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [TestMethod]
    public async Task Completed_backup_after_transition_fault_is_reconciled_without_recopy()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        await scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None);
        await RejectAsync(() => scope.Coordinator(checkpoint: stage =>
        {
            if (stage == "AfterBackupCopyBeforeTransition") throw new IOException("injected backup transition fault");
        }).AdvanceBackupAsync(lease, CancellationToken.None));
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady, (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.AreEqual(GenerationAwareOfflineVerificationResult.Authenticated,
            (await scope.Verifier.VerifyChainAsync(scope.BackupPath, CancellationToken.None)).Result);
        var noRecopy = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage == "BeforeRoot") throw new IOException("attempted recopy");
        });
        Assert.AreEqual(V2UpdateTransactionPhase.BackupReady,
            (await scope.Coordinator(artifacts: noRecopy).AdvanceBackupAsync(lease, CancellationToken.None)).Phase);
    }

    [DataTestMethod]
    [DataRow("policy")]
    [DataRow("private")]
    [DataRow("backup")]
    [DataRow("installed")]
    [DataRow("v1-journal")]
    public async Task Late_backup_publication_change_cannot_advance_PrivateReady(string mutation)
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        await scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None);
        var changed = false;
        await RejectAsync(() => scope.Coordinator(checkpoint: stage =>
        {
            if (stage != "BeforeBackupPublication") return;
            changed = true;
            switch (mutation)
            {
                case "policy": scope.WritePolicy(scope.Target); break;
                case "private": File.AppendAllText(Path.Combine(scope.PrivatePath, "Vantrel.Security.Service.exe"), "late mutation"); break;
                case "backup": File.AppendAllText(Path.Combine(scope.BackupPath, "Vantrel.Security.Service.exe"), "late mutation"); break;
                case "installed": File.AppendAllText(Path.Combine(scope.InstalledRoot, "Vantrel.Security.Service.exe"), "late mutation"); break;
                case "v1-journal": scope.WriteV1Journal(); break;
            }
        }).AdvanceBackupAsync(lease, CancellationToken.None));
        Assert.IsTrue(changed);
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [TestMethod]
    public async Task Ambiguous_backup_publication_stops_at_BackupReady_and_retains_artifacts()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        await scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None);
        await Assert.ThrowsExceptionAsync<V2JournalPostPublicationException>(() =>
            scope.Coordinator(v2Journal: scope.V2JournalWithAfterPublicationFault())
                .AdvanceBackupAsync(lease, CancellationToken.None));
        Assert.AreEqual(V2UpdateTransactionPhase.BackupReady,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.IsTrue(Directory.Exists(scope.PrivatePath));
        Assert.IsTrue(Directory.Exists(scope.BackupPath));
        await RejectAsync(() => scope.Coordinator().AdvanceBackupAsync(lease, CancellationToken.None));
    }

    [TestMethod]
    public async Task Backup_copy_failure_preserves_partial_residue_and_PrivateReady_journal()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        await scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None);
        var failingStorage = scope.StorageWithFault(checkpoint =>
        {
            if (checkpoint.Stage == "AfterFile") throw new IOException("injected backup copy fault");
        });
        await RejectAsync(() => scope.Coordinator(artifacts: failingStorage)
            .AdvanceBackupAsync(lease, CancellationToken.None));
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.IsTrue(Directory.Exists(scope.BackupPath));
        await RejectAsync(() => scope.Coordinator().AdvanceBackupAsync(lease, CancellationToken.None));
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [TestMethod]
    public async Task Cancellation_after_backup_copy_keeps_reconcilable_residue()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        await scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => scope.Coordinator(checkpoint: stage =>
        {
            if (stage == "AfterBackupCopyBeforeTransition") cancellation.Cancel();
        }).AdvanceBackupAsync(lease, cancellation.Token));
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.IsTrue(Directory.Exists(scope.BackupPath));
        Assert.AreEqual(V2UpdateTransactionPhase.BackupReady,
            (await scope.Coordinator().AdvanceBackupAsync(lease, CancellationToken.None)).Phase);
    }

    [DataTestMethod]
    [DataRow("private-missing")]
    [DataRow("private-tampered")]
    [DataRow("installed-changed")]
    [DataRow("backup-partial")]
    [DataRow("backup-wrong")]
    [DataRow("backup-sibling")]
    [DataRow("policy-changed")]
    [DataRow("v1-journal")]
    public async Task PrivateReady_requires_fresh_private_installed_policy_and_backup_evidence(string mutation)
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        await scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None);
        switch (mutation)
        {
            case "private-missing": Directory.Delete(scope.PrivatePath, recursive: true); break;
            case "private-tampered": File.AppendAllText(Path.Combine(scope.PrivatePath, "Vantrel.Security.Service.exe"), "tampered"); break;
            case "installed-changed": File.AppendAllText(Path.Combine(scope.InstalledRoot, "Vantrel.Security.Service.exe"), "tampered"); break;
            case "backup-partial": Directory.CreateDirectory(scope.BackupPath); break;
            case "backup-wrong": scope.WriteSignedV2(scope.BackupPath, 9, "other backup"); break;
            case "backup-sibling": Directory.CreateDirectory(Path.Combine(scope.ArtifactBackupsRoot, "33333333333333333333333333333333")); break;
            case "policy-changed": scope.WritePolicy(scope.Target); break;
            case "v1-journal": scope.WriteV1Journal(); break;
        }
        await RejectAsync(() => scope.Coordinator().AdvanceBackupAsync(lease, CancellationToken.None));
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady, (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    [DataTestMethod]
    [DataRow("private-missing")]
    [DataRow("backup-tampered")]
    [DataRow("installed-changed")]
    [DataRow("policy-changed")]
    [DataRow("v1-journal")]
    public async Task BackupReady_observation_rejects_missing_or_changed_required_evidence(string mutation)
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        var coordinator = scope.Coordinator();
        await coordinator.AdmitAsync(lease, CancellationToken.None);
        await coordinator.AdvancePrivateAsync(lease, CancellationToken.None);
        await coordinator.AdvanceBackupAsync(lease, CancellationToken.None);
        switch (mutation)
        {
            case "private-missing": Directory.Delete(scope.PrivatePath, recursive: true); break;
            case "backup-tampered": File.AppendAllText(Path.Combine(scope.BackupPath, "Vantrel.Security.Service.exe"), "tampered"); break;
            case "installed-changed": File.AppendAllText(Path.Combine(scope.InstalledRoot, "Vantrel.Security.Service.exe"), "tampered"); break;
            case "policy-changed": scope.WritePolicy(scope.Target); break;
            case "v1-journal": scope.WriteV1Journal(); break;
        }
        var before = File.ReadAllBytes(scope.V2JournalPath);
        await RejectAsync(() => coordinator.ObserveBackupReadyAsync(lease, CancellationToken.None));
        CollectionAssert.AreEqual(before, File.ReadAllBytes(scope.V2JournalPath));
    }

    [TestMethod]
    public async Task Exact_current_compare_rejects_stale_private_transition_without_next_phase()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        var changed = false;
        await RejectAsync(() => scope.Coordinator(checkpoint: stage =>
        {
            if (stage != "BeforePrivatePublication") return;
            changed = true;
            var current = scope.V2Journal.ReadAsync(CancellationToken.None).GetAwaiter().GetResult().Journal!;
            var next = V2UpdateTransactionStateMachine.Transition(current,
                V2UpdateTransactionPhase.PrivateReady, current.UpdatedAtUtc.AddSeconds(1));
            Assert.IsTrue(scope.V2Journal.TryPersistIfExactCurrentAsync(current, next,
                CancellationToken.None).GetAwaiter().GetResult());
        }).AdvancePrivateAsync(lease, CancellationToken.None));
        Assert.IsTrue(changed);
        Assert.AreEqual(V2UpdateTransactionPhase.PrivateReady,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
        Assert.IsFalse(Directory.Exists(scope.BackupPath));
    }

    [TestMethod]
    public async Task Exact_current_compare_rejects_stale_backup_transition_without_TargetReady()
    {
        using var scope = new Scope();
        using var lease = scope.Acquire();
        await scope.Coordinator().AdmitAsync(lease, CancellationToken.None);
        await scope.Coordinator().AdvancePrivateAsync(lease, CancellationToken.None);
        var changed = false;
        await RejectAsync(() => scope.Coordinator(checkpoint: stage =>
        {
            if (stage != "BeforeBackupPublication") return;
            changed = true;
            var current = scope.V2Journal.ReadAsync(CancellationToken.None).GetAwaiter().GetResult().Journal!;
            var next = V2UpdateTransactionStateMachine.Transition(current,
                V2UpdateTransactionPhase.BackupReady, current.UpdatedAtUtc.AddSeconds(1));
            Assert.IsTrue(scope.V2Journal.TryPersistIfExactCurrentAsync(current, next,
                CancellationToken.None).GetAwaiter().GetResult());
        }).AdvanceBackupAsync(lease, CancellationToken.None));
        Assert.IsTrue(changed);
        Assert.AreEqual(V2UpdateTransactionPhase.BackupReady,
            (await scope.V2Journal.ReadAsync(CancellationToken.None)).Journal!.Phase);
    }

    private static async Task RejectAsync(Func<Task> action)
    {
        try { await action(); }
        catch (Exception error) when (error is IOException or InvalidOperationException or ArgumentException)
        { return; }
        Assert.Fail("The coordinator accepted an unauthorized or contradictory state.");
    }

    private sealed class Scope : IDisposable
    {
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private DateTimeOffset _clock = new(2026, 10, 13, 12, 0, 0, TimeSpan.Zero);
        private int _nextId;

        internal Scope()
        {
            Directory.CreateDirectory(V1TransactionsRoot);
            Directory.CreateDirectory(V2TransactionsRoot);
            Directory.CreateDirectory(ArtifactTransactionsRoot);
            Directory.CreateDirectory(ArtifactBackupsRoot);
            Directory.CreateDirectory(Path.GetDirectoryName(PolicyPath)!);
            File.WriteAllBytes(OwnerLockPath, []);
            File.WriteAllBytes(V1LockPath, []);
            File.WriteAllBytes(V2LockPath, []);
            Predecessor = WriteSignedV2(InstalledRoot, 7, "installed");
            Target = WriteSignedV2(StagedRoot, 8, "target");
            WritePolicy(Predecessor);
        }

        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-v2-prestop-" + Guid.NewGuid().ToString("N"));
        internal string UpdatesRoot => Path.Combine(Root, "Updates");
        internal string InstalledRoot => Path.Combine(Root, "installed");
        internal string StagedRoot => Path.Combine(UpdatesRoot, "StagedV2", "candidate");
        internal string ArtifactRoot => Path.Combine(UpdatesRoot, "V2Artifacts");
        internal string ArtifactTransactionsRoot => Path.Combine(ArtifactRoot, "Transactions");
        internal string ArtifactBackupsRoot => Path.Combine(ArtifactRoot, "Backups");
        internal string V1TransactionsRoot => Path.Combine(UpdatesRoot, "Transactions");
        internal string V2TransactionsRoot => Path.Combine(UpdatesRoot, "TransactionsV2");
        internal string V1JournalPath => Path.Combine(V1TransactionsRoot, UpdateTransactionJournalStore.JournalFileName);
        internal string V2JournalPath => Path.Combine(V2TransactionsRoot, V2UpdateTransactionJournalStore.JournalFileName);
        internal string V1LockPath => Path.Combine(UpdatesRoot, UpdateTransactionJournalStore.LockFileName);
        internal string V2LockPath => Path.Combine(UpdatesRoot, V2UpdateTransactionJournalStore.LockFileName);
        internal string OwnerLockPath => Path.Combine(UpdatesRoot, OfflineUpdateOwnershipLock.OwnerLockFileName);
        internal string PolicyPath => Path.Combine(Root, "ReleasePolicy", ReleasePolicyStore.PolicyFileName);
        internal string PrivatePath => Path.Combine(ArtifactTransactionsRoot, TransactionId, "candidate");
        internal string BackupPath => Path.Combine(ArtifactBackupsRoot, BackupId);
        internal ReleaseIdentity Predecessor { get; }
        internal ReleaseIdentity Target { get; }
        internal GenerationAwareOfflineReleaseVerifier Verifier => new(
            _metadataKey.ExportSubjectPublicKeyInfo(), _manifestKey.ExportSubjectPublicKeyInfo());
        internal V2UpdateTransactionJournalStore V2Journal => new(Root, applyAcls: false);
        internal V2ReleaseArtifactStorage Storage => new(Verifier, ArtifactRoot, StagedRoot, InstalledRoot,
            enforceAcls: false);
        internal V2ReleaseArtifactStorage StorageWithFault(Action<V2ArtifactCopyCheckpoint> fault) =>
            new(Verifier, ArtifactRoot, StagedRoot, InstalledRoot, enforceAcls: false, fault);
        internal V2UpdateTransactionJournalStore V2JournalWithAfterPublicationFault() =>
            new(Root, applyAcls: false, afterPublicationForTest: _ => throw new IOException("injected journal fault"));
        internal OfflineUpdateOwnershipLease Acquire() =>
            new OfflineUpdateOwnershipLock(Root, applyAcls: false).TryAcquire(CancellationToken.None)!;

        internal V2PreStopUpdateCoordinator Coordinator(V2UpdateTransactionJournalStore? v2Journal = null,
            V2ReleaseArtifactStorage? artifacts = null, Action<string>? checkpoint = null) =>
            new(UpdatesRoot, InstalledRoot, StagedRoot, Verifier,
                new ReleasePolicyStore(Root, applyAcls: false),
                new UpdateTransactionJournalStore(Root, applyAcls: false),
                v2Journal ?? V2Journal, artifacts ?? Storage,
                clock: () => _clock = _clock.AddSeconds(1),
                newId: () => Interlocked.Increment(ref _nextId) == 1 ? TransactionId : BackupId,
                checkpoint: checkpoint);

        internal V2UpdateTransactionJournal TestJournal() => new(TransactionId, Predecessor, Target,
            V2UpdateTransactionPhase.Admitted, BackupId, _clock);

        internal void WritePolicy(ReleaseIdentity identity) => File.WriteAllBytes(PolicyPath,
            GenerationAwareReleasePolicyCodec.Serialize(new GenerationAwareReleasePolicyRecord(identity)));

        internal void WriteV1Policy() => File.WriteAllBytes(PolicyPath,
            ReleasePolicyCodec.Serialize(new ReleasePolicyRecord(Predecessor.ReleaseSequence,
                Predecessor.ManifestSha256)));

        internal void WriteV1Journal() => File.WriteAllBytes(V1JournalPath,
            UpdateTransactionJournalCodec.Serialize(new UpdateTransactionJournal(TransactionId,
                Predecessor.ReleaseSequence, Predecessor.ManifestSha256,
                Target.ReleaseSequence, Target.ManifestSha256,
                UpdateTransactionPhase.Prepared, BackupId, _clock)));

        internal void CopyInstalledToStaged()
        {
            Directory.Delete(StagedRoot, recursive: true);
            Directory.CreateDirectory(StagedRoot);
            foreach (var source in Directory.GetFiles(InstalledRoot, "*", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(InstalledRoot, source);
                var destination = Path.Combine(StagedRoot, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(source, destination);
            }
        }

        internal void WriteSignedV1(string root)
        {
            Directory.Delete(root, recursive: true);
            Directory.CreateDirectory(root);
            var components = new Dictionary<TrustedManifestComponent, string>();
            foreach (var (component, name) in FixedServiceReleaseFiles.Components)
            {
                var bytes = Encoding.UTF8.GetBytes("v1:" + name);
                File.WriteAllBytes(Path.Combine(root, name), bytes);
                components.Add(component, Convert.ToHexString(SHA256.HashData(bytes)));
            }
            var manifest = TrustedManifestCodec.CreateFile("0.1.0-beta.2", components, _manifestKey);
            File.WriteAllBytes(Path.Combine(root, "Vantrel.Security.TrustedManifest"), manifest);
            File.WriteAllBytes(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"),
                ReleaseMetadataCodec.CreateFile(7, Convert.ToHexString(SHA256.HashData(manifest)),
                    "0.1.0-beta.2", new DateTimeOffset(2026, 10, 13, 12, 0, 0, TimeSpan.Zero),
                    _metadataKey));
        }

        internal ReleaseIdentity WriteSignedV2(string root, ulong sequence, string content)
        {
            Directory.CreateDirectory(root);
            var apphost = Path.Combine(root, "Vantrel.Security.Service.exe");
            var dependency = Path.Combine(root, "deps", "Microsoft.Extensions.Hosting.dll");
            Directory.CreateDirectory(Path.GetDirectoryName(dependency)!);
            File.WriteAllText(apphost, content + " apphost");
            File.WriteAllText(dependency, content + " dependency");
            var inventory = new[]
            {
                new TrustedManifestV2File("Vantrel.Security.Service.exe", Hash(apphost)),
                new TrustedManifestV2File("deps/Microsoft.Extensions.Hosting.dll", Hash(dependency))
            };
            var manifest = TrustedManifestV2Codec.CreateFile("0.1.0-beta.2", sequence, inventory,
                _manifestKey);
            File.WriteAllBytes(Path.Combine(root, "Vantrel.Security.TrustedManifest"), manifest);
            var manifestHash = Convert.ToHexString(SHA256.HashData(manifest));
            File.WriteAllBytes(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"),
                ReleaseMetadataCodec.CreateFile(sequence, manifestHash, "0.1.0-beta.2",
                    new DateTimeOffset(2026, 10, 13, 12, 0, 0, TimeSpan.Zero), _metadataKey));
            return new(ReleaseGeneration.V2, sequence, manifestHash);
        }

        private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

        public void Dispose()
        {
            _manifestKey.Dispose();
            _metadataKey.Dispose();
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
