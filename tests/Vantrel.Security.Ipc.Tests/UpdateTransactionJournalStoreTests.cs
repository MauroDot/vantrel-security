using Vantrel.Security.Core;
using Vantrel.Security.Service;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class UpdateTransactionJournalStoreTests
{
    private const string Prior = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string Target = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    [DataTestMethod]
    [DataRow(0)] [DataRow(1)] [DataRow(2)]
    public async Task Journal_absence_is_distinct_from_missing_infrastructure_without_creation(int existingLevels)
    {
        await using var scope = new Scope();
        var updates = Path.Combine(scope.Root, "Updates");
        var transactions = Path.Combine(updates, "Transactions");
        Directory.CreateDirectory(scope.Root);
        if (existingLevels >= 1) Directory.CreateDirectory(updates);
        if (existingLevels >= 2) Directory.CreateDirectory(transactions);
        var before = Directory.GetFileSystemEntries(scope.Root, "*", SearchOption.AllDirectories);
        var result = await new UpdateTransactionJournalStore(scope.Root, true).ReadAsync(CancellationToken.None);
        Assert.IsNull(result.Journal);
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Unavailable, result.Failure);
        Assert.AreEqual(existingLevels == 2 ? JournalReadState.Absent : JournalReadState.MissingInfrastructure, result.State);
        CollectionAssert.AreEquivalent(before, Directory.GetFileSystemEntries(scope.Root, "*", SearchOption.AllDirectories));
    }

    [TestMethod]
    public async Task Valid_journal_read_and_status_sampling_preserve_descriptors_and_files()
    {
        await using var scope = new Scope();
        await new UpdateTransactionJournalStore(scope.Root, false).PersistAsync(Journal(UpdateTransactionPhase.Prepared), CancellationToken.None);
        var updates = Path.Combine(scope.Root, "Updates");
        var transactions = Path.Combine(updates, "Transactions");
        var path = Path.Combine(transactions, UpdateTransactionJournalStore.JournalFileName);
        var temporary = Path.Combine(transactions, ".transaction-leftover.tmp");
        await File.WriteAllTextAsync(temporary, "preserve");
        var directories = new[] { scope.Root, updates, transactions };
        var descriptors = directories.Select(p => new DirectoryInfo(p).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access)).ToArray();
        var fileDescriptor = new FileInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        var bytes = await File.ReadAllBytesAsync(path);
        var entries = Directory.GetFileSystemEntries(scope.Root, "*", SearchOption.AllDirectories);
        var reader = new UpdateTransactionJournalStore(scope.Root, true);
        Assert.AreEqual(Journal(UpdateTransactionPhase.Prepared), (await reader.ReadAsync(CancellationToken.None)).Journal);
        var snapshot = new UpdateTransactionStore();
        using var worker = new UpdateTransactionStatusWorker(snapshot, reader, new ReleaseProvenanceStore(), NullLogger<UpdateTransactionStatusWorker>.Instance);
        var sample = typeof(UpdateTransactionStatusWorker).GetMethod("SampleAsync", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        await (Task)sample.Invoke(worker, new object[] { CancellationToken.None })!;
        Assert.AreEqual(UpdateTransactionPhase.Prepared, snapshot.Snapshot()!.Phase);
        CollectionAssert.AreEqual(descriptors, directories.Select(p => new DirectoryInfo(p).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access)).ToArray());
        Assert.AreEqual(fileDescriptor, new FileInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access));
        CollectionAssert.AreEqual(bytes, await File.ReadAllBytesAsync(path));
        CollectionAssert.AreEquivalent(entries, Directory.GetFileSystemEntries(scope.Root, "*", SearchOption.AllDirectories));
        Assert.AreEqual("preserve", await File.ReadAllTextAsync(temporary));
    }

    [TestMethod]
    public async Task Access_denied_existing_journal_is_not_absence()
    {
        await using var scope = new Scope();
        await new UpdateTransactionJournalStore(scope.Root, false).PersistAsync(Journal(UpdateTransactionPhase.Prepared), CancellationToken.None);
        var file = new FileInfo(Path.Combine(scope.Root, "Updates", "Transactions", UpdateTransactionJournalStore.JournalFileName));
        var original = file.GetAccessControl();
        var denied = file.GetAccessControl();
        using var identity = WindowsIdentity.GetCurrent();
        denied.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.ReadData, AccessControlType.Deny));
        try
        {
            file.SetAccessControl(denied);
            await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(() => new UpdateTransactionJournalStore(scope.Root, true).ReadAsync(CancellationToken.None));
        }
        finally { file.SetAccessControl(original); }
    }

    [TestMethod]
    public async Task Access_denied_journal_cannot_reach_admission_or_recovery()
    {
        await using var scope = new Scope();
        var store = new UpdateTransactionJournalStore(scope.Root, false);
        await store.PersistAsync(Journal(UpdateTransactionPhase.Prepared), CancellationToken.None);
        var file = new FileInfo(Path.Combine(scope.Root, "Updates", "Transactions", UpdateTransactionJournalStore.JournalFileName));
        var original = file.GetAccessControl();
        var denied = file.GetAccessControl();
        using var identity = WindowsIdentity.GetCurrent();
        denied.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.ReadData, AccessControlType.Deny));
        var mutationCalls = 0;
        try
        {
            file.SetAccessControl(denied);
            await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(() => OfflineUpdateAdministrator.WithValidatedJournalAsync(
                store, _ =>
                {
                    mutationCalls++;
                    return Task.FromResult(UpdateTransactionPhase.Completed);
                }, CancellationToken.None));
            Assert.AreEqual(0, mutationCalls);
        }
        finally { file.SetAccessControl(original); }
    }

    [TestMethod]
    public async Task Journal_directory_substitution_is_not_absence()
    {
        await using var scope = new Scope();
        Directory.CreateDirectory(Path.Combine(scope.Root, "Updates", "Transactions", UpdateTransactionJournalStore.JournalFileName));
        await Assert.ThrowsExceptionAsync<IOException>(() => new UpdateTransactionJournalStore(scope.Root, true).ReadAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task Journal_reparse_ancestor_is_rejected_without_creation()
    {
        await using var scope = new Scope();
        Directory.CreateDirectory(scope.Root);
        var target = Path.Combine(scope.Root, "target"); Directory.CreateDirectory(target);
        var link = Path.Combine(scope.Root, "Updates");
        try
        {
            try { Directory.CreateSymbolicLink(link, target); }
            catch (UnauthorizedAccessException) { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
            catch (IOException ex) when ((uint)ex.HResult == 0x80070522) { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
            await Assert.ThrowsExceptionAsync<IOException>(() => new UpdateTransactionJournalStore(scope.Root, true).ReadAsync(CancellationToken.None));
            Assert.AreEqual(0, Directory.GetFileSystemEntries(target).Length);
        }
        finally { if (Directory.Exists(link)) Directory.Delete(link); }
    }

    [TestMethod]
    public async Task Journal_persists_canonically_and_rejects_illegal_phase_skip()
    {
        await using var scope = new Scope(); var store = new UpdateTransactionJournalStore(scope.Root, false);
        var prepared = Journal(UpdateTransactionPhase.Prepared);
        await store.PersistAsync(prepared, CancellationToken.None);
        var (read, failure) = await store.ReadAsync(CancellationToken.None);
        Assert.AreEqual(UpdateTransactionJournalParseFailure.None, failure); Assert.AreEqual(prepared, read);
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => store.PersistAsync(Journal(UpdateTransactionPhase.Replaced), CancellationToken.None));
        var verified = UpdateTransactionStateMachine.Transition(prepared, UpdateTransactionPhase.Verified, prepared.UpdatedAtUtc);
        await store.PersistAsync(verified, CancellationToken.None);
        Assert.AreEqual(verified, (await store.ReadAsync(CancellationToken.None)).Journal);
    }

    [TestMethod]
    public async Task Malformed_persisted_journal_fails_closed()
    {
        await using var scope = new Scope(); var directory = Path.Combine(scope.Root, "Updates", "Transactions"); Directory.CreateDirectory(directory);
        await File.WriteAllTextAsync(Path.Combine(directory, UpdateTransactionJournalStore.JournalFileName), "invalid");
        var result = await new UpdateTransactionJournalStore(scope.Root, false).ReadAsync(CancellationToken.None);
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Malformed, result.Failure); Assert.IsNull(result.Journal);
        Assert.AreEqual(JournalReadState.Invalid, result.State);
    }

    [TestMethod]
    public async Task Valid_provisioned_absence_can_reach_new_transaction_admission()
    {
        await using var scope = new Scope();
        Directory.CreateDirectory(Path.Combine(scope.Root, "Updates", "Transactions"));
        var store = new UpdateTransactionJournalStore(scope.Root, false);
        var calls = 0;
        var phase = await OfflineUpdateAdministrator.WithValidatedJournalAsync(store, journal =>
        {
            Assert.IsNull(journal);
            calls++;
            return Task.FromResult(UpdateTransactionPhase.Prepared);
        }, CancellationToken.None);
        Assert.AreEqual(UpdateTransactionPhase.Prepared, phase);
        Assert.AreEqual(1, calls);
    }

    [TestMethod]
    public async Task Valid_present_journal_reaches_recovery_with_exact_identity()
    {
        await using var scope = new Scope();
        var expected = Journal(UpdateTransactionPhase.ServiceStopped);
        var store = new UpdateTransactionJournalStore(scope.Root, false);
        var prepared = expected with { Phase = UpdateTransactionPhase.Prepared };
        var verified = expected with { Phase = UpdateTransactionPhase.Verified };
        await store.PersistAsync(prepared, CancellationToken.None);
        await store.PersistAsync(verified, CancellationToken.None);
        await store.PersistAsync(expected, CancellationToken.None);
        var calls = 0;
        await OfflineUpdateAdministrator.WithValidatedJournalAsync(store, journal =>
        {
            Assert.AreEqual(expected, journal);
            calls++;
            return Task.FromResult(UpdateTransactionPhase.RolledBack);
        }, CancellationToken.None);
        Assert.AreEqual(1, calls);
    }

    [DataTestMethod]
    [DataRow("updates-missing")]
    [DataRow("transactions-missing")]
    [DataRow("journal-directory")]
    [DataRow("journal-malformed")]
    [DataRow("journal-empty")]
    [DataRow("conflicting-entry")]
    public async Task Untrusted_journal_state_cannot_reach_admission_or_recovery(string scenario)
    {
        await using var scope = new Scope();
        Directory.CreateDirectory(scope.Root);
        var updates = Path.Combine(scope.Root, "Updates");
        var transactions = Path.Combine(updates, "Transactions");
        if (scenario != "updates-missing") Directory.CreateDirectory(updates);
        if (scenario is not ("updates-missing" or "transactions-missing")) Directory.CreateDirectory(transactions);
        var journalPath = Path.Combine(transactions, UpdateTransactionJournalStore.JournalFileName);
        if (scenario == "journal-directory") Directory.CreateDirectory(journalPath);
        if (scenario == "journal-malformed") await File.WriteAllTextAsync(journalPath, "invalid");
        if (scenario == "journal-empty") await File.WriteAllBytesAsync(journalPath, Array.Empty<byte>());
        if (scenario == "conflicting-entry") await File.WriteAllTextAsync(Path.Combine(transactions, ".transaction-conflict.tmp"), "conflict");
        var mutationCalls = 0;
        await Assert.ThrowsExceptionAsync<IOException>(() => OfflineUpdateAdministrator.WithValidatedJournalAsync(
            new UpdateTransactionJournalStore(scope.Root, false), _ =>
            {
                mutationCalls++;
                return Task.FromResult(UpdateTransactionPhase.Completed);
            }, CancellationToken.None));
        Assert.AreEqual(0, mutationCalls, "No engine, candidate, backup, service, replacement, restoration, or policy work may become reachable.");
    }

    [TestMethod]
    public async Task Missing_infrastructure_status_is_recovery_required_and_read_only()
    {
        await using var scope = new Scope();
        Directory.CreateDirectory(scope.Root);
        var before = Directory.GetFileSystemEntries(scope.Root, "*", SearchOption.AllDirectories);
        var snapshot = new UpdateTransactionStore();
        using var worker = new UpdateTransactionStatusWorker(snapshot, new UpdateTransactionJournalStore(scope.Root, true),
            new ReleaseProvenanceStore(), NullLogger<UpdateTransactionStatusWorker>.Instance);
        await SampleAsync(worker);
        Assert.AreEqual(UpdateTransactionPhase.Failed, snapshot.Snapshot()!.Phase);
        Assert.AreEqual(UpdateTransactionResult.RecoveryRequired, snapshot.Snapshot()!.LastResult);
        CollectionAssert.AreEquivalent(before, Directory.GetFileSystemEntries(scope.Root, "*", SearchOption.AllDirectories));
    }

    [TestMethod]
    public void Policy_commit_requires_present_postverified_journal()
    {
        Assert.IsFalse(UpdateTransactionPolicyCommitWorker.IsEligibleJournal(
            new(null, UpdateTransactionJournalParseFailure.Unavailable, JournalReadState.MissingInfrastructure)));
        Assert.IsFalse(UpdateTransactionPolicyCommitWorker.IsEligibleJournal(
            new(null, UpdateTransactionJournalParseFailure.Unavailable, JournalReadState.Absent)));
        Assert.IsFalse(UpdateTransactionPolicyCommitWorker.IsEligibleJournal(
            new(null, UpdateTransactionJournalParseFailure.Malformed, JournalReadState.Invalid)));
        Assert.IsFalse(UpdateTransactionPolicyCommitWorker.IsEligibleJournal(
            new(Journal(UpdateTransactionPhase.Prepared), UpdateTransactionJournalParseFailure.None, JournalReadState.Present)));
        Assert.IsTrue(UpdateTransactionPolicyCommitWorker.IsEligibleJournal(
            new(Journal(UpdateTransactionPhase.PostVerified), UpdateTransactionJournalParseFailure.None, JournalReadState.Present)));
    }

    private static async Task SampleAsync(UpdateTransactionStatusWorker worker)
    {
        var sample = typeof(UpdateTransactionStatusWorker).GetMethod("SampleAsync", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        await (Task)sample.Invoke(worker, new object[] { CancellationToken.None })!;
    }

    private static UpdateTransactionJournal Journal(UpdateTransactionPhase phase) => new("0123456789abcdef0123456789abcdef", 1, Prior, 2, Target, phase, "fedcba9876543210fedcba9876543210", new DateTimeOffset(2026, 9, 21, 12, 0, 0, TimeSpan.Zero));
    private sealed class Scope : IAsyncDisposable { internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-journal-" + Guid.NewGuid().ToString("N")); public ValueTask DisposeAsync() { if (Directory.Exists(Root)) Directory.Delete(Root, true); return ValueTask.CompletedTask; } }
}
