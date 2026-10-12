using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class V2UpdateTransactionJournalStoreTests
{
    private const string PriorHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string TargetHash = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private static readonly DateTimeOffset Time = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

    [DataTestMethod]
    [DataRow(0, false)]
    [DataRow(1, false)]
    [DataRow(2, false)]
    [DataRow(3, true)]
    public async Task Read_distinguishes_provisioned_absence_without_creating_infrastructure(
        int provisionedLevel, bool expectedAbsent)
    {
        using var scope = new Scope();
        if (provisionedLevel >= 1) Directory.CreateDirectory(scope.Updates);
        if (provisionedLevel >= 2) Directory.CreateDirectory(scope.Transactions);
        if (provisionedLevel >= 3) File.WriteAllBytes(scope.LockPath, []);
        var before = Directory.GetFileSystemEntries(scope.Root, "*", SearchOption.AllDirectories);

        var result = await scope.Store.ReadAsync(CancellationToken.None);

        Assert.AreEqual(expectedAbsent ? V2JournalReadState.Absent : V2JournalReadState.MissingInfrastructure, result.State);
        Assert.IsNull(result.Journal);
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Unavailable, result.Failure);
        CollectionAssert.AreEquivalent(before, Directory.GetFileSystemEntries(scope.Root, "*", SearchOption.AllDirectories));
    }

    [TestMethod]
    public async Task First_create_replacement_and_reload_are_canonical_and_leave_v1_untouched()
    {
        using var scope = new Scope();
        scope.Provision();
        var v1Directory = Path.Combine(scope.Updates, "Transactions");
        Directory.CreateDirectory(v1Directory);
        var v1Path = Path.Combine(v1Directory, "current-update-v1");
        var v1Bytes = Encoding.UTF8.GetBytes("existing v1 journal sentinel");
        File.WriteAllBytes(v1Path, v1Bytes);
        var admitted = Journal();

        await scope.Store.PersistAsync(admitted, CancellationToken.None);
        Assert.AreEqual(admitted, (await new V2UpdateTransactionJournalStore(scope.Root, false)
            .ReadAsync(CancellationToken.None)).Journal);
        CollectionAssert.AreEqual(V2UpdateTransactionJournalCodec.Serialize(admitted), File.ReadAllBytes(scope.JournalPath));

        var privateReady = V2UpdateTransactionStateMachine.Transition(admitted,
            V2UpdateTransactionPhase.PrivateReady, Time.AddSeconds(1));
        Assert.IsTrue(await scope.Store.TryPersistIfExactCurrentAsync(admitted, privateReady, CancellationToken.None));
        var reloaded = await new V2UpdateTransactionJournalStore(scope.Root, false).ReadAsync(CancellationToken.None);
        Assert.AreEqual(V2JournalReadState.Present, reloaded.State);
        Assert.AreEqual(UpdateTransactionJournalParseFailure.None, reloaded.Failure);
        Assert.AreEqual(privateReady, reloaded.Journal);
        CollectionAssert.AreEqual(V2UpdateTransactionJournalCodec.Serialize(privateReady), File.ReadAllBytes(scope.JournalPath));
        CollectionAssert.AreEqual(v1Bytes, File.ReadAllBytes(v1Path));
        CollectionAssert.AreEquivalent(new[] { scope.JournalPath }, Directory.GetFileSystemEntries(scope.Transactions));
    }

    [TestMethod]
    public async Task Identity_phase_and_timestamp_mutations_fail_without_changing_bytes()
    {
        using var scope = new Scope();
        scope.Provision();
        var admitted = Journal();
        await scope.Store.PersistAsync(admitted, CancellationToken.None);
        var firstBytes = File.ReadAllBytes(scope.JournalPath);

        var illegal = new[]
        {
            admitted with { TransactionId = "11111111111111111111111111111111" },
            admitted with { BackupId = "22222222222222222222222222222222" },
            admitted with { Predecessor = new ReleaseIdentity(ReleaseGeneration.V2, 2, PriorHash) },
            admitted with { Target = new ReleaseIdentity(ReleaseGeneration.V2, 4, TargetHash) },
            admitted with { Phase = V2UpdateTransactionPhase.BackupReady },
            admitted with { UpdatedAtUtc = Time.AddSeconds(1) }
        };
        foreach (var mutation in illegal)
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
                scope.Store.TryPersistIfExactCurrentAsync(admitted, mutation, CancellationToken.None));
        CollectionAssert.AreEqual(firstBytes, File.ReadAllBytes(scope.JournalPath));

        var next = V2UpdateTransactionStateMachine.Transition(admitted, V2UpdateTransactionPhase.PrivateReady,
            Time.AddSeconds(1));
        Assert.IsTrue(await scope.Store.TryPersistIfExactCurrentAsync(admitted, next, CancellationToken.None));
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
            scope.Store.TryPersistIfExactCurrentAsync(next,
                next with { Phase = V2UpdateTransactionPhase.BackupReady, UpdatedAtUtc = Time }, CancellationToken.None));
        Assert.AreEqual(next, (await scope.Store.ReadAsync(CancellationToken.None)).Journal);
    }

    [TestMethod]
    public async Task Generic_persist_creates_only_Admitted_and_refuses_even_legal_replacement()
    {
        using var scope = new Scope();
        scope.Provision();
        var admitted = Journal();
        var privateReady = V2UpdateTransactionStateMachine.Transition(admitted,
            V2UpdateTransactionPhase.PrivateReady, Time.AddSeconds(1));

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
            scope.Store.PersistAsync(privateReady, CancellationToken.None));
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
            scope.Store.PersistAsync(admitted with { Phase = V2UpdateTransactionPhase.PolicyCommitted },
                CancellationToken.None));
        Assert.IsFalse(File.Exists(scope.JournalPath));
        await scope.Store.PersistAsync(admitted, CancellationToken.None);
        var originalBytes = File.ReadAllBytes(scope.JournalPath);
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
            scope.Store.PersistAsync(admitted, CancellationToken.None));
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
            scope.Store.PersistAsync(privateReady, CancellationToken.None));
        CollectionAssert.AreEqual(originalBytes, File.ReadAllBytes(scope.JournalPath));
        CollectionAssert.AreEquivalent(new[] { scope.JournalPath }, Directory.GetFileSystemEntries(scope.Transactions));
    }

    [TestMethod]
    public async Task Stale_expected_cannot_publish_crafted_later_phase_after_another_transition()
    {
        using var scope = new Scope();
        scope.Provision();
        var actor1 = scope.Store;
        var actor2 = new V2UpdateTransactionJournalStore(scope.Root, applyAcls: false);
        var admitted = Journal();
        await actor1.PersistAsync(admitted, CancellationToken.None);
        var privateReady = V2UpdateTransactionStateMachine.Transition(admitted,
            V2UpdateTransactionPhase.PrivateReady, Time.AddSeconds(1));
        var backupReady = V2UpdateTransactionStateMachine.Transition(privateReady,
            V2UpdateTransactionPhase.BackupReady, Time.AddSeconds(2));

        Assert.IsTrue(await actor1.TryPersistIfExactCurrentAsync(admitted, privateReady, CancellationToken.None));
        var currentBytes = File.ReadAllBytes(scope.JournalPath);
        Assert.IsFalse(await actor2.TryPersistIfExactCurrentAsync(admitted, backupReady, CancellationToken.None));
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
            actor2.PersistAsync(backupReady, CancellationToken.None));
        CollectionAssert.AreEqual(currentBytes, File.ReadAllBytes(scope.JournalPath));
        Assert.IsTrue(await actor2.TryPersistIfExactCurrentAsync(privateReady, backupReady, CancellationToken.None));
        Assert.AreEqual(backupReady, (await actor1.ReadAsync(CancellationToken.None)).Journal);
    }

    [TestMethod]
    public async Task Exact_current_compare_serializes_admission_and_concurrent_transition()
    {
        using var scope = new Scope();
        scope.Provision();
        var store1 = scope.Store;
        var store2 = new V2UpdateTransactionJournalStore(scope.Root, false);
        var admitted = Journal();

        Assert.IsTrue(await store1.TryPersistIfExactCurrentAsync(null, admitted, CancellationToken.None));
        Assert.IsFalse(await store2.TryPersistIfExactCurrentAsync(null, admitted, CancellationToken.None));
        Assert.IsTrue(await store2.IsExactCurrentAsync(admitted, CancellationToken.None));
        var next = V2UpdateTransactionStateMachine.Transition(admitted,
            V2UpdateTransactionPhase.PrivateReady, Time.AddSeconds(1));
        var results = await Task.WhenAll(
            store1.TryPersistIfExactCurrentAsync(admitted, next, CancellationToken.None),
            store2.TryPersistIfExactCurrentAsync(admitted, next, CancellationToken.None));
        Assert.AreEqual(1, results.Count(static result => result));
        Assert.IsFalse(await store1.IsExactCurrentAsync(admitted, CancellationToken.None));
        Assert.IsTrue(await store2.IsExactCurrentAsync(next, CancellationToken.None));
    }

    [TestMethod]
    public async Task Crafted_policy_commit_transition_is_rejected_without_durable_policy_proof()
    {
        using var scope = new Scope();
        scope.Provision();
        var pending = Journal() with { Phase = V2UpdateTransactionPhase.PolicyCommitPending };
        var pendingBytes = V2UpdateTransactionJournalCodec.Serialize(pending);
        File.WriteAllBytes(scope.JournalPath, pendingBytes);
        var committed = pending with { Phase = V2UpdateTransactionPhase.PolicyCommitted,
            UpdatedAtUtc = Time.AddSeconds(1) };

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
            scope.Store.PersistAsync(committed, CancellationToken.None));
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
            scope.Store.TryPersistIfExactCurrentAsync(pending, committed, CancellationToken.None));
        CollectionAssert.AreEqual(pendingBytes, File.ReadAllBytes(scope.JournalPath));
    }

    [TestMethod]
    public async Task Existing_lock_handle_blocks_another_store_instance()
    {
        using var scope = new Scope();
        scope.Provision();
        using var lockHandle = new FileStream(scope.LockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var pending = new V2UpdateTransactionJournalStore(scope.Root, false).ReadAsync(CancellationToken.None);
        await Task.Delay(150);
        Assert.IsFalse(pending.IsCompleted);
        lockHandle.Dispose();
        Assert.AreEqual(V2JournalReadState.Absent, (await pending.WaitAsync(TimeSpan.FromSeconds(5))).State);
    }

    [DataTestMethod]
    [DataRow("invalid", UpdateTransactionJournalParseFailure.Malformed)]
    [DataRow("schema=vantrel-update-transaction-v99\n", UpdateTransactionJournalParseFailure.UnsupportedSchema)]
    [DataRow("", UpdateTransactionJournalParseFailure.Unavailable)]
    public async Task Malformed_or_unsupported_persisted_journal_fails_closed(
        string contents, UpdateTransactionJournalParseFailure expectedFailure)
    {
        using var scope = new Scope();
        scope.Provision();
        File.WriteAllBytes(scope.JournalPath, Encoding.UTF8.GetBytes(contents));
        var before = File.ReadAllBytes(scope.JournalPath);

        var read = await scope.Store.ReadAsync(CancellationToken.None);
        Assert.AreEqual(V2JournalReadState.Invalid, read.State);
        Assert.AreEqual(expectedFailure, read.Failure);
        Assert.IsNull(read.Journal);
        await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.PersistAsync(Journal(), CancellationToken.None));
        CollectionAssert.AreEqual(before, File.ReadAllBytes(scope.JournalPath));
    }

    [TestMethod]
    public async Task Oversized_journal_is_rejected_by_bounded_read()
    {
        using var scope = new Scope();
        scope.Provision();
        using (var file = new FileStream(scope.JournalPath, FileMode.CreateNew, FileAccess.Write))
            file.SetLength(32L * 1024 * 1024);
        var read = await scope.Store.ReadAsync(CancellationToken.None);
        Assert.AreEqual(V2JournalReadState.Invalid, read.State);
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Malformed, read.Failure);
    }

    [DataTestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task Unexpected_residue_rejects_absence_and_existing_journal(bool journalPresent)
    {
        using var scope = new Scope();
        scope.Provision();
        if (journalPresent) await scope.Store.PersistAsync(Journal(), CancellationToken.None);
        var residue = Path.Combine(scope.Transactions, ".transaction-v2-leftover.tmp");
        File.WriteAllText(residue, "residue");
        var expectedBytes = journalPresent ? File.ReadAllBytes(scope.JournalPath) : null;

        await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.ReadAsync(CancellationToken.None));
        await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.PersistAsync(Journal(), CancellationToken.None));
        Assert.AreEqual("residue", File.ReadAllText(residue));
        if (expectedBytes is not null) CollectionAssert.AreEqual(expectedBytes, File.ReadAllBytes(scope.JournalPath));
        else Assert.IsFalse(File.Exists(scope.JournalPath));
    }

    [TestMethod]
    public async Task Case_variant_journal_name_is_rejected()
    {
        using var scope = new Scope();
        scope.Provision();
        await scope.Store.PersistAsync(Journal(), CancellationToken.None);
        var intermediate = Path.Combine(scope.Transactions, "case-rename.tmp");
        var variant = Path.Combine(scope.Transactions, "CURRENT-UPDATE-V2");
        File.Move(scope.JournalPath, intermediate);
        File.Move(intermediate, variant);
        Assert.IsTrue(Directory.GetFileSystemEntries(scope.Transactions)
            .Any(path => string.Equals(Path.GetFileName(path), "CURRENT-UPDATE-V2", StringComparison.Ordinal)));

        await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.ReadAsync(CancellationToken.None));
        await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.PersistAsync(Journal(), CancellationToken.None));
    }

    [TestMethod]
    public async Task Transaction_directory_reparse_point_is_rejected()
    {
        using var scope = new Scope();
        Directory.CreateDirectory(scope.Updates);
        File.WriteAllBytes(scope.LockPath, []);
        var target = Path.Combine(scope.Root, "link-target");
        Directory.CreateDirectory(target);
        try
        {
            try { Directory.CreateSymbolicLink(scope.Transactions, target); }
            catch (UnauthorizedAccessException) { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
            catch (IOException error) when (unchecked((uint)error.HResult) == 0x80070522)
            { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
            await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.ReadAsync(CancellationToken.None));
            Assert.AreEqual(0, Directory.GetFileSystemEntries(target).Length);
        }
        finally { if (Directory.Exists(scope.Transactions)) Directory.Delete(scope.Transactions); }
    }

    [TestMethod]
    public async Task Journal_leaf_reparse_point_is_rejected()
    {
        using var scope = new Scope();
        scope.Provision();
        var targetFile = Path.Combine(scope.Root, "journal-target");
        File.WriteAllBytes(targetFile, V2UpdateTransactionJournalCodec.Serialize(Journal()));
        try
        {
            try { File.CreateSymbolicLink(scope.JournalPath, targetFile); }
            catch (UnauthorizedAccessException) { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
            catch (IOException error) when (unchecked((uint)error.HResult) == 0x80070522)
            { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
            await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.ReadAsync(CancellationToken.None));
        }
        finally { if (File.Exists(scope.JournalPath)) File.Delete(scope.JournalPath); }
    }

    [TestMethod]
    public async Task Fixed_lock_symlink_is_rejected_without_touching_its_target()
    {
        using var scope = new Scope();
        scope.Provision();
        File.Delete(scope.LockPath);
        var target = Path.Combine(scope.Root, "lock-target");
        var marker = Encoding.UTF8.GetBytes("lock target unchanged");
        File.WriteAllBytes(target, marker);
        try
        {
            try { File.CreateSymbolicLink(scope.LockPath, target); }
            catch (UnauthorizedAccessException) { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
            catch (IOException error) when (unchecked((uint)error.HResult) == 0x80070522)
            { Assert.Inconclusive("Symbolic-link privilege unavailable."); }
            await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.ReadAsync(CancellationToken.None));
            await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.PersistAsync(Journal(), CancellationToken.None));
            CollectionAssert.AreEqual(marker, File.ReadAllBytes(target));
        }
        finally { if (File.Exists(scope.LockPath)) File.Delete(scope.LockPath); }
    }

    [TestMethod]
    public async Task Competing_first_destination_is_never_overwritten_or_removed()
    {
        using var scope = new Scope();
        scope.Provision();
        var competing = Encoding.UTF8.GetBytes("competing destination");
        var store = new V2UpdateTransactionJournalStore(scope.Root, applyAcls: false,
            beforePublicationForTest: _ =>
            {
                File.WriteAllBytes(scope.JournalPath, competing);
                return Task.CompletedTask;
            });
        await Assert.ThrowsExceptionAsync<V2JournalPostPublicationException>(
            () => store.PersistAsync(Journal(), CancellationToken.None));
        CollectionAssert.AreEqual(competing, File.ReadAllBytes(scope.JournalPath));
        Assert.AreEqual(2, Directory.GetFileSystemEntries(scope.Transactions).Length);
        await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.ReadAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task Prepublication_failure_cleans_only_its_own_temporary_file()
    {
        using var scope = new Scope();
        scope.Provision();
        var store = new V2UpdateTransactionJournalStore(scope.Root, applyAcls: false,
            beforePublicationForTest: _ => throw new InvalidOperationException("Injected prepublication failure."));

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(() =>
            store.PersistAsync(Journal(), CancellationToken.None));
        Assert.IsFalse(File.Exists(scope.JournalPath));
        Assert.AreEqual(0, Directory.GetFileSystemEntries(scope.Transactions).Length);
    }

    [TestMethod]
    public async Task Failed_replacement_attempt_is_ambiguous_and_preserves_blocking_residue()
    {
        using var scope = new Scope();
        scope.Provision();
        var admitted = Journal();
        await scope.Store.PersistAsync(admitted, CancellationToken.None);
        var originalBytes = File.ReadAllBytes(scope.JournalPath);
        var next = V2UpdateTransactionStateMachine.Transition(admitted,
            V2UpdateTransactionPhase.PrivateReady, Time.AddSeconds(1));
        var attempts = 0;
        var store = new V2UpdateTransactionJournalStore(scope.Root, applyAcls: false,
            publicationAttemptForTest: (temporary, destination, replacing) =>
            {
                attempts++;
                Assert.IsTrue(replacing);
                Assert.IsTrue(File.Exists(temporary));
                Assert.AreEqual(scope.JournalPath, destination);
                throw new IOException("Simulated replacement failure with temporary file retained.");
            });

        var failure = await Assert.ThrowsExceptionAsync<V2JournalPostPublicationException>(() =>
            store.TryPersistIfExactCurrentAsync(admitted, next, CancellationToken.None));
        Assert.AreEqual(1, attempts);
        Assert.IsInstanceOfType<IOException>(failure.InnerException);
        CollectionAssert.AreEqual(originalBytes, File.ReadAllBytes(scope.JournalPath));
        var entries = Directory.GetFileSystemEntries(scope.Transactions);
        Assert.AreEqual(2, entries.Length);
        Assert.IsTrue(entries.Any(path => Path.GetFileName(path).StartsWith(".transaction-v2-", StringComparison.Ordinal)));
        await Assert.ThrowsExceptionAsync<IOException>(() => scope.Store.ReadAsync(CancellationToken.None));
        await Assert.ThrowsExceptionAsync<IOException>(() =>
            scope.Store.TryPersistIfExactCurrentAsync(admitted, next, CancellationToken.None));
    }

    [TestMethod]
    public async Task Production_acl_validation_rejects_unprovisioned_disposable_descriptors_without_repair()
    {
        if (!OperatingSystem.IsWindows()) Assert.Inconclusive("Windows ACL test.");
        using var scope = new Scope();
        scope.Provision();
        var before = Directory.GetFileSystemEntries(scope.Root, "*", SearchOption.AllDirectories);
        var store = new V2UpdateTransactionJournalStore(scope.Root, applyAcls: true);
        await Assert.ThrowsExceptionAsync<IOException>(() => store.ReadAsync(CancellationToken.None));
        CollectionAssert.AreEquivalent(before, Directory.GetFileSystemEntries(scope.Root, "*", SearchOption.AllDirectories));
    }

    [TestMethod]
    public async Task Failure_after_publication_reports_ambiguity_and_preserves_canonical_journal()
    {
        using var scope = new Scope();
        scope.Provision();
        var store = new V2UpdateTransactionJournalStore(scope.Root, false,
            _ => throw new InvalidOperationException("Injected post-publication fault."));
        var admitted = Journal();

        var failure = await Assert.ThrowsExceptionAsync<V2JournalPostPublicationException>(
            () => store.PersistAsync(admitted, CancellationToken.None));
        Assert.IsInstanceOfType<InvalidOperationException>(failure.InnerException);
        Assert.AreEqual(admitted, (await scope.Store.ReadAsync(CancellationToken.None)).Journal);
        CollectionAssert.AreEqual(V2UpdateTransactionJournalCodec.Serialize(admitted), File.ReadAllBytes(scope.JournalPath));
        CollectionAssert.AreEquivalent(new[] { scope.JournalPath }, Directory.GetFileSystemEntries(scope.Transactions));
    }

    [TestMethod]
    public async Task Canonical_readback_failure_after_publication_is_reported()
    {
        using var scope = new Scope();
        scope.Provision();
        var store = new V2UpdateTransactionJournalStore(scope.Root, false, _ =>
        {
            File.WriteAllText(scope.JournalPath, "tampered");
            return Task.CompletedTask;
        });
        await Assert.ThrowsExceptionAsync<V2JournalPostPublicationException>(
            () => store.PersistAsync(Journal(), CancellationToken.None));
        var read = await scope.Store.ReadAsync(CancellationToken.None);
        Assert.AreEqual(V2JournalReadState.Invalid, read.State);
        Assert.AreEqual(UpdateTransactionJournalParseFailure.Malformed, read.Failure);
    }

    [TestMethod]
    public async Task Cancellation_after_publication_does_not_report_an_aborted_write()
    {
        using var scope = new Scope();
        scope.Provision();
        using var source = new CancellationTokenSource();
        var store = new V2UpdateTransactionJournalStore(scope.Root, false, _ =>
        {
            source.Cancel();
            return Task.CompletedTask;
        });
        var admitted = Journal();
        await store.PersistAsync(admitted, source.Token);
        Assert.AreEqual(admitted, (await scope.Store.ReadAsync(CancellationToken.None)).Journal);
    }

    private static V2UpdateTransactionJournal Journal() => new(
        "0123456789abcdef0123456789abcdef",
        new ReleaseIdentity(ReleaseGeneration.V2, 1, PriorHash),
        new ReleaseIdentity(ReleaseGeneration.V2, 3, TargetHash),
        V2UpdateTransactionPhase.Admitted,
        "fedcba9876543210fedcba9876543210", Time);

    private sealed class Scope : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-v2-journal-" + Guid.NewGuid().ToString("N"));
        internal string Updates => Path.Combine(Root, "Updates");
        internal string Transactions => Path.Combine(Updates, "TransactionsV2");
        internal string LockPath => Path.Combine(Updates, V2UpdateTransactionJournalStore.LockFileName);
        internal string JournalPath => Path.Combine(Transactions, V2UpdateTransactionJournalStore.JournalFileName);
        internal V2UpdateTransactionJournalStore Store => new(Root, applyAcls: false);

        internal Scope() => Directory.CreateDirectory(Root);

        internal void Provision()
        {
            Directory.CreateDirectory(Transactions);
            File.WriteAllBytes(LockPath, []);
        }

        public void Dispose()
        {
            var expectedParent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
            if (!string.Equals(Path.GetDirectoryName(Path.GetFullPath(Root)), expectedParent,
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new IOException("Disposable V2 journal scope escaped the temporary directory.");
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
