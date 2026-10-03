using System.Buffers.Binary;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class LocalFolderFingerprintInventoryInspectorTests
{
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);

    [TestMethod]
    public async Task Direct_regular_files_are_fingerprinted_and_child_directories_are_not_traversed()
    {
        using var root = new DisposableRoot();
        root.File("one.bin", "one"u8.ToArray());
        root.File("two.bin", "two"u8.ToArray());
        root.File(Path.Combine("nested", "inside.bin"), "inside"u8.ToArray());

        var result = await new LocalFolderFingerprintInventoryInspector().InspectAsync(root.Path, CancellationToken.None);

        Assert.AreEqual(FolderFingerprintInventoryOutcome.Completed, result.Outcome);
        Assert.AreEqual(3, result.Entries.Count);
        Assert.AreEqual(2, result.Entries.Count(entry => entry.Outcome == FolderFingerprintEntryOutcome.Fingerprinted));
        Assert.IsTrue(result.Entries.Any(entry => entry.RelativeName == "nested" && entry.Outcome == FolderFingerprintEntryOutcome.Declined));
        Assert.IsFalse(result.Entries.Any(entry => entry.RelativeName == "inside.bin"));
        Assert.IsFalse(result.Entries.Any(entry => entry.RelativeName.Contains(root.Path, StringComparison.OrdinalIgnoreCase)));
    }

    [TestMethod]
    public async Task File_count_limit_returns_incomplete_with_only_the_first_64_observed_entries()
    {
        using var root = new DisposableRoot();
        for (var index = 0; index < LocalFolderFingerprintInventoryInspector.MaximumProcessedFiles + 1; index++)
            root.File($"{index:D3}.bin", "x"u8.ToArray());

        var result = await new LocalFolderFingerprintInventoryInspector().InspectAsync(root.Path, CancellationToken.None);

        Assert.AreEqual(FolderFingerprintInventoryOutcome.Incomplete, result.Outcome);
        Assert.AreEqual(LocalFolderFingerprintInventoryInspector.MaximumProcessedFiles, result.Entries.Count);
    }

    [TestMethod]
    public async Task Per_file_limit_records_a_declined_entry_without_hashing()
    {
        using var root = new DisposableRoot();
        var oversized = Path.Combine(root.Path, "oversized.bin");
        await using (var stream = new FileStream(oversized, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            stream.SetLength(LocalFolderFingerprintInventoryInspector.MaximumFileByteLength + 1);

        var result = await new LocalFolderFingerprintInventoryInspector().InspectAsync(root.Path, CancellationToken.None);

        Assert.AreEqual(FolderFingerprintInventoryOutcome.Completed, result.Outcome);
        Assert.AreEqual(1, result.Entries.Count);
        Assert.AreEqual(FolderFingerprintEntryOutcome.Declined, result.Entries[0].Outcome);
        Assert.IsNull(result.Entries[0].Sha256);
    }

    [TestMethod]
    public async Task Aggregate_limit_returns_incomplete_before_a_fifth_32_mib_file_is_hashed()
    {
        using var root = new DisposableRoot();
        for (var index = 0; index < 5; index++)
        {
            await using var stream = new FileStream(Path.Combine(root.Path, $"large-{index}.bin"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            stream.SetLength(LocalFolderFingerprintInventoryInspector.MaximumFileByteLength);
        }

        var result = await new LocalFolderFingerprintInventoryInspector().InspectAsync(root.Path, CancellationToken.None);

        Assert.AreEqual(FolderFingerprintInventoryOutcome.Incomplete, result.Outcome);
        Assert.AreEqual(4, result.Entries.Count);
        Assert.IsTrue(result.Entries.All(entry => entry.Outcome == FolderFingerprintEntryOutcome.Fingerprinted));
    }

    [TestMethod]
    public async Task Time_limit_is_deterministic_and_publishes_only_previously_observed_entries()
    {
        using var root = new DisposableRoot();
        root.File("one.bin", new byte[128 * 1024]);
        var now = DateTimeOffset.UtcNow;
        var inspector = new LocalFolderFingerprintInventoryInspector(
            utcNow: () => now,
            afterFirstReadAsync: _ =>
            {
                now += LocalFolderFingerprintInventoryInspector.MaximumElapsed;
                return Task.CompletedTask;
            });

        var result = await inspector.InspectAsync(root.Path, CancellationToken.None);

        Assert.AreEqual(FolderFingerprintInventoryOutcome.Incomplete, result.Outcome);
        Assert.AreEqual(1, result.Entries.Count);
    }

    [TestMethod]
    public async Task Unavailable_and_changed_direct_entries_are_scoped_without_fingerprints()
    {
        using var root = new DisposableRoot();
        var unavailable = root.File("locked.bin", "locked"u8.ToArray());
        var changed = root.File("changed.bin", new byte[128 * 1024]);
        using var lockHandle = new FileStream(unavailable, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        using var writer = new FileStream(changed, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        var inspector = new LocalFolderFingerprintInventoryInspector(afterFirstReadAsync: _ =>
        {
            writer.SetLength(0);
            writer.Write("changed"u8);
            writer.Flush(flushToDisk: true);
            return Task.CompletedTask;
        });

        var result = await inspector.InspectAsync(root.Path, CancellationToken.None);

        Assert.AreEqual(FolderFingerprintInventoryOutcome.Completed, result.Outcome);
        Assert.IsTrue(result.Entries.Any(entry => entry.RelativeName == "locked.bin" && entry.Outcome == FolderFingerprintEntryOutcome.Unavailable && entry.Sha256 is null));
        Assert.IsTrue(result.Entries.Any(entry => entry.RelativeName == "changed.bin" && entry.Outcome == FolderFingerprintEntryOutcome.Changed && entry.Sha256 is null));
    }

    [TestMethod]
    public async Task Root_reparse_and_substitution_are_declined_when_the_test_host_allows_symlinks()
    {
        using var root = new DisposableRoot();
        var target = Path.Combine(root.Path, "target");
        Directory.CreateDirectory(target);
        root.File(Path.Combine("target", "sample.bin"), "content"u8.ToArray());
        var reparse = Path.Combine(root.Path, "reparse");
        try
        {
            Directory.CreateSymbolicLink(reparse, target);
        }
        catch (Exception error) when (IsPrivilegeNotHeld(error))
        {
            Assert.Inconclusive("The test host does not permit symbolic-link creation.");
            return;
        }

        var reparseResult = await new LocalFolderFingerprintInventoryInspector().InspectAsync(reparse, CancellationToken.None);
        Assert.AreEqual(FolderFingerprintInventoryOutcome.Declined, reparseResult.Outcome);
        Assert.AreEqual(0, reparseResult.Entries.Count);

        var selected = Path.Combine(root.Path, "selected");
        Directory.CreateDirectory(selected);
        root.File(Path.Combine("selected", "sample.bin"), "content"u8.ToArray());
        var moved = Path.Combine(root.Path, "moved");
        var substitution = new LocalFolderFingerprintInventoryInspector(afterRootOpenAsync: _ =>
        {
            Directory.Move(selected, moved);
            Directory.CreateSymbolicLink(selected, target);
            return Task.CompletedTask;
        });

        var substitutionResult = await substitution.InspectAsync(selected, CancellationToken.None);
        Assert.AreEqual(FolderFingerprintInventoryOutcome.Declined, substitutionResult.Outcome);
        Assert.AreEqual(0, substitutionResult.Entries.Count);
    }

    [TestMethod]
    public async Task Replacing_the_selected_directory_after_handle_validation_cannot_enumerate_or_open_the_replacement_root()
    {
        using var root = new DisposableRoot();
        var selected = Path.Combine(root.Path, "selected");
        Directory.CreateDirectory(selected);
        File.WriteAllBytes(Path.Combine(selected, "original.bin"), "original"u8.ToArray());
        var moved = Path.Combine(root.Path, "moved");
        var operations = new RecordingDirectoryOperations(new WindowsHandleRelativeDirectoryOperations());
        var inspector = new LocalFolderFingerprintInventoryInspector(
            afterRootValidationAsync: _ =>
            {
                Directory.Move(selected, moved);
                Directory.CreateDirectory(selected);
                File.WriteAllBytes(Path.Combine(selected, "replacement.bin"), "replacement"u8.ToArray());
                return Task.CompletedTask;
            },
            directoryOperations: operations);

        var result = await inspector.InspectAsync(selected, CancellationToken.None);

        Assert.AreEqual(FolderFingerprintInventoryOutcome.Declined, result.Outcome);
        Assert.AreEqual(0, result.Entries.Count);
        CollectionAssert.Contains(operations.EnumeratedNames, "original.bin");
        CollectionAssert.DoesNotContain(operations.EnumeratedNames, "replacement.bin");
        CollectionAssert.Contains(operations.OpenedNames, "original.bin");
        CollectionAssert.DoesNotContain(operations.OpenedNames, "replacement.bin");
    }

    [TestMethod]
    public async Task Oversized_unsigned_directory_entry_offset_fails_closed_without_escaping_the_parser()
    {
        using var root = new DisposableRoot();
        root.File("sample.bin", "content"u8.ToArray());
        var native = new OversizedOffsetDirectoryNative();
        var inspector = new LocalFolderFingerprintInventoryInspector(
            directoryOperations: new WindowsHandleRelativeDirectoryOperations(native));

        var result = await inspector.InspectAsync(root.Path, CancellationToken.None);

        Assert.AreEqual(FolderFingerprintInventoryOutcome.Unavailable, result.Outcome);
        Assert.AreEqual(0, result.Entries.Count);
        Assert.AreEqual(1, native.ReadCount);
        Assert.AreEqual(0, native.OpenCount);
    }

    [TestMethod]
    public async Task Reparse_entry_is_declined_when_the_test_host_allows_one()
    {
        using var root = new DisposableRoot();
        var target = root.File("target.bin", "content"u8.ToArray());
        var link = Path.Combine(root.Path, "link.bin");
        try
        {
            File.CreateSymbolicLink(link, target);
        }
        catch (Exception error) when (IsPrivilegeNotHeld(error))
        {
            Assert.Inconclusive("The test host does not permit symbolic-link creation.");
            return;
        }

        var result = await new LocalFolderFingerprintInventoryInspector().InspectAsync(root.Path, CancellationToken.None);

        Assert.AreEqual(FolderFingerprintInventoryOutcome.Completed, result.Outcome);
        Assert.IsTrue(result.Entries.Any(entry => entry.RelativeName == "link.bin" && entry.Outcome == FolderFingerprintEntryOutcome.Declined && entry.Sha256 is null));
    }

    [TestMethod]
    public async Task Cancellation_publishes_no_inventory_result()
    {
        using var root = new DisposableRoot();
        root.File("cancel.bin", new byte[128 * 1024]);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        var inspector = new LocalFolderFingerprintInventoryInspector(afterFirstReadAsync: token =>
        {
            entered.TrySetResult();
            return Task.Delay(Timeout.InfiniteTimeSpan, token);
        });

        var inventory = inspector.InspectAsync(root.Path, cancellation.Token);
        await entered.Task;
        cancellation.Cancel();

        try
        {
            await inventory;
            Assert.Fail("Cancellation must not publish an inventory result.");
        }
        catch (OperationCanceledException)
        {
        }
    }

    [TestMethod]
    public async Task Inventory_shares_the_single_in_flight_lease_with_file_inspection()
    {
        using var root = new DisposableRoot();
        var file = root.File("busy.bin", new byte[128 * 1024]);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var coordinator = new LocalFileInspectionCoordinator();
        var inventory = new LocalFolderFingerprintInventoryInspector(coordinator, afterFirstReadAsync: _ =>
        {
            entered.TrySetResult();
            return release.Task;
        });
        var fingerprint = new LocalFileFingerprintInspector(coordinator: coordinator);

        var inventoryTask = inventory.InspectAsync(root.Path, CancellationToken.None);
        await entered.Task;
        var fingerprintResult = await fingerprint.InspectAsync(file, CancellationToken.None);
        release.TrySetResult();

        Assert.AreEqual(FileFingerprintInspectionOutcome.AlreadyInProgress, fingerprintResult.Outcome);
        Assert.AreEqual(FolderFingerprintInventoryOutcome.Completed, (await inventoryTask).Outcome);
    }

    private sealed class DisposableRoot : IDisposable
    {
        internal DisposableRoot()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "Vantrel.Security.Desktop.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }
        internal string Path { get; }
        internal string File(string name, byte[] contents)
        {
            var path = System.IO.Path.Combine(Path, name);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            System.IO.File.WriteAllBytes(path, contents);
            return path;
        }
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, true); }
    }

    private static bool IsPrivilegeNotHeld(Exception error) => error.HResult == PrivilegeNotHeldHResult;

    private sealed class RecordingDirectoryOperations(IHandleRelativeDirectoryOperations inner) : IHandleRelativeDirectoryOperations
    {
        private readonly Dictionary<long, string> _namesById = [];
        internal List<string> EnumeratedNames { get; } = [];
        internal List<string> OpenedNames { get; } = [];

        public IEnumerable<HandleRelativeDirectoryEntry> Enumerate(Microsoft.Win32.SafeHandles.SafeFileHandle directoryHandle)
        {
            foreach (var entry in inner.Enumerate(directoryHandle))
            {
                _namesById[entry.FileId] = entry.Name;
                EnumeratedNames.Add(entry.Name);
                yield return entry;
            }
        }

        public Microsoft.Win32.SafeHandles.SafeFileHandle OpenFile(Microsoft.Win32.SafeHandles.SafeFileHandle directoryHandle, long fileId)
        {
            if (_namesById.TryGetValue(fileId, out var name)) OpenedNames.Add(name);
            return inner.OpenFile(directoryHandle, fileId);
        }
    }

    private sealed class OversizedOffsetDirectoryNative : IHandleRelativeDirectoryNativeApi
    {
        internal int ReadCount { get; private set; }
        internal int OpenCount { get; private set; }

        public bool ReadDirectory(SafeFileHandle directoryHandle, int informationClass, byte[] buffer, out int error)
        {
            ReadCount++;
            Array.Clear(buffer);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, uint.MaxValue);
            error = 0;
            return true;
        }

        public SafeFileHandle OpenFileById(SafeFileHandle directoryHandle, ref FileIdDescriptor fileId, uint desiredAccess,
            uint shareMode, uint flagsAndAttributes)
        {
            OpenCount++;
            throw new AssertFailedException("A malformed directory entry must not be opened.");
        }
    }
}
