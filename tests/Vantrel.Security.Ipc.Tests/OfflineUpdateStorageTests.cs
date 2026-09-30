using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class OfflineUpdateStorageTests
{
    [DataTestMethod]
    [DataRow(true, 1)]
    [DataRow(true, 5)]
    [DataRow(true, 9)]
    [DataRow(false, 1)]
    [DataRow(false, 5)]
    [DataRow(false, 9)]
    public async Task Active_copy_cancellation_cleans_destination_and_preserves_source_and_sibling(bool candidate, int filePosition)
    {
        await using var scope = new Scope();
        using var cancellation = new CancellationTokenSource();
        var source = candidate ? Path.Combine(scope.UpdatesRoot, "Staged", "candidate") : scope.InstalledRoot;
        Directory.CreateDirectory(source);
        var originals = new Dictionary<string, byte[]>();
        foreach (var name in FixedServiceReleaseFiles.AllNames)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat(name, 256)));
            originals.Add(name, bytes);
            await File.WriteAllBytesAsync(Path.Combine(source, name), bytes);
        }
        var operations = new Operations { CancelCopyAt = filePosition };
        var storage = CreateStorage(scope, applyAcls: true, operations: operations);
        const string id = "0123456789abcdef0123456789abcdef";
        var destination = candidate ? storage.PrivateCandidate(id) : storage.Backup(id);
        var sibling = Path.Combine(Path.GetDirectoryName(destination)!, "unrelated-sibling");
        Directory.CreateDirectory(sibling);
        var sentinel = Path.Combine(sibling, FixedServiceReleaseFiles.AllNames[0]);
        await File.WriteAllTextAsync(sentinel, "unchanged sibling");
        var copy = candidate ? storage.CopyStagedToPrivateAsync(id, cancellation.Token)
            : storage.CopyInstalledToBackupAsync(id, cancellation.Token);
        try
        {
            await operations.CopyPending.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.IsFalse(copy.IsCompleted);
            Assert.IsFalse(cancellation.IsCancellationRequested);
            Assert.AreEqual(cancellation.Token, operations.ActiveCopyToken);
            Assert.AreEqual(4096, operations.ActiveCopyBytes);
            Assert.IsTrue(operations.ActiveDestinationWasExclusivelyOpen);
            cancellation.Cancel();
            var failure = await Assert.ThrowsExceptionAsync<TaskCanceledException>(
                () => copy.WaitAsync(TimeSpan.FromSeconds(10)));
            Assert.AreEqual(cancellation.Token, failure.CancellationToken);
            Assert.IsTrue(copy.IsCanceled);
            Assert.IsTrue(operations.ActiveCancellationObserved);
            Assert.AreEqual(filePosition, operations.CopiedPaths.Count);
            Assert.AreEqual(filePosition - 1, operations.CompletedCopies.Count);
            Assert.AreEqual(filePosition - 1, operations.FlushedPaths.Count);
            CollectionAssert.AreEqual(FixedServiceReleaseFiles.AllNames.Take(filePosition - 1)
                .Select(name => Path.Combine(destination, name)).ToArray(), operations.CompletedFlushes);
            CollectionAssert.AreEqual(operations.CompletedFlushes, operations.FileAcls.Select(call => call.Path).ToArray());
            CollectionAssert.AreEqual(FixedServiceReleaseFiles.AllNames.Take(filePosition - 1)
                .SelectMany(name => new[] { "copy:" + name, "flush:" + name })
                .Append("copy:" + FixedServiceReleaseFiles.AllNames[filePosition - 1]).ToArray(), operations.ContentCalls);
            Assert.IsFalse(Directory.Exists(destination), "Storage must clean up before fixture disposal.");
            Assert.ThrowsException<DirectoryNotFoundException>(() => OfflineReleaseVerifier.ValidateExactSet(destination));
            foreach (var name in FixedServiceReleaseFiles.AllNames)
            {
                Assert.IsFalse(File.Exists(Path.Combine(destination, name)));
                using var input = new FileStream(Path.Combine(source, name), FileMode.Open, FileAccess.Read, FileShare.None);
                using var contents = new MemoryStream();
                await input.CopyToAsync(contents);
                CollectionAssert.AreEqual(originals[name], contents.ToArray());
            }
            OfflineReleaseVerifier.ValidateExactSet(source);
            Assert.AreEqual("unchanged sibling", await File.ReadAllTextAsync(sentinel));
            CollectionAssert.AreEqual(new[] { sentinel }, Directory.GetFileSystemEntries(sibling));
        }
        finally
        {
            cancellation.Cancel();
            try { await copy.WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        }
    }

    [DataTestMethod]
    [DataRow(true, 1)]
    [DataRow(true, 5)]
    [DataRow(true, 9)]
    [DataRow(false, 1)]
    [DataRow(false, 5)]
    [DataRow(false, 9)]
    public async Task Durable_flush_failure_cleans_destination_and_preserves_source_and_sibling(bool candidate, int filePosition)
    {
        await using var scope = new Scope();
        var source = candidate ? Path.Combine(scope.UpdatesRoot, "Staged", "candidate") : scope.InstalledRoot;
        await CreateFixedReleaseAsync(source, "flush-failure-");
        var originals = new Dictionary<string, byte[]>();
        foreach (var name in FixedServiceReleaseFiles.AllNames)
            originals.Add(name, await File.ReadAllBytesAsync(Path.Combine(source, name)));
        var operations = new Operations { FailFlushAt = filePosition };
        var storage = CreateStorage(scope, applyAcls: true, operations: operations);
        const string id = "0123456789abcdef0123456789abcdef";
        var destination = candidate ? storage.PrivateCandidate(id) : storage.Backup(id);
        var sibling = Path.Combine(Path.GetDirectoryName(destination)!, "unrelated-sibling");
        Directory.CreateDirectory(sibling);
        var sentinel = Path.Combine(sibling, FixedServiceReleaseFiles.AllNames[0]);
        await File.WriteAllTextAsync(sentinel, "unchanged sibling");

        var failure = await Assert.ThrowsExceptionAsync<IOException>(() => candidate
            ? storage.CopyStagedToPrivateAsync(id, CancellationToken.None)
            : storage.CopyInstalledToBackupAsync(id, CancellationToken.None));
        Assert.AreEqual("Test-only durable-flush failure after FlushAsync.", failure.Message);
        var failedPath = Path.Combine(destination, FixedServiceReleaseFiles.AllNames[filePosition - 1]);
        Assert.AreEqual(failedPath, operations.FailedFlushPath);
        Assert.IsTrue(operations.FailedFlushAsyncCompleted);
        Assert.IsTrue(operations.FlushDestinationWasExclusivelyOpen);
        Assert.AreEqual(filePosition, operations.CopiedPaths.Count);
        Assert.AreEqual(filePosition, operations.CompletedCopies.Count);
        Assert.AreEqual((long)originals[Path.GetFileName(failedPath)].Length, operations.CompletedCopies[failedPath]);
        Assert.AreEqual(filePosition, operations.FlushedPaths.Count);
        CollectionAssert.AreEqual(FixedServiceReleaseFiles.AllNames.Take(filePosition - 1)
            .Select(name => Path.Combine(destination, name)).ToArray(), operations.CompletedFlushes);
        CollectionAssert.AreEqual(operations.CompletedFlushes, operations.FileAcls.Select(call => call.Path).ToArray());
        CollectionAssert.AreEqual(FixedServiceReleaseFiles.AllNames.Take(filePosition)
            .SelectMany(name => new[] { "copy:" + name, "flush:" + name }).ToArray(), operations.ContentCalls);
        Assert.IsFalse(Directory.Exists(destination), "Storage cleanup must complete before fixture disposal.");
        Assert.ThrowsException<DirectoryNotFoundException>(() => OfflineReleaseVerifier.ValidateExactSet(destination));
        foreach (var name in FixedServiceReleaseFiles.AllNames)
        {
            Assert.IsFalse(File.Exists(Path.Combine(destination, name)));
            using var input = new FileStream(Path.Combine(source, name), FileMode.Open, FileAccess.Read, FileShare.None);
            using var contents = new MemoryStream();
            await input.CopyToAsync(contents);
            CollectionAssert.AreEqual(originals[name], contents.ToArray());
        }
        OfflineReleaseVerifier.ValidateExactSet(source);
        Assert.AreEqual("unchanged sibling", await File.ReadAllTextAsync(sentinel));
        CollectionAssert.AreEqual(new[] { sentinel }, Directory.GetFileSystemEntries(sibling));
        // The failing destination denied a second open without delete sharing;
        // successful storage deletion proves its handle closed before cleanup.
    }

    [DataTestMethod]
    [DataRow(true, 1)]
    [DataRow(true, 5)]
    [DataRow(true, 9)]
    [DataRow(false, 1)]
    [DataRow(false, 5)]
    [DataRow(false, 9)]
    public async Task Partial_copy_failure_cleans_destination_and_preserves_source_and_sibling(bool candidate, int filePosition)
    {
        await using var scope = new Scope();
        var source = candidate ? Path.Combine(scope.UpdatesRoot, "Staged", "candidate") : scope.InstalledRoot;
        Directory.CreateDirectory(source);
        var originals = new Dictionary<string, byte[]>();
        foreach (var name in FixedServiceReleaseFiles.AllNames)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat(name, 256)));
            originals.Add(name, bytes);
            await File.WriteAllBytesAsync(Path.Combine(source, name), bytes);
        }
        var operations = new Operations { PartialCopyAt = filePosition };
        var storage = CreateStorage(scope, operations: operations);
        const string id = "0123456789abcdef0123456789abcdef";
        var destination = candidate ? storage.PrivateCandidate(id) : storage.Backup(id);
        var sibling = Path.Combine(Path.GetDirectoryName(destination)!, "unrelated-sibling");
        Directory.CreateDirectory(sibling);
        var sentinel = Path.Combine(sibling, FixedServiceReleaseFiles.AllNames[0]);
        await File.WriteAllTextAsync(sentinel, "unchanged sibling");

        var exception = await Assert.ThrowsExceptionAsync<IOException>(() => candidate
            ? storage.CopyStagedToPrivateAsync(id, CancellationToken.None)
            : storage.CopyInstalledToBackupAsync(id, CancellationToken.None));
        Assert.AreEqual("Test-only partial-copy failure.", exception.Message);
        Assert.AreEqual(4096, operations.PartialBytesWritten);
        Assert.IsTrue(operations.PartialDestinationWasExclusivelyOpen);
        Assert.AreEqual(filePosition, operations.CopiedPaths.Count);
        Assert.AreEqual(filePosition - 1, operations.FlushedPaths.Count);
        CollectionAssert.AreEqual(FixedServiceReleaseFiles.AllNames.Take(filePosition - 1)
            .SelectMany(name => new[] { "copy:" + name, "flush:" + name })
            .Append("copy:" + FixedServiceReleaseFiles.AllNames[filePosition - 1]).ToArray(), operations.ContentCalls);
        Assert.IsFalse(Directory.Exists(destination), "Cleanup must remove partial and earlier completed files before scope disposal.");
        Assert.ThrowsException<DirectoryNotFoundException>(() => OfflineReleaseVerifier.ValidateExactSet(destination));
        // FileShare.None denied a second open during injection. Successful deletion by
        // storage therefore also proves the destination handle closed before cleanup.
        foreach (var name in FixedServiceReleaseFiles.AllNames)
        {
            Assert.IsFalse(File.Exists(Path.Combine(destination, name)));
            using var input = new FileStream(Path.Combine(source, name), FileMode.Open, FileAccess.Read, FileShare.None);
            using var contents = new MemoryStream();
            await input.CopyToAsync(contents);
            CollectionAssert.AreEqual(originals[name], contents.ToArray());
        }
        OfflineReleaseVerifier.ValidateExactSet(source);
        Assert.AreEqual("unchanged sibling", await File.ReadAllTextAsync(sentinel));
        CollectionAssert.AreEqual(new[] { sentinel }, Directory.GetFileSystemEntries(sibling));
    }

    [DataTestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task Fixed_copy_and_durable_flush_use_storage_owned_provider(bool candidate)
    {
        await using var scope = new Scope();
        var source = candidate ? Path.Combine(scope.UpdatesRoot, "Staged", "candidate") : scope.InstalledRoot;
        await CreateFixedReleaseAsync(source, "copy-flush-");
        var operations = new Operations();
        var storage = CreateStorage(scope, operations: operations);
        const string id = "0123456789abcdef0123456789abcdef";
        if (candidate) await storage.CopyStagedToPrivateAsync(id, CancellationToken.None);
        else await storage.CopyInstalledToBackupAsync(id, CancellationToken.None);
        var destination = candidate ? storage.PrivateCandidate(id) : storage.Backup(id);

        CollectionAssert.AreEqual(FixedServiceReleaseFiles.AllNames.SelectMany(name => new[] { "copy:" + name, "flush:" + name }).ToArray(), operations.ContentCalls);
        Assert.AreEqual(9, operations.CopiedPaths.Count);
        Assert.AreEqual(9, operations.FlushedPaths.Count);
        foreach (var name in FixedServiceReleaseFiles.AllNames)
        {
            Assert.IsTrue(operations.CopiedPaths.Contains((Path.Combine(source, name), Path.Combine(destination, name))));
            CollectionAssert.Contains(operations.FlushedPaths, Path.Combine(destination, name));
            // Exclusive opens prove storage disposed its handles after provider completion.
            using var input = new FileStream(Path.Combine(source, name), FileMode.Open, FileAccess.Read, FileShare.None);
            using var output = new FileStream(Path.Combine(destination, name), FileMode.Open, FileAccess.Read, FileShare.None);
            using var sourceReader = new StreamReader(input);
            using var destinationReader = new StreamReader(output);
            Assert.AreEqual(await sourceReader.ReadToEndAsync(), await destinationReader.ReadToEndAsync());
        }
        OfflineReleaseVerifier.ValidateExactSet(destination);
    }

    [TestMethod]
    public async Task Private_copy_accepts_only_the_fixed_nine_file_set()
    {
        await using var scope = new Scope();
        var staged = Path.Combine(scope.UpdatesRoot, "Staged", "candidate"); Directory.CreateDirectory(staged);
        foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(staged, name), name);
        var storage = CreateStorage(scope);
        await storage.CopyStagedToPrivateAsync("0123456789abcdef0123456789abcdef", CancellationToken.None);
        OfflineReleaseVerifier.ValidateExactSet(storage.PrivateCandidate("0123456789abcdef0123456789abcdef"));
    }

    [TestMethod]
    public async Task Private_copy_rejects_extra_and_never_creates_a_candidate()
    {
        await using var scope = new Scope();
        var staged = Path.Combine(scope.UpdatesRoot, "Staged", "candidate"); Directory.CreateDirectory(staged);
        foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(staged, name), name);
        await File.WriteAllTextAsync(Path.Combine(staged, "extra.dll"), "x");
        var storage = CreateStorage(scope);
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => storage.CopyStagedToPrivateAsync("0123456789abcdef0123456789abcdef", CancellationToken.None));
        Assert.IsFalse(Directory.Exists(storage.PrivateCandidate("0123456789abcdef0123456789abcdef")));
    }

    [TestMethod]
    public void Exact_set_rejects_directory_and_containment_escape()
    {
        var scope = new Scope();
        var root = scope.Root;
        try
        {
            Directory.CreateDirectory(root);
            foreach (var name in FixedServiceReleaseFiles.AllNames) File.WriteAllText(Path.Combine(root, name), name);
            Assert.ThrowsException<ArgumentException>(() => CreateStorage(scope).PrivateCandidate("../escaped"));
            File.Delete(Path.Combine(root, "Vantrel.Security.Core.dll")); Directory.CreateDirectory(Path.Combine(root, "Vantrel.Security.Core.dll"));
            Assert.ThrowsException<InvalidDataException>(() => OfflineReleaseVerifier.ValidateExactSet(root));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [DataTestMethod]
    [DataRow("missing")]
    [DataRow("extra")]
    [DataRow("directory")]
    public async Task Invalid_staged_candidate_never_becomes_private_authority(string kind)
    {
        await using var scope = new Scope(); var staged = Path.Combine(scope.UpdatesRoot, "Staged", "candidate"); Directory.CreateDirectory(staged);
        foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(staged, name), name);
        if (kind == "missing") File.Delete(Path.Combine(staged, FixedServiceReleaseFiles.AllNames[0]));
        if (kind == "extra") await File.WriteAllTextAsync(Path.Combine(staged, "unexpected"), "x");
        if (kind == "directory") { File.Delete(Path.Combine(staged, FixedServiceReleaseFiles.AllNames[0])); Directory.CreateDirectory(Path.Combine(staged, FixedServiceReleaseFiles.AllNames[0])); }
        var storage = CreateStorage(scope); const string id = "0123456789abcdef0123456789abcdef";
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => storage.CopyStagedToPrivateAsync(id, CancellationToken.None));
        Assert.IsFalse(Directory.Exists(storage.PrivateCandidate(id)));
    }

    [TestMethod]
    public async Task Pre_cancelled_private_copy_cleans_its_partial_fixed_directory()
    {
        await using var scope = new Scope(); var staged = Path.Combine(scope.UpdatesRoot, "Staged", "candidate"); Directory.CreateDirectory(staged);
        foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(staged, name), name);
        var storage = CreateStorage(scope); const string id = "0123456789abcdef0123456789abcdef"; using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => storage.CopyStagedToPrivateAsync(id, cancelled.Token));
        Assert.IsFalse(Directory.Exists(storage.PrivateCandidate(id)));
    }
    [DataTestMethod]
    [DataRow(0)]
    [DataRow(4)]
    [DataRow(8)]
    public async Task Faulted_fixed_backup_copy_cleans_partial_files_and_cannot_be_reused(int failingIndex)
    {
        await using var scope = new Scope(); var source = Path.Combine(scope.Root, "source"); var backup = Path.Combine(scope.Root, "Backups", "0123456789abcdef0123456789abcdef"); Directory.CreateDirectory(source);
        foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(source, name), name);
        await Assert.ThrowsExceptionAsync<IOException>(() => OfflineUpdateStorage.CopyExactReleaseForTestAsync(source, backup, index => index == failingIndex, CancellationToken.None));
        Assert.IsFalse(Directory.Exists(backup));
        Assert.ThrowsException<DirectoryNotFoundException>(() => OfflineReleaseVerifier.ValidateExactSet(backup));
    }
    [TestMethod]
    public async Task Storage_uses_injected_directory_and_attribute_operations()
    {
        await using var scope = new Scope(); var staged = Path.Combine(scope.UpdatesRoot, "Staged", "candidate"); Directory.CreateDirectory(staged);
        foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(staged, name), name);
        var operations = new Operations(); var storage = CreateStorage(scope, false, operations);
        await storage.CopyStagedToPrivateAsync("0123456789abcdef0123456789abcdef", CancellationToken.None);
        Assert.AreEqual(1, operations.Created.Count);
        Assert.AreEqual(Path.Combine(scope.UpdatesRoot, "Transactions"), operations.Created[0]);
        Assert.IsTrue(operations.Attributes > 0);
    }

    [TestMethod]
    public async Task Attribute_inspection_failure_prevents_private_candidate()
    {
        await using var scope = new Scope(); var staged = Path.Combine(scope.UpdatesRoot, "Staged", "candidate"); Directory.CreateDirectory(staged);
        foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(staged, name), name);
        var storage = CreateStorage(scope, false, new Operations { ThrowAttributes = true }); const string id="0123456789abcdef0123456789abcdef";
        await Assert.ThrowsExceptionAsync<IOException>(() => storage.CopyStagedToPrivateAsync(id, CancellationToken.None)); Assert.IsFalse(Directory.Exists(storage.PrivateCandidate(id)));
    }

    [TestMethod]
    public async Task Directory_creation_failure_prevents_private_candidate()
    {
        await using var scope = new Scope(); var staged = Path.Combine(scope.UpdatesRoot, "Staged", "candidate"); Directory.CreateDirectory(staged);
        foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(staged, name), name);
        var operations = new Operations { ThrowCreate = true }; var storage = CreateStorage(scope, false, operations); const string id = "0123456789abcdef0123456789abcdef";
        await Assert.ThrowsExceptionAsync<IOException>(() => storage.CopyStagedToPrivateAsync(id, CancellationToken.None));
        Assert.AreEqual(1, operations.Created.Count); Assert.AreEqual(Path.Combine(scope.UpdatesRoot, "Transactions"), operations.Created[0]); Assert.IsFalse(Directory.Exists(storage.PrivateCandidate(id)));
    }

    [TestMethod]
    public void Explicit_disposable_roots_accept_distinct_safe_directories()
    {
        using var scope = new Scope();
        var storage = CreateStorage(scope);
        Assert.AreEqual(Path.Combine(scope.UpdatesRoot, "Backups", "0123456789abcdef0123456789abcdef"), storage.Backup("0123456789abcdef0123456789abcdef"));
    }

    [DataTestMethod]
    [DataRow("")]
    [DataRow("relative")]
    public void Explicit_disposable_roots_reject_missing_or_relative_paths(string updatesRoot)
    {
        using var scope = new Scope();
        Assert.ThrowsException<ArgumentException>(() => new OfflineUpdateStorage(updatesRoot, scope.InstalledRoot, false, WindowsOfflineUpdateFileOperations.Instance));
        Assert.ThrowsException<ArgumentException>(() => new OfflineUpdateStorage(scope.UpdatesRoot, updatesRoot, false, WindowsOfflineUpdateFileOperations.Instance));
    }

    [TestMethod]
    public void Explicit_disposable_roots_reject_null_paths()
    {
        using var scope = new Scope();
        Assert.ThrowsException<ArgumentException>(() => new OfflineUpdateStorage(null!, scope.InstalledRoot, false, WindowsOfflineUpdateFileOperations.Instance));
        Assert.ThrowsException<ArgumentException>(() => new OfflineUpdateStorage(scope.UpdatesRoot, null!, false, WindowsOfflineUpdateFileOperations.Instance));
    }

    [TestMethod]
    public void Explicit_disposable_roots_reject_overlaps_but_accept_similarly_named_siblings()
    {
        using var scope = new Scope();
        Assert.ThrowsException<ArgumentException>(() => new OfflineUpdateStorage(scope.UpdatesRoot, Path.Combine(scope.UpdatesRoot, "Installed"), false, WindowsOfflineUpdateFileOperations.Instance));
        var sibling = Path.Combine(scope.Root, "Updates-sibling");
        var storage = new OfflineUpdateStorage(scope.UpdatesRoot, sibling, false, WindowsOfflineUpdateFileOperations.Instance);
        Assert.AreEqual(Path.Combine(scope.UpdatesRoot, "Backups", "0123456789abcdef0123456789abcdef"), storage.Backup("0123456789abcdef0123456789abcdef"));
    }

    [DataTestMethod]
    [DataRow("installed")]
    [DataRow("installed-ancestor")]
    [DataRow("installed-descendant")]
    [DataRow("updates")]
    [DataRow("updates-ancestor")]
    [DataRow("updates-descendant")]
    [DataRow("policy")]
    public void Explicit_disposable_roots_reject_protected_production_locations(string kind)
    {
        using var scope = new Scope();
        var policy = Path.Combine(FixedUpdatePaths.VantrelRoot, "ReleasePolicy");
        var protectedRoot = kind switch
        {
            "installed" => FixedUpdatePaths.InstalledServiceRoot,
            "installed-ancestor" => Directory.GetParent(FixedUpdatePaths.InstalledServiceRoot)!.FullName,
            "installed-descendant" => Path.Combine(FixedUpdatePaths.InstalledServiceRoot, "child"),
            "updates" => FixedUpdatePaths.UpdatesRoot,
            "updates-ancestor" => Directory.GetParent(FixedUpdatePaths.UpdatesRoot)!.FullName,
            "updates-descendant" => Path.Combine(FixedUpdatePaths.UpdatesRoot, "child"),
            "policy" => policy,
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        Assert.ThrowsException<ArgumentException>(() => new OfflineUpdateStorage(protectedRoot, scope.InstalledRoot, false, WindowsOfflineUpdateFileOperations.Instance));
    }

    [TestMethod]
    public void Explicit_disposable_roots_reject_reparse_leaf_and_ancestor()
    {
        using var scope = new Scope();
        Directory.CreateDirectory(scope.Root);
        var target = Path.Combine(scope.Root, "target"); Directory.CreateDirectory(target);
        var leaf = Path.Combine(scope.Root, "leaf");
        try { Directory.CreateSymbolicLink(leaf, target); }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c mklink /J \"{leaf}\" \"{target}\"",
                CreateNoWindow = true,
                UseShellExecute = false
            });
            process!.WaitForExit();
            if (process.ExitCode != 0)
            {
                Assert.Inconclusive("Creating a disposable directory reparse point is unavailable in this environment.");
                return;
            }
        }
        try
        {
            Assert.ThrowsException<IOException>(() => new OfflineUpdateStorage(leaf, scope.InstalledRoot, false, WindowsOfflineUpdateFileOperations.Instance));
            Assert.ThrowsException<IOException>(() => new OfflineUpdateStorage(Path.Combine(leaf, "child"), scope.InstalledRoot, false, WindowsOfflineUpdateFileOperations.Instance));
        }
        finally
        {
            if (Directory.Exists(leaf)) Directory.Delete(leaf);
        }
    }

    [TestMethod]
    public async Task Backup_copy_uses_the_disposable_installed_predecessor_root()
    {
        await using var scope = new Scope();
        Directory.CreateDirectory(scope.InstalledRoot);
        foreach (var name in FixedServiceReleaseFiles.AllNames)
            await File.WriteAllTextAsync(Path.Combine(scope.InstalledRoot, name), "predecessor-" + name);

        var storage = CreateStorage(scope);
        const string id = "0123456789abcdef0123456789abcdef";
        await storage.CopyInstalledToBackupAsync(id, CancellationToken.None);

        var backup = storage.Backup(id);
        OfflineReleaseVerifier.ValidateExactSet(backup);
        foreach (var name in FixedServiceReleaseFiles.AllNames)
            Assert.AreEqual("predecessor-" + name, await File.ReadAllTextAsync(Path.Combine(backup, name)));
        Assert.IsTrue(Path.GetFullPath(backup).StartsWith(Path.GetFullPath(scope.UpdatesRoot) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public async Task Candidate_copy_applies_all_acls_through_the_storage_owned_operations()
    {
        await using var scope = new Scope();
        var staged = Path.Combine(scope.UpdatesRoot, "Staged", "candidate"); Directory.CreateDirectory(staged);
        foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(staged, name), name);

        var operations = new Operations();
        var storage = CreateStorage(scope, applyAcls: true, operations);
        const string id = "0123456789abcdef0123456789abcdef";
        await storage.CopyStagedToPrivateAsync(id, CancellationToken.None);

        var candidate = storage.PrivateCandidate(id);
        CollectionAssert.AreEquivalent(
            new[] { Path.GetFullPath(scope.UpdatesRoot), Path.Combine(scope.UpdatesRoot, "Transactions"), candidate },
            operations.DirectoryAcls.Select(call => call.Path).ToArray());
        Assert.IsTrue(operations.DirectoryAcls.Single(call => PathsEqual(call.Path, Path.Combine(scope.UpdatesRoot, "Transactions"))).AllowLocalService);
        Assert.IsTrue(operations.DirectoryAcls.Where(call => !PathsEqual(call.Path, Path.Combine(scope.UpdatesRoot, "Transactions"))).All(call => !call.AllowLocalService));
        Assert.AreEqual(FixedServiceReleaseFiles.AllNames.Length, operations.FileAcls.Count);
        CollectionAssert.AreEquivalent(FixedServiceReleaseFiles.AllNames, operations.FileAcls.Select(call => Path.GetFileName(call.Path)).ToArray());
        Assert.IsTrue(operations.FileAcls.All(call => !call.AllowLocalService));
        Assert.IsTrue(operations.DirectoryAcls.Concat(operations.FileAcls).All(call => IsAtOrUnder(scope.UpdatesRoot, call.Path)));
        OfflineReleaseVerifier.ValidateExactSet(candidate);
    }

    [TestMethod]
    public async Task Backup_copy_applies_all_acls_through_the_storage_owned_operations()
    {
        await using var scope = new Scope();
        Directory.CreateDirectory(scope.InstalledRoot);
        foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(scope.InstalledRoot, name), "predecessor-" + name);

        var operations = new Operations();
        var storage = CreateStorage(scope, applyAcls: true, operations);
        const string id = "0123456789abcdef0123456789abcdef";
        await storage.CopyInstalledToBackupAsync(id, CancellationToken.None);

        var backup = storage.Backup(id);
        CollectionAssert.AreEquivalent(
            new[] { Path.GetFullPath(scope.UpdatesRoot), Path.Combine(scope.UpdatesRoot, "Backups"), backup },
            operations.DirectoryAcls.Select(call => call.Path).ToArray());
        Assert.IsTrue(operations.DirectoryAcls.All(call => !call.AllowLocalService));
        Assert.AreEqual(FixedServiceReleaseFiles.AllNames.Length, operations.FileAcls.Count);
        CollectionAssert.AreEquivalent(FixedServiceReleaseFiles.AllNames, operations.FileAcls.Select(call => Path.GetFileName(call.Path)).ToArray());
        Assert.IsTrue(operations.FileAcls.All(call => !call.AllowLocalService));
        Assert.IsTrue(operations.DirectoryAcls.Concat(operations.FileAcls).All(call => IsAtOrUnder(scope.UpdatesRoot, call.Path)));
        foreach (var name in FixedServiceReleaseFiles.AllNames)
            Assert.AreEqual("predecessor-" + name, await File.ReadAllTextAsync(Path.Combine(backup, name)));
        OfflineReleaseVerifier.ValidateExactSet(backup);
    }

    [TestMethod]
    public async Task Administrator_only_real_windows_acls_protect_candidate_and_backup_descriptors()
    {
        var principal = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent());
        if (!principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator)) Assert.Inconclusive("Administrator token required before protected ACL artifacts are created.");
        await using var scope = new Scope();
        await CreateFixedReleaseAsync(Path.Combine(scope.UpdatesRoot, "Staged", "candidate"), "candidate-");
        await CreateFixedReleaseAsync(scope.InstalledRoot, "backup-");
        var storage = CreateStorage(scope, true, WindowsOfflineUpdateFileOperations.Instance); const string id = "0123456789abcdef0123456789abcdef";
        await storage.CopyStagedToPrivateAsync(id, CancellationToken.None); await storage.CopyInstalledToBackupAsync(id, CancellationToken.None);
        var transactions = Path.Combine(scope.UpdatesRoot, "Transactions"); var candidate = storage.PrivateCandidate(id); var backups = Path.Combine(scope.UpdatesRoot, "Backups"); var backup = storage.Backup(id);
        foreach (var path in new[] { scope.UpdatesRoot, transactions, candidate, backups, backup }) AssertDirectoryDescriptor(path, PathsEqual(path, transactions));
        AssertFileDescriptor(Path.Combine(candidate, FixedServiceReleaseFiles.AllNames[0])); AssertFileDescriptor(Path.Combine(backup, FixedServiceReleaseFiles.AllNames[0]));
    }

    [DataTestMethod]
    [DataRow("candidate", 1)]
    [DataRow("candidate", 2)]
    [DataRow("candidate", 3)]
    [DataRow("backup", 2)]
    [DataRow("backup", 3)]
    public async Task Directory_acl_failure_keeps_fixed_copy_non_authoritative(string kind, int aclCall)
    {
        await using var scope = new Scope();
        var operations = new Operations { ThrowDirectoryAclAt = aclCall };
        var storage = CreateStorage(scope, applyAcls: true, operations);
        const string id = "0123456789abcdef0123456789abcdef";
        string destination;
        if (kind == "candidate")
        {
            await CreateFixedReleaseAsync(Path.Combine(scope.UpdatesRoot, "Staged", "candidate"), "candidate-");
            destination = storage.PrivateCandidate(id);
            await Assert.ThrowsExceptionAsync<IOException>(() => storage.CopyStagedToPrivateAsync(id, CancellationToken.None));
        }
        else
        {
            await CreateFixedReleaseAsync(scope.InstalledRoot, "backup-");
            destination = storage.Backup(id);
            await Assert.ThrowsExceptionAsync<IOException>(() => storage.CopyInstalledToBackupAsync(id, CancellationToken.None));
        }
        Assert.AreEqual(aclCall, operations.DirectoryAcls.Count);
        AssertNotExactRelease(destination);
    }

    [DataTestMethod]
    [DataRow("candidate", 1)]
    [DataRow("candidate", 5)]
    [DataRow("candidate", 9)]
    [DataRow("backup", 1)]
    [DataRow("backup", 5)]
    [DataRow("backup", 9)]
    public async Task File_acl_failure_cleans_fixed_copy_and_keeps_it_non_authoritative(string kind, int fileCall)
    {
        await using var scope = new Scope();
        var operations = new Operations { ThrowFileAclAt = fileCall };
        var storage = CreateStorage(scope, applyAcls: true, operations);
        const string id = "0123456789abcdef0123456789abcdef";
        string destination;
        if (kind == "candidate")
        {
            await CreateFixedReleaseAsync(Path.Combine(scope.UpdatesRoot, "Staged", "candidate"), "candidate-");
            destination = storage.PrivateCandidate(id);
            await Assert.ThrowsExceptionAsync<IOException>(() => storage.CopyStagedToPrivateAsync(id, CancellationToken.None));
        }
        else
        {
            await CreateFixedReleaseAsync(scope.InstalledRoot, "backup-");
            destination = storage.Backup(id);
            await Assert.ThrowsExceptionAsync<IOException>(() => storage.CopyInstalledToBackupAsync(id, CancellationToken.None));
        }
        Assert.AreEqual(fileCall, operations.FileAcls.Count);
        Assert.IsFalse(Directory.Exists(destination));
        Assert.ThrowsException<DirectoryNotFoundException>(() => OfflineReleaseVerifier.ValidateExactSet(destination));
    }

    private static OfflineUpdateStorage CreateStorage(
        Scope scope,
        bool applyAcls = false,
        IOfflineUpdateFileOperations? operations = null) =>
        new(scope.UpdatesRoot, scope.InstalledRoot, applyAcls, operations ?? WindowsOfflineUpdateFileOperations.Instance);

    private static bool PathsEqual(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);

    private static bool IsAtOrUnder(string root, string path) =>
        PathsEqual(root, path) || IsUnder(root, path);

    private static bool IsUnder(string root, string path) =>
        Path.GetFullPath(path).StartsWith(Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    private static async Task CreateFixedReleaseAsync(string root, string contentPrefix)
    {
        Directory.CreateDirectory(root);
        foreach (var name in FixedServiceReleaseFiles.AllNames)
            await File.WriteAllTextAsync(Path.Combine(root, name), contentPrefix + name);
    }

    private static void AssertNotExactRelease(string root)
    {
        try
        {
            OfflineReleaseVerifier.ValidateExactSet(root);
            Assert.Fail("An incomplete fixed release was accepted.");
        }
        catch (InvalidDataException) { }
        catch (DirectoryNotFoundException) { }
    }

    private static void AssertDirectoryDescriptor(string path, bool localService)
    {
        var security = new System.IO.DirectoryInfo(path).GetAccessControl(); Assert.IsTrue(security.AreAccessRulesProtected);
        AssertDescriptorRules(security.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier)), localService, true);
    }
    private static void AssertFileDescriptor(string path)
    {
        var security = new System.IO.FileInfo(path).GetAccessControl(); Assert.IsTrue(security.AreAccessRulesProtected);
        AssertDescriptorRules(security.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier)), false, false);
    }
    private static void AssertDescriptorRules(System.Security.AccessControl.AuthorizationRuleCollection rules, bool localService, bool directory)
    {
        var admin = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null); var system = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null); var service = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalServiceSid, null);
        var access = rules.Cast<System.Security.AccessControl.FileSystemAccessRule>().Where(r => r.AccessControlType == System.Security.AccessControl.AccessControlType.Allow && !r.IsInherited).ToArray();
        Assert.IsTrue(access.Any(r => r.IdentityReference == admin && r.FileSystemRights == System.Security.AccessControl.FileSystemRights.FullControl)); Assert.IsTrue(access.Any(r => r.IdentityReference == system && r.FileSystemRights == System.Security.AccessControl.FileSystemRights.FullControl));
        var localServiceRights = System.Security.AccessControl.FileSystemRights.Modify | System.Security.AccessControl.FileSystemRights.Synchronize;
        Assert.AreEqual(
            localService,
            access.Any(r => r.IdentityReference == service && r.FileSystemRights == localServiceRights),
            $"category={(directory ? "directory" : "file")}; expected-localservice={localService}; expected-inheritance={(directory ? System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit : System.Security.AccessControl.InheritanceFlags.None)}; expected-propagation={System.Security.AccessControl.PropagationFlags.None}; actual={DescribeRules(rules)}");
        var expectedInheritance = directory ? System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit : System.Security.AccessControl.InheritanceFlags.None;
        Assert.IsTrue(access.Where(r => r.IdentityReference == admin || r.IdentityReference == system || r.IdentityReference == service).All(r => r.InheritanceFlags == expectedInheritance && r.PropagationFlags == System.Security.AccessControl.PropagationFlags.None), DescribeRules(rules));
    }
    private static string DescribeRules(System.Security.AccessControl.AuthorizationRuleCollection rules) => string.Join("; ", rules.Cast<System.Security.AccessControl.FileSystemAccessRule>().Select(r => $"sid={r.IdentityReference.Value},rights={r.FileSystemRights},type={r.AccessControlType},inherited={r.IsInherited},inheritance={r.InheritanceFlags},propagation={r.PropagationFlags}"));

    private sealed class Operations : IOfflineUpdateFileOperations
    {
        internal int Attributes; internal bool ThrowAttributes; internal bool ThrowCreate; internal bool ApplyRealAcls { get; init; } internal int? ThrowDirectoryAclAt; internal int? ThrowFileAclAt; internal List<string> Created { get; } = [];
        internal List<(string Path, bool AllowLocalService)> DirectoryAcls { get; } = [];
        internal List<(string Path, bool AllowLocalService)> FileAcls { get; } = [];
        internal List<string> ContentCalls { get; } = [];
        internal List<(string Source, string Destination)> CopiedPaths { get; } = [];
        internal List<string> FlushedPaths { get; } = [];
        internal Dictionary<string, long> CompletedCopies { get; } = [];
        internal List<string> CompletedFlushes { get; } = [];
        internal int? FailFlushAt;
        internal string? FailedFlushPath;
        internal bool FailedFlushAsyncCompleted;
        internal bool FlushDestinationWasExclusivelyOpen;
        internal int? PartialCopyAt;
        internal int PartialBytesWritten;
        internal bool PartialDestinationWasExclusivelyOpen;
        internal int? CancelCopyAt;
        internal TaskCompletionSource CopyPending { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal CancellationToken ActiveCopyToken;
        internal int ActiveCopyBytes;
        internal bool ActiveDestinationWasExclusivelyOpen;
        internal bool ActiveCancellationObserved;
        public async Task CopyFixedFileContentsAsync(FileStream source, FileStream destination, CancellationToken token)
        {
            Assert.IsTrue(source.CanRead && destination.CanWrite);
            ContentCalls.Add("copy:" + Path.GetFileName(destination.Name));
            CopiedPaths.Add((source.Name, destination.Name));
            if (CancelCopyAt == CopiedPaths.Count)
            {
                ActiveCopyToken = token;
                Assert.IsTrue(token.CanBeCanceled);
                Assert.IsFalse(token.IsCancellationRequested);
                var bytes = new byte[4096];
                Assert.IsTrue(source.Length > bytes.Length);
                await source.ReadExactlyAsync(bytes, token);
                await destination.WriteAsync(bytes, token);
                Assert.AreEqual((long)bytes.Length, destination.Position);
                Assert.AreEqual((long)bytes.Length, destination.Length);
                ActiveCopyBytes = bytes.Length;
                var sharingFailure = Assert.ThrowsException<IOException>(() =>
                {
                    using var secondOpen = new FileStream(destination.Name, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                });
                Assert.AreEqual(0x80070020u, unchecked((uint)sharingFailure.HResult));
                ActiveDestinationWasExclusivelyOpen = true;
                // Coordinate cancellation in the provider, not an OS interruption of CopyToAsync.
                var pending = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var boundary = pending.Task.WaitAsync(TimeSpan.FromSeconds(10), token);
                CopyPending.SetResult();
                try { await boundary; }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    ActiveCancellationObserved = true;
                    Assert.IsTrue(source.CanRead && destination.CanWrite);
                    throw;
                }
                Assert.Fail("The active copy boundary must terminate through cancellation.");
            }
            if (PartialCopyAt == CopiedPaths.Count)
            {
                var bytes = new byte[4096];
                Assert.IsTrue(source.Length > bytes.Length);
                await source.ReadExactlyAsync(bytes, token);
                await destination.WriteAsync(bytes, token);
                Assert.AreEqual((long)bytes.Length, destination.Position);
                Assert.AreEqual((long)bytes.Length, destination.Length);
                PartialBytesWritten = bytes.Length;
                var sharingFailure = Assert.ThrowsException<IOException>(() =>
                {
                    using var secondOpen = new FileStream(destination.Name, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                });
                Assert.AreEqual(0x80070020u, unchecked((uint)sharingFailure.HResult));
                PartialDestinationWasExclusivelyOpen = true;
                Assert.IsTrue(source.CanRead && destination.CanWrite);
                throw new IOException("Test-only partial-copy failure.");
            }
            await WindowsOfflineUpdateFileOperations.Instance.CopyFixedFileContentsAsync(source, destination, token);
            Assert.IsTrue(source.CanRead && destination.CanWrite);
            Assert.AreEqual(source.Length, source.Position);
            Assert.AreEqual(source.Length, destination.Position);
            Assert.AreEqual(source.Length, destination.Length);
            CompletedCopies.Add(destination.Name, destination.Length);
        }
        public async Task FlushFixedFileToDiskAsync(FileStream destination, CancellationToken token)
        {
            Assert.IsTrue(destination.CanWrite);
            ContentCalls.Add("flush:" + Path.GetFileName(destination.Name));
            FlushedPaths.Add(destination.Name);
            if (FailFlushAt == FlushedPaths.Count)
            {
                Assert.IsTrue(CompletedCopies.TryGetValue(destination.Name, out var copiedLength));
                Assert.IsTrue(copiedLength > 0);
                Assert.AreEqual(copiedLength, destination.Length);
                Assert.AreEqual(copiedLength, destination.Position);
                await destination.FlushAsync(token);
                FailedFlushAsyncCompleted = true;
                FailedFlushPath = destination.Name;
                var sharingFailure = Assert.ThrowsException<IOException>(() =>
                {
                    using var secondOpen = new FileStream(destination.Name, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                });
                Assert.AreEqual(0x80070020u, unchecked((uint)sharingFailure.HResult));
                FlushDestinationWasExclusivelyOpen = true;
                Assert.IsTrue(destination.CanWrite);
                // Deliberately fail before the explicit Flush(true) call. This tests
                // orchestration and cleanup, not physical persistence or hardware failure.
                throw new IOException("Test-only durable-flush failure after FlushAsync.");
            }
            await WindowsOfflineUpdateFileOperations.Instance.FlushFixedFileToDiskAsync(destination, token);
            Assert.IsTrue(destination.CanWrite);
            CompletedFlushes.Add(destination.Name);
        }
        public void CreateFixedDirectory(string path) { Created.Add(path); if (ThrowCreate) throw new IOException(); Directory.CreateDirectory(path); }
        public FileAttributes GetAttributes(string path) { Attributes++; if (ThrowAttributes) throw new IOException(); return File.GetAttributes(path); }
        public void ApplyProtectedDirectoryAcl(string path, bool allowLocalService)
        {
            DirectoryAcls.Add((Path.GetFullPath(path), allowLocalService));
            if (ThrowDirectoryAclAt == DirectoryAcls.Count) throw new IOException("Test-only directory ACL failure.");
            if (ApplyRealAcls) WindowsOfflineUpdateFileOperations.Instance.ApplyProtectedDirectoryAcl(path, allowLocalService);
        }
        public void ApplyProtectedFileAcl(string path, bool allowLocalService)
        {
            FileAcls.Add((Path.GetFullPath(path), allowLocalService));
            if (ThrowFileAclAt == FileAcls.Count) throw new IOException("Test-only file ACL failure.");
            if (ApplyRealAcls) WindowsOfflineUpdateFileOperations.Instance.ApplyProtectedFileAcl(path, allowLocalService);
        }
    }
    private sealed class Scope : IDisposable, IAsyncDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-update-" + Guid.NewGuid().ToString("N"));
        internal string UpdatesRoot => Path.Combine(Root, "Updates");
        internal string InstalledRoot => Path.Combine(Root, "Installed");
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, true); }
        public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
    }
}
