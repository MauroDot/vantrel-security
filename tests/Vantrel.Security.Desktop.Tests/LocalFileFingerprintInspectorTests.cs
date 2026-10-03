using System.Security.Cryptography;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class LocalFileFingerprintInspectorTests
{
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);

    [TestMethod]
    public async Task Regular_file_returns_its_name_byte_count_and_known_sha256()
    {
        using var root = new DisposableRoot();
        var path = root.File("sample.bin", "abc"u8.ToArray());

        var result = await new LocalFileFingerprintInspector().InspectAsync(path, CancellationToken.None);

        Assert.AreEqual(FileFingerprintInspectionOutcome.Completed, result.Outcome);
        Assert.AreEqual("sample.bin", result.FileName);
        Assert.AreEqual(3L, result.ByteLength);
        Assert.AreEqual("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", result.Sha256);
    }

    [TestMethod]
    public async Task Directory_unc_and_device_selections_are_declined()
    {
        using var root = new DisposableRoot();
        var inspector = new LocalFileFingerprintInspector();

        Assert.AreEqual(FileFingerprintInspectionOutcome.Declined,
            (await inspector.InspectAsync(root.Path, CancellationToken.None)).Outcome);
        Assert.AreEqual(FileFingerprintInspectionOutcome.Declined,
            (await inspector.InspectAsync("\\\\server\\share\\sample.bin", CancellationToken.None)).Outcome);
        Assert.AreEqual(FileFingerprintInspectionOutcome.Declined,
            (await inspector.InspectAsync("\\\\.\\NUL", CancellationToken.None)).Outcome);
    }

    [TestMethod]
    public async Task Reparse_point_is_declined_when_the_test_host_allows_one()
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

        var result = await new LocalFileFingerprintInspector().InspectAsync(link, CancellationToken.None);

        Assert.AreEqual(FileFingerprintInspectionOutcome.Declined, result.Outcome);
    }

    [TestMethod]
    public async Task Reparse_ancestor_is_declined_when_the_test_host_allows_one()
    {
        using var root = new DisposableRoot();
        var targetDirectory = Path.Combine(root.Path, "target");
        Directory.CreateDirectory(targetDirectory);
        root.File(Path.Combine("target", "target.bin"), "content"u8.ToArray());
        var redirectedDirectory = Path.Combine(root.Path, "redirected");
        try
        {
            Directory.CreateSymbolicLink(redirectedDirectory, targetDirectory);
        }
        catch (Exception error) when (IsPrivilegeNotHeld(error))
        {
            Assert.Inconclusive("The test host does not permit symbolic-link creation.");
            return;
        }

        var result = await new LocalFileFingerprintInspector().InspectAsync(
            Path.Combine(redirectedDirectory, "target.bin"), CancellationToken.None);

        Assert.AreEqual(FileFingerprintInspectionOutcome.Declined, result.Outcome);
        Assert.IsNull(result.Sha256);
    }

    [TestMethod]
    public async Task Normal_nonreparse_ancestor_path_still_returns_a_fingerprint()
    {
        using var root = new DisposableRoot();
        Directory.CreateDirectory(Path.Combine(root.Path, "ordinary"));
        var path = root.File(Path.Combine("ordinary", "sample.bin"), "abc"u8.ToArray());

        var result = await new LocalFileFingerprintInspector().InspectAsync(path, CancellationToken.None);

        Assert.AreEqual(FileFingerprintInspectionOutcome.Completed, result.Outcome);
        Assert.AreEqual("sample.bin", result.FileName);
    }

    [TestMethod]
    public async Task Redirect_after_textual_validation_is_rejected_by_final_handle_path_when_supported()
    {
        using var root = new DisposableRoot();
        var ordinaryDirectory = Path.Combine(root.Path, "ordinary");
        var targetDirectory = Path.Combine(root.Path, "target");
        Directory.CreateDirectory(ordinaryDirectory);
        Directory.CreateDirectory(targetDirectory);
        var selectedPath = root.File(Path.Combine("ordinary", "sample.bin"), "original"u8.ToArray());
        root.File(Path.Combine("target", "sample.bin"), "redirected"u8.ToArray());
        var redirected = false;
        var privilegeUnavailable = false;
        var inspector = new LocalFileFingerprintInspector(afterPathValidationAsync: _ =>
        {
            File.Delete(selectedPath);
            Directory.Delete(ordinaryDirectory);
            try
            {
                Directory.CreateSymbolicLink(ordinaryDirectory, targetDirectory);
                redirected = true;
            }
            catch (Exception error) when (IsPrivilegeNotHeld(error))
            {
                privilegeUnavailable = true;
            }
            return Task.CompletedTask;
        });

        var result = await inspector.InspectAsync(selectedPath, CancellationToken.None);

        if (!redirected)
        {
            Assert.IsTrue(privilegeUnavailable, "Only missing symbolic-link privilege may skip this test.");
            Assert.Inconclusive("The test host does not permit symbolic-link creation.");
            return;
        }

        Assert.AreEqual(FileFingerprintInspectionOutcome.Declined, result.Outcome);
        Assert.IsNull(result.Sha256);
    }

    [TestMethod]
    public async Task File_above_the_fixed_limit_is_declined_without_hashing()
    {
        using var root = new DisposableRoot();
        var path = Path.Combine(root.Path, "large.bin");
        await using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            stream.SetLength(LocalFileFingerprintInspector.MaximumByteLength + 1);

        var result = await new LocalFileFingerprintInspector().InspectAsync(path, CancellationToken.None);

        Assert.AreEqual(FileFingerprintInspectionOutcome.Declined, result.Outcome);
        Assert.IsNull(result.FileName);
    }

    [TestMethod]
    public async Task Open_failure_is_reported_without_file_details()
    {
        using var root = new DisposableRoot();
        var path = root.File("locked.bin", "content"u8.ToArray());
        using var lockHandle = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var result = await new LocalFileFingerprintInspector().InspectAsync(path, CancellationToken.None);

        Assert.AreEqual(FileFingerprintInspectionOutcome.Unavailable, result.Outcome);
        Assert.IsNull(result.FileName);
    }

    [TestMethod]
    public async Task Cancellation_propagates_and_does_not_return_a_fingerprint()
    {
        using var root = new DisposableRoot();
        var path = root.File("cancel.bin", new byte[128 * 1024]);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var inspector = new LocalFileFingerprintInspector(token =>
        {
            entered.TrySetResult();
            return Task.Delay(Timeout.InfiniteTimeSpan, token);
        });
        using var cancellation = new CancellationTokenSource();

        var inspection = inspector.InspectAsync(path, cancellation.Token);
        await entered.Task;
        cancellation.Cancel();

        try
        {
            await inspection;
            Assert.Fail("Cancellation must not return a fingerprint.");
        }
        catch (OperationCanceledException)
        {
        }
    }

    [TestMethod]
    public async Task Only_one_inspection_can_run_at_a_time()
    {
        using var root = new DisposableRoot();
        var path = root.File("busy.bin", new byte[128 * 1024]);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var inspector = new LocalFileFingerprintInspector(_ =>
        {
            entered.TrySetResult();
            return release.Task;
        });

        var first = inspector.InspectAsync(path, CancellationToken.None);
        await entered.Task;
        var second = await inspector.InspectAsync(path, CancellationToken.None);
        release.TrySetResult();

        Assert.AreEqual(FileFingerprintInspectionOutcome.AlreadyInProgress, second.Outcome);
        Assert.AreEqual(FileFingerprintInspectionOutcome.Completed, (await first).Outcome);
    }

    [TestMethod]
    public async Task Mutation_during_hashing_returns_no_fingerprint()
    {
        using var root = new DisposableRoot();
        var path = root.File("changing.bin", new byte[128 * 1024]);
        using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        var inspector = new LocalFileFingerprintInspector(_ =>
        {
            writer.SetLength(0);
            writer.Write("changed"u8);
            writer.Flush(flushToDisk: true);
            return Task.CompletedTask;
        });

        var result = await inspector.InspectAsync(path, CancellationToken.None);

        Assert.AreEqual(FileFingerprintInspectionOutcome.Changed, result.Outcome);
        Assert.IsNull(result.FileName);
        Assert.IsNull(result.Sha256);
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

        public void Dispose()
        {
            if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true);
        }
    }

    private static bool IsPrivilegeNotHeld(Exception error) => error.HResult == PrivilegeNotHeldHResult;
}
