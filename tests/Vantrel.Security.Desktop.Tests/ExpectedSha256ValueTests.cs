using System.Security.Cryptography;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class ExpectedSha256ValueTests
{
    [TestMethod]
    public void Exactly_64_ascii_hexadecimal_characters_are_accepted_case_insensitively()
    {
        const string lowercase = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        Assert.IsTrue(ExpectedSha256Value.TryParse(lowercase, out var expected));
        Assert.IsTrue(expected.Matches(lowercase.ToUpperInvariant()));
    }

    [DataTestMethod]
    [DataRow("")]
    [DataRow(" BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    [DataRow("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD ")]
    [DataRow("SHA256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    [DataRow("BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD")]
    [DataRow("BA78-16BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    [DataRow("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015A")]
    [DataRow("ＢＡ７８１６ＢＦ８Ｆ０１ＣＦＥＡ４１４１４０ＤＥ５ＤＡＥ２２２３Ｂ００３６１Ａ３９６１７７Ａ９ＣＢ４１０ＦＦ６１Ｆ２００１５ＡＤ")]
    [DataRow("GA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    public void Whitespace_prefixes_separators_nonascii_wrong_length_and_nonhex_are_rejected(string value)
    {
        Assert.IsFalse(ExpectedSha256Value.TryParse(value, out _));
    }
}

[TestClass]
public sealed class LocalFileFingerprintComparisonInspectorTests
{
    [TestMethod]
    public async Task Newly_computed_fingerprint_matches_or_mismatches_case_insensitively()
    {
        using var root = new DisposableRoot();
        var path = root.File("sample.bin", "abc"u8.ToArray());
        Assert.IsTrue(ExpectedSha256Value.TryParse("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", out var match));
        Assert.IsTrue(ExpectedSha256Value.TryParse(new string('A', 64), out var mismatch));
        var inspector = new LocalFileFingerprintComparisonInspector();

        Assert.AreEqual(FileFingerprintComparisonOutcome.Match, (await inspector.CompareAsync(path, match, CancellationToken.None)).Outcome);
        Assert.AreEqual(FileFingerprintComparisonOutcome.Mismatch, (await inspector.CompareAsync(path, mismatch, CancellationToken.None)).Outcome);
    }

    [TestMethod]
    public async Task Rejected_directory_path_never_publishes_a_match_or_file_data()
    {
        using var root = new DisposableRoot();
        Assert.IsTrue(ExpectedSha256Value.TryParse(new string('A', 64), out var expected));

        var result = await new LocalFileFingerprintComparisonInspector().CompareAsync(root.Path, expected, CancellationToken.None);

        Assert.AreEqual(FileFingerprintComparisonOutcome.Declined, result.Outcome);
        Assert.IsFalse(result.Outcome is FileFingerprintComparisonOutcome.Match or FileFingerprintComparisonOutcome.Mismatch);
        CollectionAssert.AreEqual(new[] { "Outcome" }, typeof(FileFingerprintComparisonResult).GetProperties().Select(property => property.Name).ToArray());
    }

    [TestMethod]
    public async Task Comparison_rehashes_the_file_instead_of_reusing_an_earlier_fingerprint()
    {
        using var root = new DisposableRoot();
        var path = root.File("changing.bin", "old"u8.ToArray());
        var earlier = await new LocalFileFingerprintInspector().InspectAsync(path, CancellationToken.None);
        File.WriteAllBytes(path, "new"u8.ToArray());
        Assert.IsTrue(ExpectedSha256Value.TryParse(Convert.ToHexString(SHA256.HashData("new"u8.ToArray())), out var expected));

        var result = await new LocalFileFingerprintComparisonInspector().CompareAsync(path, expected, CancellationToken.None);

        Assert.AreEqual(FileFingerprintInspectionOutcome.Completed, earlier.Outcome);
        Assert.AreEqual(FileFingerprintComparisonOutcome.Match, result.Outcome);
    }

    [TestMethod]
    public async Task Mutation_during_comparison_publishes_no_match_or_mismatch()
    {
        using var root = new DisposableRoot();
        var path = root.File("changing.bin", new byte[128 * 1024]);
        Assert.IsTrue(ExpectedSha256Value.TryParse(new string('A', 64), out var expected));
        using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        var inspector = new LocalFileFingerprintComparisonInspector(afterFirstReadAsync: _ =>
        {
            writer.SetLength(0);
            writer.Write("changed"u8);
            writer.Flush(flushToDisk: true);
            return Task.CompletedTask;
        });

        var result = await inspector.CompareAsync(path, expected, CancellationToken.None);

        Assert.AreEqual(FileFingerprintComparisonOutcome.Changed, result.Outcome);
    }

    [TestMethod]
    public async Task Cancellation_propagates_without_a_comparison_result()
    {
        using var root = new DisposableRoot();
        var path = root.File("cancel.bin", new byte[128 * 1024]);
        Assert.IsTrue(ExpectedSha256Value.TryParse(new string('A', 64), out var expected));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        var inspector = new LocalFileFingerprintComparisonInspector(afterFirstReadAsync: token =>
        {
            entered.TrySetResult();
            return Task.Delay(Timeout.InfiniteTimeSpan, token);
        });

        var comparison = inspector.CompareAsync(path, expected, cancellation.Token);
        await entered.Task;
        cancellation.Cancel();

        try
        {
            await comparison;
            Assert.Fail("Cancellation must not return a comparison result.");
        }
        catch (OperationCanceledException)
        {
        }
    }

    [TestMethod]
    public async Task Comparison_shares_the_single_in_flight_lease()
    {
        using var root = new DisposableRoot();
        var path = root.File("busy.bin", new byte[128 * 1024]);
        Assert.IsTrue(ExpectedSha256Value.TryParse(new string('A', 64), out var expected));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var coordinator = new LocalFileInspectionCoordinator();
        var first = new LocalFileFingerprintComparisonInspector(coordinator, afterFirstReadAsync: _ =>
        {
            entered.TrySetResult();
            return release.Task;
        });
        var second = new LocalFileFingerprintComparisonInspector(coordinator);

        var firstTask = first.CompareAsync(path, expected, CancellationToken.None);
        await entered.Task;
        var secondResult = await second.CompareAsync(path, expected, CancellationToken.None);
        release.TrySetResult();

        Assert.AreEqual(FileFingerprintComparisonOutcome.AlreadyInProgress, secondResult.Outcome);
        Assert.AreEqual(FileFingerprintComparisonOutcome.Mismatch, (await firstTask).Outcome);
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
}
