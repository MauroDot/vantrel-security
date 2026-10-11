using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2BuildProvenanceTests
{
    private const string Commit = "0123456789abcdef0123456789abcdef01234567";

    [TestMethod]
    public void Clean_exact_checkout_runs_locked_win_x64_restore_before_returning_bound_identity()
    {
        using var fixture = new Fixture();
        var result = ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(
            fixture.Root, Commit, fixture.Runner);

        Assert.AreEqual(Commit, result.SourceCommit);
        Assert.AreEqual("10.0.401", result.SdkVersion);
        Assert.AreEqual(fixture.SourceLockHash, result.SourceLockSha256);
        Assert.AreEqual("net10.0-windows", result.TargetFramework);
        Assert.AreEqual("win-x64", result.RuntimeIdentifier);
        Assert.AreEqual("framework-dependent", result.Deployment);
        Assert.AreEqual(1, fixture.Runner.RestoreCount);
        Assert.IsTrue(fixture.Runner.Calls.FindIndex(call => call.Contains("status")) <
            fixture.Runner.Calls.FindIndex(call => call.Contains("restore")));
        var restoreCall = fixture.Runner.Calls.Single(call => call.StartsWith("dotnet restore ",
            StringComparison.Ordinal));
        StringAssert.Contains(restoreCall, "--locked-mode");
        StringAssert.Contains(restoreCall, "--runtime win-x64");
    }

    [TestMethod]
    public void Tracked_untracked_and_ignored_residue_each_decline_before_restore_without_names()
    {
        foreach (var status in new[] { " M global.json", "?? stray.txt", "!! bin/" })
        {
            using var fixture = new Fixture();
            fixture.Runner.Status = status;
            var error = Assert.ThrowsException<IOException>(() =>
                ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(fixture.Root, Commit, fixture.Runner));
            Assert.AreEqual("V2 release build inputs are unavailable or invalid.", error.Message);
            Assert.IsFalse(error.Message.Contains(status, StringComparison.Ordinal));
            Assert.AreEqual(0, fixture.Runner.RestoreCount);
        }
    }

    [TestMethod]
    public void Wrong_head_or_noncommit_object_declines_before_restore()
    {
        using (var fixture = new Fixture())
        {
            fixture.Runner.Head = "fedcba9876543210fedcba9876543210fedcba98";
            AssertClosedBeforeRestore(fixture);
        }
        using (var fixture = new Fixture())
        {
            fixture.Runner.ObjectType = "tag";
            AssertClosedBeforeRestore(fixture);
        }
        using (var fixture = new Fixture())
        {
            fixture.Runner.GitRoot = fixture.Root + "-other";
            AssertClosedBeforeRestore(fixture);
        }
        using (var fixture = new Fixture())
        {
            Assert.ThrowsException<IOException>(() =>
                ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(fixture.Root, "0123456", fixture.Runner));
            Assert.AreEqual(0, fixture.Runner.RestoreCount);
        }
    }

    [TestMethod]
    public void Exact_global_sdk_rollforward_and_installed_sdk_are_required()
    {
        foreach (var global in new[]
        {
            "{\"sdk\":{\"version\":\"10.0.402\",\"rollForward\":\"disable\"}}",
            "{\"sdk\":{\"version\":\"10.0.401\",\"rollForward\":\"latestPatch\"}}",
            "{\"sdk\":{\"version\":\"10.0.401\",\"rollForward\":\"disable\",\"allowPrerelease\":true}}",
            "{\"sdk\":{\"version\":\"10.0.401\",\"version\":\"10.0.401\",\"rollForward\":\"disable\"}}"
        })
        {
            using var fixture = new Fixture();
            File.WriteAllText(Path.Combine(fixture.Root, "global.json"), global);
            AssertClosedBeforeRestore(fixture);
        }
        using (var fixture = new Fixture())
        {
            fixture.Runner.Sdk = "10.0.402";
            AssertClosedBeforeRestore(fixture);
        }
    }

    [TestMethod]
    public void Locked_restore_failure_and_wrong_project_identity_decline()
    {
        using (var fixture = new Fixture())
        {
            fixture.Runner.RestoreExit = 1;
            Assert.ThrowsException<IOException>(() =>
                ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(fixture.Root, Commit, fixture.Runner));
            Assert.AreEqual(1, fixture.Runner.RestoreCount);
        }
        foreach (var tfm in new[] { "net9.0-windows", "net10.0" })
        {
            using var fixture = new Fixture();
            File.WriteAllText(fixture.ServiceProject,
                "<Project><PropertyGroup><TargetFramework>" + tfm + "</TargetFramework></PropertyGroup></Project>");
            AssertClosedBeforeRestore(fixture);
        }
        using (var fixture = new Fixture())
        {
            File.WriteAllText(fixture.ServiceProject,
                "<Project><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework>" +
                "<SelfContained>true</SelfContained></PropertyGroup></Project>");
            AssertClosedBeforeRestore(fixture);
        }
        using (var fixture = new Fixture())
        {
            File.WriteAllText(fixture.ServiceProject,
                "<!DOCTYPE Project [<!ENTITY external SYSTEM 'file:///C:/Windows/win.ini'>]>" +
                "<Project><PropertyGroup><TargetFramework>&external;</TargetFramework></PropertyGroup></Project>");
            AssertClosedBeforeRestore(fixture);
        }
    }

    [TestMethod]
    public void Source_lock_is_tracked_and_hash_bound_during_restore()
    {
        using var fixture = new Fixture();
        fixture.Runner.OnRestore = () =>
        {
            Assert.ThrowsException<IOException>(() => File.AppendAllText(fixture.ServiceLock, "tamper"));
        };
        var result = ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(
            fixture.Root, Commit, fixture.Runner);
        Assert.AreEqual(fixture.SourceLockHash, result.SourceLockSha256);
        Assert.AreEqual(fixture.SourceLockHash,
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fixture.ServiceLock))));

        using var untracked = new Fixture();
        untracked.Runner.UntrackedLock = true;
        AssertClosedBeforeRestore(untracked);
    }

    [TestMethod]
    public void Real_git_clean_exact_head_and_legitimate_crlf_checkout_pass()
    {
        using var fixture = new RealGitFixture();
        Assert.IsTrue(fixture.Status().Length == 0);
        Assert.IsTrue(File.ReadAllBytes(fixture.SourceFile).AsSpan().IndexOf("\r\n"u8) >= 0);

        var result = fixture.VerifyAndRestore();

        Assert.AreEqual(fixture.Head, result.SourceCommit);
        Assert.AreEqual(1, fixture.Runner.RestoreCount);
        ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(
            fixture.Root, fixture.Head, result.SourceLockSha256, fixture.Runner);
    }

    [TestMethod]
    public void Real_git_ordinary_and_staged_source_changes_decline_before_restore()
    {
        using (var fixture = new RealGitFixture())
        {
            fixture.ChangeSource();
            Assert.IsTrue(fixture.Status().Length != 0);
            fixture.AssertDeclinedBeforeRestore();
        }

        using (var fixture = new RealGitFixture())
        {
            fixture.ChangeSource();
            fixture.Git("add", "--", RealGitFixture.SourceRelative);
            Assert.IsTrue(fixture.Status().Length != 0);
            Assert.AreEqual(RealGitFixture.SourceRelative,
                Assert.ThrowsException<TrackedSourceProvenanceException>(() =>
                    ServiceReleaseV2BuildProvenancePreflight.RequireTrackedWorktreeMatchesHead(
                        fixture.Root, fixture.Head, fixture.Runner)).RelativePath);
            fixture.AssertDeclinedBeforeRestore();
        }

        using (var fixture = new RealGitFixture())
        {
            fixture.ChangeSource();
            fixture.Git("add", "--", RealGitFixture.SourceRelative);
            fixture.WriteOriginalSource();
            Assert.IsTrue(fixture.Status().Length != 0,
                "The index still differs from HEAD after the worktree is restored.");
            Assert.AreEqual(RealGitFixture.SourceRelative,
                Assert.ThrowsException<TrackedSourceProvenanceException>(() =>
                    ServiceReleaseV2BuildProvenancePreflight.RequireTrackedWorktreeMatchesHead(
                        fixture.Root, fixture.Head, fixture.Runner)).RelativePath);
            fixture.AssertDeclinedBeforeRestore();
        }
    }

    [TestMethod]
    public void Real_git_assume_unchanged_cannot_hide_changed_source_before_or_after_restore()
    {
        using (var fixture = new RealGitFixture())
        {
            fixture.Git("update-index", "--assume-unchanged", "--", RealGitFixture.SourceRelative);
            fixture.ChangeSource();
            Assert.AreEqual(string.Empty, fixture.Status(),
                "This test must exercise a change hidden from ordinary Git status.");
            fixture.AssertDeclinedBeforeRestore(affectedPath: RealGitFixture.SourceRelative);
        }

        using (var fixture = new RealGitFixture())
        {
            var result = fixture.VerifyAndRestore();
            fixture.Git("update-index", "--assume-unchanged", "--", RealGitFixture.SourceRelative);
            fixture.ChangeSource();
            Assert.AreEqual(string.Empty, fixture.Status());
            IOException? error = null;
            try
            {
                ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(
                    fixture.Root, fixture.Head, result.SourceLockSha256, fixture.Runner);
            }
            catch (IOException caught) { error = caught; }
            Assert.IsNotNull(error, "A hidden late source change must fail final binding.");
            StringAssert.Contains(error.Message, RealGitFixture.SourceRelative);
            Assert.IsFalse(error.Message.Contains(fixture.Root, StringComparison.OrdinalIgnoreCase));
        }
    }

    [TestMethod]
    public void Real_git_skip_worktree_cannot_hide_changed_source()
    {
        using var fixture = new RealGitFixture();
        fixture.Git("update-index", "--skip-worktree", "--", RealGitFixture.SourceRelative);
        fixture.ChangeSource();
        Assert.AreEqual(string.Empty, fixture.Status(),
            "This test must exercise a change hidden from ordinary Git status.");
        fixture.AssertDeclinedBeforeRestore(affectedPath: RealGitFixture.SourceRelative);
    }

    [TestMethod]
    public void Real_git_nonordinary_index_flags_are_rejected_even_without_content_changes()
    {
        foreach (var flag in new[] { "--assume-unchanged", "--skip-worktree" })
        {
            using var fixture = new RealGitFixture();
            fixture.Git("update-index", flag, "--", RealGitFixture.SourceRelative);
            Assert.AreEqual(string.Empty, fixture.Status());
            fixture.AssertDeclinedBeforeRestore(affectedPath: RealGitFixture.SourceRelative);
        }
    }

    [TestMethod]
    public void Real_git_missing_source_wrong_commit_and_noncanonical_content_decline()
    {
        using (var fixture = new RealGitFixture())
        {
            File.Delete(fixture.SourceFile);
            fixture.AssertDeclinedBeforeRestore();
        }

        using (var fixture = new RealGitFixture())
        {
            File.Delete(fixture.SourceFile);
            Directory.CreateDirectory(fixture.SourceFile);
            fixture.AssertDeclinedBeforeRestore();
        }

        using (var fixture = new RealGitFixture())
        {
            fixture.AssertDeclinedBeforeRestore(
                (fixture.Head[0] == '0' ? "1" : "0") + fixture.Head[1..]);
        }

        using (var fixture = new RealGitFixture())
        {
            // The source still has CRLF, but its content is no longer equivalent
            // to the committed LF blob under the repository's text attributes.
            fixture.ChangeSource();
            Assert.IsTrue(File.ReadAllBytes(fixture.SourceFile).AsSpan().IndexOf("\r\n"u8) >= 0);
            fixture.AssertDeclinedBeforeRestore();
        }
    }

    [TestMethod]
    public void Named_stream_on_any_tracked_source_file_is_rejected_before_and_after_restore()
    {
        using (var fixture = new Fixture())
        {
            var extra = fixture.AddTrackedSource();
            File.WriteAllText(extra + ":hidden", "not a build input");
            AssertClosedBeforeRestore(fixture);
        }
        using (var fixture = new Fixture())
        {
            var extra = fixture.AddTrackedSource();
            var result = ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(
                fixture.Root, Commit, fixture.Runner);
            File.WriteAllText(extra + ":hidden", "late stream");
            try
            {
                ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(
                    fixture.Root, Commit, result.SourceLockSha256, fixture.Runner);
                Assert.Fail("A late named stream must fail final source binding.");
            }
            catch (IOException error)
            {
                StringAssert.StartsWith(error.Message, "V2 release build inputs are unavailable or invalid.");
                Assert.IsFalse(error.Message.Contains(fixture.Root, StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    [TestMethod]
    public void Process_output_drain_is_bounded_for_either_pipe_and_sanitizes_failures()
    {
        var timeoutActions = 0;
        Assert.AreEqual("expected", SystemReleaseV2CommandRunner.CompleteDrains(
            Task.FromResult("expected"), Task.FromResult(string.Empty), 100, () => timeoutActions++));
        Assert.AreEqual(0, timeoutActions);

        foreach (var blockStdout in new[] { true, false })
        {
            var blocked = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var stdout = blockStdout ? blocked.Task : Task.FromResult("expected");
            var stderr = blockStdout ? Task.FromResult(string.Empty) : blocked.Task;
            var waiting = Task.Run(() => SystemReleaseV2CommandRunner.CompleteDrains(
                stdout, stderr, 25, () => Interlocked.Increment(ref timeoutActions)));
            try
            {
                Assert.AreSame(waiting, Task.WhenAny(waiting, Task.Delay(2_000)).GetAwaiter().GetResult());
                var error = Assert.ThrowsException<IOException>(() => waiting.GetAwaiter().GetResult());
                Assert.AreEqual("V2 release build command failed.", error.Message);
            }
            finally { blocked.TrySetResult(string.Empty); }
        }
        Assert.AreEqual(2, timeoutActions);

        var failed = Task.FromException<string>(new IOException("sensitive process output"));
        var sanitized = Assert.ThrowsException<IOException>(() =>
            SystemReleaseV2CommandRunner.CompleteDrains(failed, Task.FromResult(string.Empty),
                100, () => timeoutActions++));
        Assert.AreEqual("V2 release build command failed.", sanitized.Message);
        Assert.AreEqual(2, timeoutActions);
    }

    [TestMethod]
    public void Process_timeout_terminates_its_tree_and_normal_exit_does_not()
    {
        var terminations = 0;
        var error = Assert.ThrowsException<IOException>(() =>
            SystemReleaseV2CommandRunner.RequireProcessExit(milliseconds =>
            {
                Assert.AreEqual(25, milliseconds);
                return false;
            }, () => terminations++, 25));
        Assert.AreEqual("V2 release build command failed.", error.Message);
        Assert.AreEqual(1, terminations);

        SystemReleaseV2CommandRunner.RequireProcessExit(milliseconds =>
        {
            Assert.AreEqual(25, milliseconds);
            return true;
        }, () => terminations++, 25);
        Assert.AreEqual(1, terminations);
    }

    private static void AssertClosedBeforeRestore(Fixture fixture)
    {
        IOException? error = null;
        try { ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(fixture.Root, Commit, fixture.Runner); }
        catch (IOException caught) { error = caught; }
        Assert.IsNotNull(error, "The release preflight must decline before restore.");
        StringAssert.StartsWith(error.Message, "V2 release build inputs are unavailable or invalid.");
        Assert.IsFalse(error.Message.Contains(fixture.Root, StringComparison.OrdinalIgnoreCase));
        Assert.AreEqual(0, fixture.Runner.RestoreCount);
    }

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(),
            "vantrel-task073-provenance-" + Guid.NewGuid().ToString("N"));
        internal FakeRunner Runner { get; }
        internal string ServiceProject => Path.Combine(Root, "src", "Vantrel.Security.Service",
            "Vantrel.Security.Service.csproj");
        internal string ServiceLock => Path.Combine(Root, "src", "Vantrel.Security.Service", "packages.lock.json");
        internal string SourceLockHash => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(ServiceLock)));

        internal Fixture()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ServiceProject)!);
            File.WriteAllText(Path.Combine(Root, "global.json"),
                "{\"sdk\":{\"version\":\"10.0.401\",\"rollForward\":\"disable\"}}");
            File.WriteAllText(ServiceProject,
                "<Project><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework></PropertyGroup></Project>");
            File.WriteAllText(ServiceLock, "synthetic lock graph");
            File.WriteAllText(Path.Combine(Root, "Vantrel.Security.sln"), "synthetic solution");
            Runner = new FakeRunner(Root);
        }

        internal string AddTrackedSource()
        {
            var path = Path.Combine(Root, "src", "Vantrel.Security.Service", "Additional.cs");
            File.WriteAllText(path, "internal class Additional { }");
            Runner.IncludeExtraTracked = true;
            return path;
        }

        public void Dispose()
        {
            var root = Path.GetFullPath(Root);
            var temp = Path.GetFullPath(Path.GetTempPath());
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(root).StartsWith("vantrel-task073-provenance-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(root, recursive: true);
        }
    }

    private sealed class FakeRunner : IReleaseV2CommandRunner
    {
        private readonly string _root;
        internal FakeRunner(string root)
        {
            _root = root;
            GitRoot = root;
        }

        internal string Status { get; set; } = string.Empty;
        internal string Head { get; set; } = Commit;
        internal string ObjectType { get; set; } = "commit";
        internal string GitRoot { get; set; }
        internal string Sdk { get; set; } = "10.0.401";
        internal bool UntrackedLock { get; set; }
        internal bool IncludeExtraTracked { get; set; }
        internal int RestoreExit { get; set; }
        internal int RestoreCount { get; private set; }
        internal Action? OnRestore { get; set; }
        internal List<string> Calls { get; } = [];

        public ReleaseV2CommandResult Run(string executable, IReadOnlyList<string> arguments,
            string workingDirectory, bool captureStandardOutput)
        {
            Assert.AreEqual(_root, workingDirectory);
            var command = executable + " " + string.Join(" ", arguments);
            Calls.Add(command);
            if (executable == "git")
            {
                Assert.AreEqual("-C", arguments[0]);
                Assert.AreEqual(_root, arguments[1]);
                if (ServiceReleaseV2FakeGitProof.TryRun(arguments, _root, out var proof,
                    IncludeExtraTracked)) return proof;
                return arguments[2] switch
                {
                    "rev-parse" when arguments.Last() == "--show-toplevel" => new(0, GitRoot + "\n"),
                    "rev-parse" when arguments.Last() == "HEAD^{commit}" => new(0, Head + "\n"),
                    "cat-file" => new(0, ObjectType + "\n"),
                    "status" => new(0, Status),
                    "ls-files" when UntrackedLock && arguments.Last().EndsWith("packages.lock.json", StringComparison.Ordinal)
                        => new(1, string.Empty),
                    "ls-files" when arguments.Last() == "-z" => new(0,
                        "global.json\0src/Vantrel.Security.Service/Vantrel.Security.Service.csproj\0" +
                        "src/Vantrel.Security.Service/packages.lock.json\0Vantrel.Security.sln\0" +
                        (IncludeExtraTracked ? "src/Vantrel.Security.Service/Additional.cs\0" : string.Empty)),
                    "ls-files" => new(0, arguments.Last() + "\n"),
                    _ => throw new AssertFailedException("Unexpected Git command.")
                };
            }
            Assert.AreEqual("dotnet", executable);
            if (arguments.SequenceEqual(["--version"])) return new(0, Sdk + "\n");
            Assert.AreEqual("restore", arguments[0]);
            Assert.IsFalse(captureStandardOutput);
            RestoreCount++;
            OnRestore?.Invoke();
            return new(RestoreExit, string.Empty);
        }

        public ReleaseV2CommandResult RunWithInput(string executable, IReadOnlyList<string> arguments,
            string workingDirectory, Stream standardInput)
        {
            Assert.AreEqual(_root, workingDirectory);
            Assert.AreEqual("git", executable);
            Calls.Add(executable + " " + string.Join(" ", arguments));
            return ServiceReleaseV2FakeGitProof.RunWithInput(arguments, standardInput);
        }
    }

    private sealed class RealGitFixture : IDisposable
    {
        internal const string SourceRelative = "src/Vantrel.Security.Service/Tracked.cs";
        private const string OriginalSource = "internal static class Tracked { internal const int Value = 1; }\n";
        internal string Root { get; } = Path.Combine(Path.GetTempPath(),
            "vantrel-task073-real-git-" + Guid.NewGuid().ToString("N"));
        internal string SourceFile => Path.Combine(Root, SourceRelative.Replace('/', Path.DirectorySeparatorChar));
        internal string Head { get; }
        internal RealGitRunner Runner { get; } = new();

        internal RealGitFixture()
        {
            Directory.CreateDirectory(Root);
            Git("init", "--quiet");
            Git("config", "user.name", "Vantrel Test");
            Git("config", "user.email", "fixture@example.invalid");
            Git("config", "core.autocrlf", "true");
            Git("config", "core.filemode", "false");
            File.WriteAllText(Path.Combine(Root, ".gitattributes"), "*.cs text eol=crlf\n");
            File.WriteAllText(Path.Combine(Root, "global.json"),
                "{\"sdk\":{\"version\":\"10.0.401\",\"rollForward\":\"disable\"}}\n");
            var serviceDirectory = Path.GetDirectoryName(SourceFile)!;
            Directory.CreateDirectory(serviceDirectory);
            File.WriteAllText(Path.Combine(serviceDirectory, "Vantrel.Security.Service.csproj"),
                "<Project><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework></PropertyGroup></Project>\n");
            File.WriteAllText(Path.Combine(serviceDirectory, "packages.lock.json"), "synthetic lock graph\n");
            File.WriteAllText(Path.Combine(Root, "Vantrel.Security.sln"), "synthetic solution\n");
            File.WriteAllText(SourceFile, OriginalSource);
            Git("add", "--all");
            Git("commit", "--quiet", "-m", "disposable provenance fixture");
            Head = Git("rev-parse", "HEAD").Trim();
            Assert.AreEqual(40, Head.Length);
            File.Delete(SourceFile);
            Git("checkout-index", "--", SourceRelative);
            Git("add", "--", SourceRelative);
            Assert.AreEqual(string.Empty, Status(),
                "Attributes: " + Git("check-attr", "--all", "--", SourceRelative) +
                " Diff: " + Git("diff", "--numstat", "--", SourceRelative) +
                " Cached: " + Git("diff", "--cached", "--numstat", "--", SourceRelative) +
                " Again: " + Status() +
                " Blob: " + Git("rev-parse", "HEAD:" + SourceRelative) +
                " Worktree: " + Git("hash-object", "--path=" + SourceRelative, SourceRelative) +
                " CRLF: " + (File.ReadAllBytes(SourceFile).AsSpan().IndexOf("\r\n"u8) >= 0));
        }

        internal void WriteOriginalSource() =>
            File.WriteAllText(SourceFile, OriginalSource.Replace("\n", "\r\n", StringComparison.Ordinal));

        internal void ChangeSource() => File.WriteAllText(SourceFile,
            OriginalSource.Replace("Value = 1", "Value = 2", StringComparison.Ordinal)
                .Replace("\n", "\r\n", StringComparison.Ordinal));

        internal ServiceReleaseV2BuildProvenance VerifyAndRestore() =>
            ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(Root, Head, Runner);

        internal void AssertDeclinedBeforeRestore(string? expectedCommit = null, string? affectedPath = null)
        {
            IOException? error = null;
            try
            {
                ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(
                    Root, expectedCommit ?? Head, Runner);
            }
            catch (IOException caught) { error = caught; }
            Assert.IsNotNull(error, "The release preflight must decline before restore.");
            if (affectedPath is null)
                Assert.AreEqual("V2 release build inputs are unavailable or invalid.", error.Message);
            else
            {
                StringAssert.Contains(error.Message, affectedPath);
                Assert.IsFalse(error.Message.Contains(Root, StringComparison.OrdinalIgnoreCase));
            }
            Assert.AreEqual(0, Runner.RestoreCount);
        }

        internal string Status() => Git("status", "--porcelain=v1", "--untracked-files=all")
            .TrimEnd('\r', '\n');

        internal string Git(params string[] arguments)
        {
            var start = new ProcessStartInfo("git")
            {
                WorkingDirectory = Root, UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (var argument in arguments) start.ArgumentList.Add(argument);
            using var process = Process.Start(start) ?? throw new AssertFailedException("Git fixture failed to start.");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            Assert.IsTrue(process.WaitForExit(20_000), "Disposable Git operation timed out.");
            Assert.AreEqual(0, process.ExitCode, "Disposable Git operation failed.");
            _ = stderr.GetAwaiter().GetResult();
            return stdout.GetAwaiter().GetResult();
        }

        public void Dispose()
        {
            var root = Path.GetFullPath(Root);
            var temp = Path.GetFullPath(Path.GetTempPath());
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(root).StartsWith("vantrel-task073-real-git-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(root, "*",
                    SearchOption.AllDirectories))
                {
                    var attributes = File.GetAttributes(entry);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                        throw new AssertFailedException("A disposable Git fixture contained a reparse point.");
                    if ((attributes & FileAttributes.ReadOnly) != 0)
                        File.SetAttributes(entry, attributes & ~FileAttributes.ReadOnly);
                }
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private sealed class RealGitRunner : IReleaseV2CommandRunner
    {
        private readonly SystemReleaseV2CommandRunner _git = new();
        internal int RestoreCount { get; private set; }

        public ReleaseV2CommandResult Run(string executable, IReadOnlyList<string> arguments,
            string workingDirectory, bool captureStandardOutput)
        {
            if (executable == "git") return _git.Run(executable, arguments, workingDirectory, captureStandardOutput);
            Assert.AreEqual("dotnet", executable);
            if (arguments.SequenceEqual(["--version"])) return new(0, "10.0.401\n");
            Assert.AreEqual("restore", arguments[0]);
            CollectionAssert.Contains(arguments.ToArray(), "--locked-mode");
            CollectionAssert.Contains(arguments.ToArray(), "win-x64");
            Assert.IsFalse(captureStandardOutput);
            RestoreCount++;
            return new(0, string.Empty);
        }

        public ReleaseV2CommandResult RunWithInput(string executable, IReadOnlyList<string> arguments,
            string workingDirectory, Stream standardInput)
        {
            Assert.AreEqual("git", executable);
            return _git.RunWithInput(executable, arguments, workingDirectory, standardInput);
        }
    }
}

/// <summary>Git plumbing for synthetic v2 tests. Real-Git regressions above never use it.</summary>
internal static class ServiceReleaseV2FakeGitProof
{
    private static readonly string[] RequiredPaths =
    [
        "global.json", "src/Vantrel.Security.Service/Vantrel.Security.Service.csproj",
        "src/Vantrel.Security.Service/packages.lock.json", "Vantrel.Security.sln"
    ];

    internal static bool TryRun(IReadOnlyList<string> arguments, string root,
        out ReleaseV2CommandResult result, bool includeExtra = false)
    {
        if (arguments.Contains("ls-tree", StringComparer.Ordinal))
        {
            result = new(0, string.Concat(Paths(includeExtra).Select(path =>
                "100644 blob " + GitBlob(File.ReadAllBytes(Path.Combine(root,
                    path.Replace('/', Path.DirectorySeparatorChar)))) + "\t" + path + "\0")));
            return true;
        }
        if (arguments.Contains("ls-files", StringComparer.Ordinal) &&
            arguments.Contains("--stage", StringComparer.Ordinal))
        {
            result = new(0, string.Concat(Paths(includeExtra).Select(path =>
                "H 100644 " + GitBlob(File.ReadAllBytes(Path.Combine(root,
                    path.Replace('/', Path.DirectorySeparatorChar)))) + " 0\t" + path + "\0")));
            return true;
        }
        result = default!;
        return false;
    }

    internal static ReleaseV2CommandResult RunWithInput(IReadOnlyList<string> arguments,
        Stream standardInput)
    {
        if (arguments.Contains("check-attr", StringComparer.Ordinal)) return new(0, string.Empty);
        if (!arguments.Contains("hash-object", StringComparer.Ordinal) ||
            !arguments.Contains("--stdin", StringComparer.Ordinal) ||
            !arguments.Any(argument => argument.StartsWith("--path=", StringComparison.Ordinal)))
            throw new AssertFailedException("Unexpected Git stdin command.");
        standardInput.Position = 0;
        using var buffer = new MemoryStream();
        standardInput.CopyTo(buffer);
        standardInput.Position = 0;
        return new(0, GitBlob(buffer.ToArray()) + "\n");
    }

    private static IEnumerable<string> Paths(bool includeExtra)
    {
        foreach (var path in RequiredPaths) yield return path;
        if (includeExtra) yield return "src/Vantrel.Security.Service/Additional.cs";
    }

    private static string GitBlob(byte[] contents)
    {
        var header = Encoding.ASCII.GetBytes("blob " + contents.Length + "\0");
        var framed = new byte[header.Length + contents.Length];
        header.CopyTo(framed, 0);
        contents.CopyTo(framed, header.Length);
        return Convert.ToHexString(SHA1.HashData(framed)).ToLowerInvariant();
    }
}
