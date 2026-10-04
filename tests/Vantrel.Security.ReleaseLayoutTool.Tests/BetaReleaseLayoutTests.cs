using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.ManifestTool;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
public sealed class BetaReleaseLayoutTests
{
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);

    [TestMethod]
    public void Canonical_layout_writes_a_relative_complete_record_without_secret_retention()
    {
        using var scope = new LayoutScope();
        var record = scope.Validate();
        var text = File.ReadAllText(Path.Combine(scope.Root, BetaReleaseLayoutValidator.RecordFileName));

        Assert.AreEqual(13, record.Artifacts.Count);
        Assert.IsTrue(record.Artifacts.Any(item => item.RelativePath == "desktop/Vantrel.Security.Desktop.exe"));
        Assert.IsTrue(record.Artifacts.Any(item => item.RelativePath == "offline-update-tool/Vantrel.Security.OfflineUpdateTool.exe"));
        Assert.IsFalse(text.Contains(scope.Root, StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(text.Contains("private", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(text.Contains("exception", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Raw_service_publish_residue_projects_exact_components_then_supports_a_nine_file_layout()
    {
        using var scope = new LayoutScope(rawServicePublish: true);
        new ServicePayloadProjector().Project(scope.RawServicePublishDirectory, Path.Combine(scope.Root, "service"));
        Directory.Delete(scope.RawServicePublishDirectory, recursive: true);

        CollectionAssert.AreEquivalent(ReleasePayloadVerifier.ServiceComponents.Select(component => component.FileName).ToArray(),
            Directory.EnumerateFiles(Path.Combine(scope.Root, "service")).Select(Path.GetFileName).ToArray());
        scope.AddSyntheticServicePublicArtifacts();

        var record = scope.Validate();
        Assert.AreEqual(13, record.Artifacts.Count);
    }

    [TestMethod]
    public void Missing_projected_component_fails_closed_without_a_final_service_directory()
    {
        using var scope = new LayoutScope(rawServicePublish: true);
        File.Delete(Path.Combine(scope.RawServicePublishDirectory, ReleasePayloadVerifier.ServiceComponentFileNames[0]));

        Assert.ThrowsException<IOException>(() => new ServicePayloadProjector().Project(scope.RawServicePublishDirectory, Path.Combine(scope.Root, "service")));
        Assert.IsFalse(Directory.Exists(Path.Combine(scope.Root, "service")));
    }

    [TestMethod]
    public void Reparse_projected_component_fails_closed_when_symbolic_links_are_permitted()
    {
        using var scope = new LayoutScope(rawServicePublish: true);
        var component = Path.Combine(scope.RawServicePublishDirectory, ReleasePayloadVerifier.ServiceComponentFileNames[0]);
        var target = Path.Combine(scope.Root, "component-target.bin");
        File.WriteAllText(target, "target");
        File.Delete(component);
        try { File.CreateSymbolicLink(component, target); }
        catch (Exception error) when (IsPrivilegeNotHeld(error)) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }

        Assert.ThrowsException<IOException>(() => new ServicePayloadProjector().Project(scope.RawServicePublishDirectory, Path.Combine(scope.Root, "service")));
        Assert.IsFalse(Directory.Exists(Path.Combine(scope.Root, "service")));
    }
    [TestMethod]
    public void Unexpected_service_file_fails_closed_without_a_record()
    {
        using var scope = new LayoutScope();
        scope.File("service/unexpected.dll", "unexpected");

        scope.AssertRejected();
    }

    [TestMethod]
    public void Missing_desktop_artifact_fails_closed_without_a_record()
    {
        using var scope = new LayoutScope();
        File.Delete(Path.Combine(scope.Root, "desktop", "Vantrel.Security.Desktop.exe"));

        scope.AssertRejected();
    }

    [TestMethod]
    public void Release_notes_hash_mismatch_fails_closed_without_a_record()
    {
        using var scope = new LayoutScope();
        File.AppendAllText(Path.Combine(scope.Root, BetaReleaseLayoutValidator.ReleaseNotesFileName), "changed");

        scope.AssertRejected();
    }

    [TestMethod]
    public void Manifest_or_metadata_version_mismatch_fails_closed_without_a_record()
    {
        using var scope = new LayoutScope(new StubVerifier(new VerifiedServicePayload("0.1.1-beta.1", "0.1.1-beta.1", 7, new string('B', 64))));

        scope.AssertRejected();
    }
    [TestMethod]
    public void Service_payload_hash_mismatch_fails_closed_without_a_record()
    {
        using var scope = new LayoutScope();
        var verifier = new HashCheckingVerifier(scope.Root);
        File.AppendAllText(Path.Combine(scope.Root, "service", "Vantrel.Security.Service.exe"), "changed");

        Assert.ThrowsException<IOException>(() => new BetaReleaseLayoutValidator(verifier).ValidateAndWriteRecord(scope.Root));
        Assert.IsFalse(File.Exists(Path.Combine(scope.Root, BetaReleaseLayoutValidator.RecordFileName)));
    }


    [TestMethod]
    public void Malformed_descriptor_rejects_extra_and_noncanonical_fields()
    {
        var descriptor = new BetaReleaseDescriptor(new string('a', 40), "0.1.0-beta.1", 7,
            new DateTimeOffset(2026, 10, 3, 12, 0, 0, TimeSpan.Zero), "Release", "win-x64", "10.0.401", new string('A', 64));
        var canonical = System.Text.Encoding.UTF8.GetString(BetaReleaseDescriptorCodec.CreateCanonical(descriptor));

        Assert.IsTrue(BetaReleaseDescriptorCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(canonical), out var parsed));
        Assert.AreEqual(descriptor, parsed);
        Assert.IsFalse(BetaReleaseDescriptorCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(canonical + "extra=value\n"), out _));
        Assert.IsFalse(BetaReleaseDescriptorCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(canonical.Replace("release-sequence=7", "release-sequence=07", StringComparison.Ordinal)), out _));
    }

    [TestMethod]
    public void Secret_like_artifact_is_rejected_and_never_enters_the_record()
    {
        using var scope = new LayoutScope();
        scope.File("desktop/forbidden.pem", "not-a-key");

        scope.AssertRejected();
    }

    [TestMethod]
    public void Signature_verification_failure_fails_closed_without_raw_diagnostics_or_record()
    {
        using var scope = new LayoutScope(new ThrowingVerifier());

        scope.AssertRejected();
    }

    [TestMethod]
    public void Reparse_directory_substitution_is_rejected_when_symbolic_links_are_permitted()
    {
        using var scope = new LayoutScope();
        var desktop = Path.Combine(scope.Root, "desktop");
        var target = Path.Combine(scope.Root, "replacement");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "Vantrel.Security.Desktop.exe"), "replacement");
        Directory.Delete(desktop, recursive: true);
        try { Directory.CreateSymbolicLink(desktop, target); }
        catch (Exception error) when (IsPrivilegeNotHeld(error)) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }

        scope.AssertRejected();
    }

    [TestMethod]
    public void Reparse_artifact_is_rejected_when_symbolic_links_are_permitted()
    {
        using var scope = new LayoutScope();
        var target = Path.Combine(scope.Root, "target.bin");
        File.WriteAllText(target, "target");
        var link = Path.Combine(scope.Root, "desktop", "linked.dll");
        try { File.CreateSymbolicLink(link, target); }
        catch (Exception error) when (IsPrivilegeNotHeld(error)) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }

        scope.AssertRejected();
    }

    [TestMethod]
    public void Two_independent_clean_source_roots_publish_identical_artifacts_and_bind_descriptor_metadata()
    {
        using var scope = new IndependentPublishScope();
        const string version = "0.1.0-beta.1";
        var first = Path.Combine(scope.Root, "first-output");
        var second = Path.Combine(scope.Root, "second-output");

        Assert.AreEqual(scope.FirstSource.Commit, scope.SecondSource.Commit);
        var firstResult = scope.FirstSource.RunPrepare(first, version);
        var secondResult = scope.SecondSource.RunPrepare(second, version);

        Assert.AreEqual(0, firstResult.ExitCode, firstResult.Output);
        Assert.AreEqual(0, secondResult.ExitCode, secondResult.Output);
        CollectionAssert.AreEqual(Snapshot(first), Snapshot(second));
        foreach (var relativeAssembly in new[]
                 {
                     "service/Vantrel.Security.Service.dll",
                     "desktop/Vantrel.Security.Desktop.dll",
                     "offline-update-tool/Vantrel.Security.OfflineUpdateTool.dll"
                 })
        {
            var image = Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(first, relativeAssembly)));
            StringAssert.Contains(image, version + "+" + scope.FirstSource.Commit);
            StringAssert.Contains(image, "VantrelReleaseVersion");
            StringAssert.Contains(image, "VantrelSourceCommit");
        }
    }

    [DataTestMethod]
    [DataRow(" M tracked-input")]
    [DataRow("?? untracked-input")]
    public void Release_script_rejects_dirty_or_untracked_checkout_before_publish(string status)
    {
        using var scope = new ScriptScope(status, failLockedRestore: false);

        var result = scope.RunPrepare();

        Assert.AreNotEqual(0, result.ExitCode);
        StringAssert.Contains(result.Output, "Beta release requires a clean immutable checkout.");
        Assert.IsFalse(result.Output.Contains("tracked-input", StringComparison.Ordinal));
        Assert.IsFalse(Directory.Exists(scope.OutputRoot));
    }

    [TestMethod]
    public void Release_script_rejects_ignored_residue_in_a_real_disposable_source_fixture_before_restore()
    {
        using var fixture = ReleaseSourceFixture.Create();
        var residue = "ignored-release-residue.txt";
        File.WriteAllText(Path.Combine(fixture.Root, ".git", "info", "exclude"), residue + "\n");
        File.WriteAllText(Path.Combine(fixture.Root, residue), "ignored");
        var output = Path.Combine(Path.GetTempPath(), "vantrel-beta-ignored-output-" + Guid.NewGuid().ToString("N"));

        try
        {
            var result = fixture.RunPrepare(output, "0.1.0-beta.1");

            Assert.AreNotEqual(0, result.ExitCode);
            StringAssert.Contains(result.Output, "Beta release requires a clean immutable checkout.");
            Assert.IsFalse(result.Output.Contains(residue, StringComparison.Ordinal));
            Assert.IsFalse(Directory.Exists(output));
        }
        finally
        {
            if (Directory.Exists(output)) Directory.Delete(output, recursive: true);
        }
    }

    [TestMethod]
    public void Locked_restore_failure_prevents_release_publish()
    {
        using var scope = new ScriptScope(status: null, failLockedRestore: true);

        var result = scope.RunPrepare();

        Assert.AreNotEqual(0, result.ExitCode);
        StringAssert.Contains(result.Output, "dotnet command failed");
        var invocations = File.ReadAllText(scope.DotnetLog);
        StringAssert.Contains(invocations, "restore");
        StringAssert.Contains(invocations, "--locked-mode");
        Assert.IsFalse(invocations.Contains("publish", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Changed_real_package_graph_fails_locked_restore_before_release_artifacts_are_created()
    {
        using var fixture = ReleaseSourceFixture.Create();
        var project = Path.Combine(fixture.Root, "tests", "Vantrel.Security.ReleaseLayoutTool.Tests", "Vantrel.Security.ReleaseLayoutTool.Tests.csproj");
        File.WriteAllText(project, File.ReadAllText(project).Replace("</Project>", "  <ItemGroup>\n    <PackageReference Include=\"System.Text.Json\" Version=\"10.0.1\" />\n  </ItemGroup>\n</Project>", StringComparison.Ordinal));
        fixture.CommitChanges("change locked package graph");
        var output = Path.Combine(Path.GetTempPath(), "vantrel-beta-lock-output-" + Guid.NewGuid().ToString("N"));

        try
        {
            var result = fixture.RunPrepare(output, "0.1.0-beta.1");

            Assert.AreNotEqual(0, result.ExitCode);
            StringAssert.Contains(result.Output, "dotnet command failed");
            Assert.IsFalse(File.Exists(Path.Combine(output, BetaReleaseLayoutValidator.RecordFileName)));
            Assert.IsFalse(Directory.Exists(Path.Combine(output, "service")));
            Assert.IsFalse(Directory.Exists(Path.Combine(output, "desktop")));
            Assert.IsFalse(Directory.Exists(Path.Combine(output, "offline-update-tool")));
        }
        finally
        {
            if (Directory.Exists(output)) Directory.Delete(output, recursive: true);
        }
    }

    private static bool IsPrivilegeNotHeld(Exception error) => error.HResult == PrivilegeNotHeldHResult;

    private static string[] Snapshot(string root) => Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
        .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/') + "|" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))))
        .OrderBy(value => value, StringComparer.Ordinal).ToArray();

    private static ProcessResult Run(string fileName, IEnumerable<string> arguments, string? path = null, string? log = null, IReadOnlyDictionary<string, string>? environment = null)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo(fileName) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true } };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        if (path is not null) process.StartInfo.Environment["PATH"] = path;
        if (log is not null) process.StartInfo.Environment["VANTREL_TEST_LOG"] = log;
        if (environment is not null)
            foreach (var pair in environment) process.StartInfo.Environment[pair.Key] = pair.Value;
        process.Start();
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        Task.WaitAll(standardOutput, standardError);
        return new(process.ExitCode, standardOutput.Result + standardError.Result);
    }

    private sealed record ProcessResult(int ExitCode, string Output);

    private sealed class IndependentPublishScope : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-beta-independent-publish-" + Guid.NewGuid().ToString("N"));
        internal ReleaseSourceFixture FirstSource { get; }
        internal ReleaseSourceFixture SecondSource { get; }

        internal IndependentPublishScope()
        {
            Directory.CreateDirectory(Root);
            FirstSource = ReleaseSourceFixture.Create(Path.Combine(Root, "source-one"));
            SecondSource = ReleaseSourceFixture.Create(Path.Combine(Root, "source-two"));
        }

        public void Dispose()
        {
            FirstSource.Dispose();
            SecondSource.Dispose();
            TryDeleteDirectory(Root);
        }
    }

    private sealed class ReleaseSourceFixture : IDisposable
    {
        private const string FixedGitDate = "2026-10-04T00:00:00Z";
        private const string ExcludedFixtureScript = "task016-fixture-recovery-review.ps1";
        private readonly string _notes;

        internal string Root { get; }
        internal string Commit { get; private set; } = string.Empty;

        private ReleaseSourceFixture(string root)
        {
            Root = root;
            _notes = Path.Combine(Path.GetTempPath(), "vantrel-beta-notes-" + Guid.NewGuid().ToString("N") + ".md");
        }

        internal static ReleaseSourceFixture Create(string? root = null)
        {
            var fixture = new ReleaseSourceFixture(root ?? Path.Combine(Path.GetTempPath(), "vantrel-beta-source-" + Guid.NewGuid().ToString("N")));
            fixture.CloneHeadAndApplyCurrentReleaseChanges();
            File.WriteAllText(fixture._notes, "# Beta notes\n");
            Assert.AreEqual(0, Run("git", ["-C", fixture.Root, "config", "user.email", "release-fixture@example.invalid"]).ExitCode);
            Assert.AreEqual(0, Run("git", ["-C", fixture.Root, "config", "user.name", "Release Fixture"]).ExitCode);
            fixture.CommitChanges("release fixture");
            return fixture;
        }

        internal void CommitChanges(string message)
        {
            Assert.AreEqual(0, Run("git", ["-C", Root, "add", "-A"]).ExitCode);
            var dates = new Dictionary<string, string>
            {
                ["GIT_AUTHOR_DATE"] = FixedGitDate,
                ["GIT_COMMITTER_DATE"] = FixedGitDate
            };
            var commit = Run("git", ["-C", Root, "commit", "--quiet", "-m", message], environment: dates);
            Assert.AreEqual(0, commit.ExitCode, commit.Output);
            var head = Run("git", ["-C", Root, "rev-parse", "HEAD"]);
            Assert.AreEqual(0, head.ExitCode, head.Output);
            Commit = head.Output.Trim();
        }

        internal ProcessResult RunPrepare(string output, string version) => Run("powershell.exe", [
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", Path.Combine(Root, "scripts", "New-BetaReleaseLayout.ps1"),
            "-Phase", "Prepare", "-OutputRoot", output, "-SourceCommit", Commit, "-ReleaseVersion", version,
            "-ReleaseSequence", "1", "-PublishedAtUtc", "2026-10-04T00:00:00Z", "-ReleaseNotesPath", _notes
        ]);

        public void Dispose()
        {
            if (File.Exists(_notes)) File.Delete(_notes);
            TryDeleteDirectory(Root);
        }

        private void CloneHeadAndApplyCurrentReleaseChanges()
        {
            var sourceRoot = FindRepositoryRoot();
            var clone = Run("git", ["clone", "--quiet", "--no-local", sourceRoot, Root]);
            Assert.AreEqual(0, clone.ExitCode, clone.Output);

            var tracked = Run("git", ["-C", sourceRoot, "-c", "core.autocrlf=false", "diff", "--name-only", "HEAD"]);
            var untracked = Run("git", ["-C", sourceRoot, "-c", "core.autocrlf=false", "ls-files", "--others", "--exclude-standard"]);
            Assert.AreEqual(0, tracked.ExitCode, tracked.Output);
            Assert.AreEqual(0, untracked.ExitCode, untracked.Output);
            var files = tracked.Output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries)
                .Concat(untracked.Output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries))
                .Distinct(StringComparer.Ordinal);
            foreach (var relative in files)
            {
                if (string.Equals(relative.Replace('/', '\\'), ExcludedFixtureScript, StringComparison.OrdinalIgnoreCase)) continue;
                var source = Path.Combine(sourceRoot, relative);
                var destination = Path.Combine(Root, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(source, destination, overwrite: true);
            }
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        for (var attempt = 0; Directory.Exists(path) && attempt < 5; attempt++)
        {
            try
            {
                Directory.Delete(path, recursive: true);
                return;
            }
            catch (IOException) { if (attempt < 4) Thread.Sleep(200); }
            catch (UnauthorizedAccessException) { if (attempt < 4) Thread.Sleep(200); }
        }
    }

    private sealed class ScriptScope : IDisposable
    {
        private const string Commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        private readonly string _fakeBin;
        private readonly string _notes;
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-beta-script-" + Guid.NewGuid().ToString("N"));
        internal string OutputRoot => Path.Combine(Root, "output");
        internal string DotnetLog => Path.Combine(Root, "dotnet.log");

        internal ScriptScope(string? status, bool failLockedRestore)
        {
            Directory.CreateDirectory(Root);
            _fakeBin = Path.Combine(Root, "bin");
            Directory.CreateDirectory(_fakeBin);
            _notes = Path.Combine(Root, "notes.md");
            File.WriteAllText(_notes, "notes");
            File.WriteAllText(Path.Combine(_fakeBin, "git.cmd"), BuildGit(status));
            File.WriteAllText(Path.Combine(_fakeBin, "dotnet.cmd"), BuildDotnet(failLockedRestore));
        }

        internal ProcessResult RunPrepare() => Run("powershell.exe", [
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", Path.Combine(FindRepositoryRoot(), "scripts", "New-BetaReleaseLayout.ps1"),
            "-Phase", "Prepare", "-OutputRoot", OutputRoot, "-SourceCommit", Commit, "-ReleaseVersion", "0.1.0-beta.1",
            "-ReleaseSequence", "1", "-PublishedAtUtc", "2026-10-04T00:00:00Z", "-ReleaseNotesPath", _notes
        ], _fakeBin + ";" + Environment.GetEnvironmentVariable("PATH"), DotnetLog);

        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }

        private static string BuildGit(string? status) => $"@echo off\r\nsetlocal\r\nset args=%*\r\necho %args%>> \"%VANTREL_TEST_LOG%\"\r\necho %args% | findstr /C:\"rev-parse\" >nul\r\nif not errorlevel 1 (echo {Commit} & exit /b 0)\r\necho %args% | findstr /C:\"cat-file\" >nul\r\nif not errorlevel 1 exit /b 0\r\necho %args% | findstr /C:\"status\" >nul\r\nif not errorlevel 1 (" + (status is null ? "exit /b 0" : $"echo {status} & exit /b 0") + ")\r\nexit /b 1\r\n";
        private static string BuildDotnet(bool failLockedRestore) => $"@echo off\r\nsetlocal\r\nset args=%*\r\necho %args%>> \"%VANTREL_TEST_LOG%\"\r\necho %args% | findstr /C:\"--version\" >nul\r\nif not errorlevel 1 (echo 10.0.401 & exit /b 0)\r\necho %args% | findstr /C:\"restore\" >nul\r\nif not errorlevel 1 (" + (failLockedRestore ? "exit /b 1" : "exit /b 0") + ")\r\nexit /b 0\r\n";
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "Directory.Build.props"))) return directory.FullName;
        throw new InvalidOperationException("Repository root is unavailable.");
    }
    private sealed class LayoutScope : IDisposable
    {
        private const string Version = "0.1.0-beta.1";
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-beta-layout-" + Guid.NewGuid().ToString("N"));
        private readonly IServicePayloadSignatureVerifier _verifier;
        internal string RawServicePublishDirectory => Path.Combine(Root, "service-publish");

        internal LayoutScope(IServicePayloadSignatureVerifier? verifier = null, bool rawServicePublish = false)
        {
            Directory.CreateDirectory(Root);
            _verifier = verifier ?? new StubVerifier(new VerifiedServicePayload(Version, Version, 7, new string('B', 64)));
            File(BetaReleaseLayoutValidator.ReleaseNotesFileName, "# Beta notes\n");
            var notesHash = Hash(Path.Combine(Root, BetaReleaseLayoutValidator.ReleaseNotesFileName));
            var descriptor = new BetaReleaseDescriptor(new string('a', 40), Version, 7,
                new DateTimeOffset(2026, 10, 3, 12, 0, 0, TimeSpan.Zero), "Release", "win-x64", "10.0.401", notesHash);
            System.IO.File.WriteAllBytes(Path.Combine(Root, BetaReleaseDescriptorCodec.FileName), BetaReleaseDescriptorCodec.CreateCanonical(descriptor));
            if (rawServicePublish)
            {
                foreach (var name in ReleasePayloadVerifier.ServiceComponentFileNames) File(Path.Combine("service-publish", name), name);
                File("service-publish/Vantrel.Security.Service.pdb", "debug");
                File("service-publish/appsettings.json", "settings");
                File("service-publish/Microsoft.Extensions.Hosting.dll", "dependency");
            }
            else foreach (var name in ReleasePayloadVerifier.ExactFileNames) File(Path.Combine("service", name), name);
            File("desktop/Vantrel.Security.Desktop.exe", "desktop");
            File("offline-update-tool/Vantrel.Security.OfflineUpdateTool.exe", "tool");
        }

        internal void File(string relative, string contents)
        {
            var path = Path.Combine(Root, relative); Directory.CreateDirectory(Path.GetDirectoryName(path)!); System.IO.File.WriteAllText(path, contents);
        }
        internal void AddSyntheticServicePublicArtifacts()
        {
            File("service/Vantrel.Security.TrustedManifest", "manifest");
            File("service/Vantrel.Security.ReleaseMetadata", "metadata");
        }
        internal BetaReleaseRecord Validate() => new BetaReleaseLayoutValidator(_verifier).ValidateAndWriteRecord(Root);
        internal void AssertRejected()
        {
            Assert.ThrowsException<IOException>(() => Validate());
            Assert.IsFalse(System.IO.File.Exists(Path.Combine(Root, BetaReleaseLayoutValidator.RecordFileName)));
        }
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }
        private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(System.IO.File.ReadAllBytes(path)));
    }

    private sealed class StubVerifier(VerifiedServicePayload payload) : IServicePayloadSignatureVerifier
    {
        public VerifiedServicePayload Verify(string payloadDirectory) => payload;
    }
    private sealed class ThrowingVerifier : IServicePayloadSignatureVerifier
    {
        public VerifiedServicePayload Verify(string payloadDirectory) => throw new InvalidDataException("synthetic failure");
    }
    private sealed class HashCheckingVerifier : IServicePayloadSignatureVerifier
    {
        private readonly IReadOnlyDictionary<string, string> _expected;

        internal HashCheckingVerifier(string root)
        {
            _expected = ReleasePayloadVerifier.ExactFileNames.ToDictionary(
                name => name,
                name => Hash(Path.Combine(root, "service", name)),
                StringComparer.Ordinal);
        }

        public VerifiedServicePayload Verify(string payloadDirectory)
        {
            foreach (var pair in _expected)
                if (!string.Equals(pair.Value, Hash(Path.Combine(payloadDirectory, pair.Key)), StringComparison.Ordinal))
                    throw new InvalidDataException("Synthetic service signature hash mismatch.");
            return new VerifiedServicePayload("0.1.0-beta.1", "0.1.0-beta.1", 7, new string('B', 64));
        }

        private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    }
}
