using System.Security.Cryptography;
using Vantrel.Security.InstallerPreflight;
using Vantrel.Security.ManifestTool;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.InstallerPreflight.Tests;

[TestClass]
[DoNotParallelize]
public sealed class InstallerInputValidatorTests
{
    [TestMethod]
    public void Valid_completed_layout_creates_a_safe_initial_install_plan()
    {
        using var scope = new LayoutScope();
        var plan = new InstallerInputValidator().CreatePlan(scope.Root, "0.1.1");

        Assert.AreEqual("0.1.1", plan.MsiProductVersion);
        Assert.HasCount(20, plan.Artifacts);
        Assert.IsTrue(plan.Artifacts.All(item => !Path.IsPathFullyQualified(item.SourceRelativePath)));
        Assert.IsTrue(plan.Artifacts.All(item => !item.SourceRelativePath.Contains(scope.Root, StringComparison.OrdinalIgnoreCase)));
        Assert.IsTrue(plan.Artifacts.All(item => item.Destination.DirectoryId == "ProgramFiles64Folder"));
        Assert.IsFalse(InstallerInputValidator.CreateCanonicalPlan(plan).Contains(scope.Root, StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Static_model_preserves_only_initial_install_behavior()
    {
        var model = InitialInstallContract.Model;

        Assert.AreEqual("VantrelSecurityService", model.Service.Name);
        Assert.AreEqual("Vantrel Security Service", model.Service.DisplayName);
        Assert.AreEqual("NT AUTHORITY\\LocalService", model.Service.Account);
        Assert.AreEqual("own-process", model.Service.ServiceType);
        Assert.AreEqual("demand", model.Service.StartType);
        Assert.IsFalse(model.Service.HasDependencies);
        Assert.IsFalse(model.Service.HasFailureActions);
        Assert.IsFalse(model.Service.StartsDuringInstall);
        Assert.AreEqual("Application", model.EventLog.LogName);
        Assert.AreEqual("System.Diagnostics.EventLog.Messages.dll", Path.GetFileName(model.EventLog.MessageResource.RelativePath));
        Assert.AreEqual("all-users", model.DesktopShortcut.Scope);
        Assert.IsFalse(model.DesktopShortcut.Advertised);
        Assert.IsFalse(model.DesktopShortcut.DesktopShortcut);
        Assert.IsFalse(model.DesktopShortcut.Elevates);
        Assert.IsFalse(model.DesktopShortcut.StartsService);
        Assert.IsFalse(model.DesktopShortcut.InvokesUpdater);
        CollectionAssert.AreEqual(new[]
        {
            "ProgramData\\Vantrel Security\\Updates",
            "ProgramData\\Vantrel Security\\Updates\\Staged",
            "ProgramData\\Vantrel Security\\Updates\\Transactions",
            "ProgramData\\Vantrel Security\\Updates\\Backups",
            "ProgramData\\Vantrel Security\\Updates\\.update-journal-v1.lock",
            "ProgramData\\Vantrel Security\\Updates\\.offline-update-owner-v1.lock",
            "ProgramData\\Vantrel Security\\ReleasePolicy"
        }, model.ExcludedDataRoots.ToArray());
    }

    [TestMethod]
    [DataRow("0.1.0", true)]
    [DataRow("255.255.65535", true)]
    [DataRow("0.01.0", false)]
    [DataRow("0.1", false)]
    [DataRow("256.1.0", false)]
    [DataRow("0.1.65536", false)]
    [DataRow("0.1.0-beta.1", false)]
    [DataRow(" 0.1.0", false)]
    public void Msi_product_version_is_explicit_and_canonical(string value, bool expected)
    {
        Assert.AreEqual(expected, MsiProductVersion.TryParse(value, out _));
    }

    [TestMethod]
    public void Missing_unrecorded_and_hash_mismatched_artifacts_fail_without_a_plan()
    {
        using (var missing = new LayoutScope())
        {
            File.Delete(Path.Combine(missing.Root, "desktop", "Vantrel.Security.Desktop.dll"));
            Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(missing.Root, "0.1.1"));
        }
        using (var unrecorded = new LayoutScope())
        {
            File.WriteAllText(Path.Combine(unrecorded.Root, "desktop", "unexpected.dll"), "extra");
            Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(unrecorded.Root, "0.1.1"));
        }
        using (var changed = new LayoutScope())
        {
            File.AppendAllText(Path.Combine(changed.Root, "offline-update-tool", "Vantrel.Security.OfflineUpdateTool.dll"), "changed");
            Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(changed.Root, "0.1.1"));
        }
    }

    [TestMethod]
    public void Malformed_completed_release_record_fails_without_a_plan()
    {
        using var scope = new LayoutScope();
        File.AppendAllText(Path.Combine(scope.Root, BetaReleaseLayoutValidator.RecordFileName), "artifact-count=4294967295\n");

        Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(scope.Root, "0.1.1"));
    }

    [TestMethod]
    [DataRow("../escape.bin")]
    [DataRow("C:/artifact.bin")]
    [DataRow("C:artifact.bin")]
    public void Traversal_and_Windows_drive_artifact_paths_are_rejected_at_record_parse_time(string unsafePath)
    {
        using var scope = new LayoutScope();
        var recordPath = Path.Combine(scope.Root, BetaReleaseLayoutValidator.RecordFileName);
        var record = File.ReadAllText(recordPath);
        const string knownPath = "desktop/desktop.deps.json";
        Assert.IsTrue(record.Contains(knownPath, StringComparison.Ordinal));
        File.WriteAllText(recordPath, record.Replace(knownPath, unsafePath, StringComparison.Ordinal));

        Assert.IsFalse(BetaReleaseRecordCodec.TryParse(File.ReadAllBytes(recordPath), out _));
        Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(scope.Root, "0.1.1"));
    }

    [TestMethod]
    public void Service_requires_the_exact_nine_file_payload_and_runtime_directories_match_the_record()
    {
        using (var missingService = new LayoutScope())
        {
            File.Delete(Path.Combine(missingService.Root, "service", "Vantrel.Security.Core.dll"));
            Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(missingService.Root, "0.1.1"));
        }
        using (var service = new LayoutScope())
        {
            File.WriteAllText(Path.Combine(service.Root, "service", "extra.dll"), "extra");
            Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(service.Root, "0.1.1"));
        }
        using (var desktop = new LayoutScope())
        {
            File.Delete(Path.Combine(desktop.Root, "desktop", "Vantrel.Security.Desktop.exe"));
            Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(desktop.Root, "0.1.1"));
        }
        using (var tool = new LayoutScope())
        {
            File.Delete(Path.Combine(tool.Root, "offline-update-tool", "Vantrel.Security.OfflineUpdateTool.exe"));
            Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(tool.Root, "0.1.1"));
        }
    }

    [TestMethod]
    public void Ineligible_pdb_script_and_secret_artifacts_fail_closed()
    {
        foreach (var name in new[] { "Vantrel.Security.Desktop.pdb", "install.ps1", "private.key" })
        {
            using var scope = new LayoutScope();
            File.WriteAllText(Path.Combine(scope.Root, "desktop", name), "unsafe");
            Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(scope.Root, "0.1.1"), name);
        }
    }

    [TestMethod]
    public void Plan_output_is_canonical_sensitive_free_and_never_written_partially()
    {
        using var scope = new LayoutScope();
        var planPath = Path.Combine(Path.GetTempPath(), "vantrel-installer-plan-" + Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            var plan = new InstallerInputValidator().CreateAndWritePlan(scope.Root, "0.1.1", planPath);
            var text = File.ReadAllText(planPath);
            StringAssert.Contains(text, "future-operations=unsupported");
            Assert.IsFalse(text.Contains(scope.Root, StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(text.Contains("certificate", StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(text.Contains("ProgramData\\Vantrel Security\\Updates", StringComparison.OrdinalIgnoreCase));
            Assert.Throws<IOException>(() => new InstallerInputValidator().CreateAndWritePlan(scope.Root, "0.1.1", Path.Combine(scope.Root, "plan.txt")));
            Assert.IsFalse(File.Exists(Path.Combine(scope.Root, "plan.txt")));
            Assert.AreEqual(plan.Artifacts.Count, text.Split('\n').Count(line => line.StartsWith("artifact=", StringComparison.Ordinal)));
        }
        finally { if (File.Exists(planPath)) File.Delete(planPath); }
    }

    [TestMethod]
    public void Reparse_layout_entry_is_rejected_when_symbolic_links_are_permitted()
    {
        using var scope = new LayoutScope();
        var link = Path.Combine(scope.Root, "desktop", "redirect.dll");
        var target = Path.Combine(scope.Root, "outside.dll");
        File.WriteAllText(target, "outside");
        try { File.CreateSymbolicLink(link, target); }
        catch (IOException error) when (error.HResult == unchecked((int)0x80070522)) { Assert.Inconclusive("Windows symbolic-link privilege is not held."); return; }
        catch (UnauthorizedAccessException error) when (error.HResult == unchecked((int)0x80070522)) { Assert.Inconclusive("Windows symbolic-link privilege is not held."); return; }

        Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(scope.Root, "0.1.1"));
    }

    private sealed class LayoutScope : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-installer-input-" + Guid.NewGuid().ToString("N"));

        internal LayoutScope()
        {
            Directory.CreateDirectory(Root);
            var descriptor = new BetaReleaseDescriptor(new string('a', 40), "0.1.0-beta.1", 7,
                new DateTimeOffset(2026, 10, 5, 0, 0, 0, TimeSpan.Zero), "Release", "win-x64", "10.0.401", new string('0', 64));
            File.WriteAllText(Path.Combine(Root, BetaReleaseLayoutValidator.ReleaseNotesFileName), "# notes\n");
            descriptor = descriptor with { ReleaseNotesSha256 = Hash(Path.Combine(Root, BetaReleaseLayoutValidator.ReleaseNotesFileName)) };
            File.WriteAllBytes(Path.Combine(Root, BetaReleaseDescriptorCodec.FileName), BetaReleaseDescriptorCodec.CreateCanonical(descriptor));
            foreach (var file in ReleasePayloadVerifier.ExactFileNames) Write("service/" + file, file);
            foreach (var file in ReleaseSigningContract.VantrelOwnedPeArtifacts.Where(item => !item.RelativePath.StartsWith("service/", StringComparison.Ordinal))) Write(file.RelativePath, file.RelativePath);
            Write("desktop/desktop.deps.json", "desktop dependencies");
            Write("offline-update-tool/tool.runtimeconfig.json", "tool runtime");
            var artifacts = EnumerateArtifacts().ToArray();
            var evidence = ReleaseSigningContract.VantrelOwnedPeArtifacts.Select(item => new AuthenticodeReleaseEvidence(item.RelativePath,
                AuthenticodeVerificationCategory.Valid, "test-publisher-policy", PrimarySignatureCountPolicyCategory.ExactlyOne, TimestampPolicyCategory.ValidRfc3161)).ToArray();
            var record = new BetaReleaseRecord(descriptor, new Vantrel.Security.ReleaseLayoutTool.VerifiedServicePayload(descriptor.ReleaseVersion, descriptor.ReleaseVersion, descriptor.ReleaseSequence, new string('B', 64)),
                Array.AsReadOnly(artifacts), Array.AsReadOnly(evidence));
            File.WriteAllBytes(Path.Combine(Root, BetaReleaseLayoutValidator.RecordFileName), BetaReleaseRecordCodec.CreateCanonical(record));
        }

        private void Write(string relative, string text)
        {
            var path = Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, text);
        }

        private IEnumerable<ReleaseArtifact> EnumerateArtifacts()
        {
            foreach (var name in new[] { BetaReleaseDescriptorCodec.FileName, BetaReleaseLayoutValidator.ReleaseNotesFileName })
                yield return new(name, Hash(Path.Combine(Root, name)));
            foreach (var top in new[] { "service", "desktop", "offline-update-tool" })
                foreach (var file in Directory.EnumerateFiles(Path.Combine(Root, top), "*", SearchOption.AllDirectories).OrderBy(path => path, StringComparer.Ordinal))
                    yield return new(top + "/" + Path.GetRelativePath(Path.Combine(Root, top), file).Replace('\\', '/'), Hash(file));
        }

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, true);
        }

        private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    }
}
