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
    public void Signed_sandbox_preparation_validates_completed_inputs_and_copies_only_approved_bytes()
    {
        using var scope = new LayoutScope();
        using var inputs = new SignedCandidateScope(scope.Root);
        var output = Path.Combine(inputs.Root, "bundle");
        inputs.Prepare(output);
        var copied = Path.Combine(output, "input", "VantrelSecurity.msi");
        File.WriteAllText(Path.Combine(output, "input", "Validate-VantrelSignedCandidateSandbox.ps1"), "# synthetic validator\n");
        SignedSandboxCandidatePreparation.ValidatePreparedInput(Path.Combine(output, "input"), inputs.DistributionHash);
        Assert.AreEqual(inputs.MsiHash, Hash(copied));
        Assert.AreEqual(inputs.RecordHash, Hash(Path.Combine(output, "input", BetaReleaseLayoutValidator.RecordFileName)));
        Assert.AreEqual(inputs.PlanHash, Hash(Path.Combine(output, "input", InstallerInputValidator.PlanFileName)));
        Assert.AreEqual(inputs.DistributionHash, Hash(Path.Combine(output, "input", MsiDistributionRecordCodec.FileName)));
        var manifest = File.ReadAllBytes(Path.Combine(output, "input", SignedSandboxCandidateInputCodec.FileName));
        Assert.IsTrue(SignedSandboxCandidateInputCodec.TryParse(manifest, out var parsed));
        Assert.IsNotNull(parsed);
        Assert.AreEqual(inputs.DistributionHash, parsed.DistributionRecordSha256);
        Assert.AreEqual(inputs.MsiHash, parsed.Installation.MsiSha256);
        Assert.Throws<IOException>(() => inputs.Prepare(output));
        File.AppendAllText(copied, "changed");
        Assert.Throws<IOException>(() => SignedSandboxCandidatePreparation.ValidatePreparedInput(
            Path.Combine(output, "input"), inputs.DistributionHash));
    }

    [TestMethod]
    public void Signed_sandbox_preparation_rejects_each_hash_and_changed_input_without_creating_output()
    {
        using var scope = new LayoutScope();
        using var inputs = new SignedCandidateScope(scope.Root);
        foreach (var which in new[] { "msi", "plan", "release", "distribution" })
        {
            var output = Path.Combine(inputs.Root, "rejected-" + which);
            inputs.PrepareExpectFailure(output, which);
            Assert.IsFalse(Directory.Exists(output), which);
        }
        File.AppendAllText(inputs.SignedMsi, "changed");
        var changed = Path.Combine(inputs.Root, "changed-copy");
        Assert.Throws<IOException>(() => inputs.Prepare(changed));
        Assert.IsFalse(Directory.Exists(changed));
    }

    [TestMethod]
    public void Signed_sandbox_preparation_rejects_mismatched_plan_record_and_unsafe_paths()
    {
        using var scope = new LayoutScope();
        using var inputs = new SignedCandidateScope(scope.Root);
        var output = Path.Combine(inputs.Root, "unsafe");
        Assert.Throws<IOException>(() => SignedSandboxCandidatePreparation.Prepare(scope.Root, inputs.Plan,
            inputs.SignedMsi, inputs.Distribution, inputs.MsiHash, inputs.PlanHash, inputs.RecordHash,
            inputs.DistributionHash, scope.Root));
        Assert.Throws<IOException>(() => SignedSandboxCandidatePreparation.Prepare(scope.Root, inputs.Plan,
            inputs.SignedMsi, inputs.Distribution, inputs.MsiHash, inputs.PlanHash, inputs.RecordHash,
            inputs.DistributionHash, Path.Combine(inputs.Root, "..", "unsafe")));
        File.AppendAllText(Path.Combine(scope.Root, "desktop", "desktop.deps.json"), "changed");
        Assert.Throws<IOException>(() => inputs.Prepare(output));
        Assert.IsFalse(Directory.Exists(output));
    }

    [TestMethod]
    public void Signed_sandbox_preparation_rejects_canonical_distribution_cross_binding_mismatch()
    {
        using var scope = new LayoutScope();
        using var inputs = new SignedCandidateScope(scope.Root);
        foreach (var which in new[] { "msi", "plan", "release" })
        {
            var altered = new MsiDistributionRecord("VantrelSecurity.msi",
                which == "msi" ? new string('A', 64) : inputs.MsiHash,
                which == "release" ? new string('A', 64) : inputs.RecordHash,
                which == "plan" ? new string('A', 64) : inputs.PlanHash,
                MsiAuthenticodeInspectionResult.PolicyId, NativeAuthenticodeTrustCategory.Success,
                PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256,
                TimestampPolicyCategory.ValidRfc3161, AuthenticodeEkuPolicyCategory.Match);
            File.WriteAllBytes(inputs.Distribution, MsiDistributionRecordCodec.CreateCanonical(altered));
            var output = Path.Combine(inputs.Root, "mismatch-" + which);
            Assert.Throws<IOException>(() => inputs.Prepare(output));
            Assert.IsFalse(Directory.Exists(output));
        }
    }

    [TestMethod]
    public void Signed_sandbox_preparation_rejects_reparse_msi_when_symbolic_links_are_permitted()
    {
        using var scope = new LayoutScope();
        using var inputs = new SignedCandidateScope(scope.Root);
        var linked = Path.Combine(inputs.Root, "linked.msi");
        try { File.CreateSymbolicLink(linked, inputs.SignedMsi); }
        catch (IOException error) when (error.HResult == unchecked((int)0x80070522)) { Assert.Inconclusive("Windows symbolic-link privilege is not held."); return; }
        catch (UnauthorizedAccessException error) when (error.HResult == unchecked((int)0x80070522)) { Assert.Inconclusive("Windows symbolic-link privilege is not held."); return; }
        var output = Path.Combine(inputs.Root, "reparse-output");
        Assert.Throws<IOException>(() => SignedSandboxCandidatePreparation.Prepare(scope.Root, inputs.Plan,
            linked, inputs.Distribution, inputs.MsiHash, inputs.PlanHash, inputs.RecordHash,
            inputs.DistributionHash, output));
        Assert.IsFalse(Directory.Exists(output));
    }

    [TestMethod]
    public void Signed_sandbox_input_rejects_changed_missing_and_extra_transferred_files()
    {
        using var scope = new LayoutScope();
        using var inputs = new SignedCandidateScope(scope.Root);
        foreach (var name in new[]
        {
            "VantrelSecurity.msi", InstallerInputValidator.PlanFileName,
            BetaReleaseLayoutValidator.RecordFileName, MsiDistributionRecordCodec.FileName,
            SignedSandboxCandidateInputCodec.FileName
        })
        {
            var output = Path.Combine(inputs.Root, "transferred-" + name.Replace('.', '-'));
            inputs.Prepare(output);
            var input = Path.Combine(output, "input");
            File.WriteAllText(Path.Combine(input, "Validate-VantrelSignedCandidateSandbox.ps1"), "# synthetic validator\n");
            SignedSandboxCandidatePreparation.ValidatePreparedInput(input, inputs.DistributionHash);
            File.AppendAllText(Path.Combine(input, name), "changed");
            Assert.Throws<IOException>(() => SignedSandboxCandidatePreparation.ValidatePreparedInput(input, inputs.DistributionHash), name);
        }
        var missingOutput = Path.Combine(inputs.Root, "missing");
        inputs.Prepare(missingOutput);
        var missingInput = Path.Combine(missingOutput, "input");
        File.WriteAllText(Path.Combine(missingInput, "Validate-VantrelSignedCandidateSandbox.ps1"), "# synthetic validator\n");
        File.Delete(Path.Combine(missingInput, InstallerInputValidator.PlanFileName));
        Assert.Throws<IOException>(() => SignedSandboxCandidatePreparation.ValidatePreparedInput(missingInput, inputs.DistributionHash));
        var extraOutput = Path.Combine(inputs.Root, "extra");
        inputs.Prepare(extraOutput);
        var extraInput = Path.Combine(extraOutput, "input");
        File.WriteAllText(Path.Combine(extraInput, "Validate-VantrelSignedCandidateSandbox.ps1"), "# synthetic validator\n");
        File.WriteAllText(Path.Combine(extraInput, "unexpected.txt"), "extra");
        Assert.Throws<IOException>(() => SignedSandboxCandidatePreparation.ValidatePreparedInput(extraInput, inputs.DistributionHash));
    }

    [TestMethod]
    public void Signed_sandbox_codec_rejects_noncanonical_fields_paths_and_binding_changes()
    {
        using var scope = new LayoutScope();
        using var inputs = new SignedCandidateScope(scope.Root);
        var plan = new InstallerInputValidator().CreatePlan(scope.Root, "0.1.1");
        var legacy = new SandboxValidationInput(plan.Descriptor.SourceCommit, plan.Descriptor.ReleaseVersion,
            plan.Descriptor.ReleaseSequence, plan.Descriptor.PublishedAtUtc, plan.MsiProductVersion,
            inputs.MsiHash, inputs.PlanHash, plan.Artifacts);
        var canonical = System.Text.Encoding.ASCII.GetString(SignedSandboxCandidateInputCodec.CreateCanonical(
            new(legacy, inputs.RecordHash, inputs.DistributionHash, MsiAuthenticodeInspectionResult.PolicyId)));
        Assert.IsTrue(SignedSandboxCandidateInputCodec.TryParse(System.Text.Encoding.ASCII.GetBytes(canonical), out _));
        foreach (var altered in new[]
        {
            canonical.Replace("schema=vantrel-signed-sandbox-input-v1", "schema=vantrel-sandbox-input-v1", StringComparison.Ordinal),
            canonical.Replace("distribution-record-sha256=" + inputs.DistributionHash, "distribution-record-sha256=BAD", StringComparison.Ordinal),
            canonical.Replace("policy-id=" + MsiAuthenticodeInspectionResult.PolicyId, "policy-id=anything", StringComparison.Ordinal),
            canonical.Replace("service/Vantrel.Security.Service.exe", "../escape.exe", StringComparison.Ordinal),
            canonical.Replace("artifact-count=", "extra=value\nartifact-count=", StringComparison.Ordinal),
            canonical.Replace("\n", "\r\n", StringComparison.Ordinal)
        }) Assert.IsFalse(SignedSandboxCandidateInputCodec.TryParse(System.Text.Encoding.ASCII.GetBytes(altered), out _));
    }

    private sealed class SignedCandidateScope : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-signed-sandbox-" + Guid.NewGuid().ToString("N"));
        private readonly string _layout;
        internal string Plan => Path.Combine(Root, InstallerInputValidator.PlanFileName);
        internal string Distribution => Path.Combine(Root, MsiDistributionRecordCodec.FileName);
        internal string SignedMsi => Path.Combine(Root, "VantrelSecurity.msi");
        internal string MsiHash { get; }
        internal string PlanHash => Hash(Plan);
        internal string RecordHash => Hash(Path.Combine(_layout, BetaReleaseLayoutValidator.RecordFileName));
        internal string DistributionHash => Hash(Distribution);
        internal SignedCandidateScope(string layout)
        {
            _layout = layout;
            Directory.CreateDirectory(Root);
            var plan = new InstallerInputValidator().CreatePlan(layout, "0.1.1");
            File.WriteAllText(Plan, InstallerInputValidator.CreateCanonicalPlan(plan));
            File.WriteAllBytes(SignedMsi, [0x4D, 0x5A, 1, 2, 3]);
            MsiHash = Hash(SignedMsi);
            var record = new MsiDistributionRecord("VantrelSecurity.msi", MsiHash, RecordHash, PlanHash,
                MsiAuthenticodeInspectionResult.PolicyId, NativeAuthenticodeTrustCategory.Success,
                PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256,
                TimestampPolicyCategory.ValidRfc3161, AuthenticodeEkuPolicyCategory.Match);
            File.WriteAllBytes(Distribution, MsiDistributionRecordCodec.CreateCanonical(record));
        }
        internal void Prepare(string output) => SignedSandboxCandidatePreparation.Prepare(_layout, Plan, SignedMsi,
            Distribution, MsiHash, PlanHash, RecordHash, DistributionHash, output);
        internal void PrepareExpectFailure(string output, string which) => Assert.Throws<IOException>(() =>
            SignedSandboxCandidatePreparation.Prepare(_layout, Plan, SignedMsi, Distribution,
                which == "msi" ? new string('A', 64) : MsiHash,
                which == "plan" ? new string('A', 64) : PlanHash,
                which == "release" ? new string('A', 64) : RecordHash,
                which == "distribution" ? new string('A', 64) : DistributionHash, output));
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, true); }
    }
    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

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
    public void Recorded_publish_residue_is_hashed_but_omitted_from_the_plan()
    {
        using var scope = new LayoutScope("desktop/Vantrel.Security.Desktop.pdb", "desktop/packages.lock.json",
            "offline-update-tool/Vantrel.Security.OfflineUpdateTool.pdb", "offline-update-tool/packages.lock.json");

        var plan = new InstallerInputValidator().CreatePlan(scope.Root, "0.1.1");
        Assert.HasCount(20, plan.Artifacts);
        Assert.IsFalse(plan.Artifacts.Any(item => item.SourceRelativePath.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase) ||
            item.SourceRelativePath.EndsWith("/packages.lock.json", StringComparison.Ordinal)));
        Assert.IsTrue(InstallerInputPlanCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(InstallerInputValidator.CreateCanonicalPlan(plan)), out var parsed));
        Assert.HasCount(20, parsed!.Artifacts);
    }

    [TestMethod]
    public void Changed_missing_or_unrecorded_publish_residue_still_fails()
    {
        foreach (var residue in new[] { "desktop/Vantrel.Security.Desktop.pdb", "offline-update-tool/packages.lock.json" })
        {
            using (var changed = new LayoutScope(residue))
            {
                File.AppendAllText(Path.Combine(changed.Root, residue.Replace('/', Path.DirectorySeparatorChar)), "changed");
                Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(changed.Root, "0.1.1"));
            }
            using (var missing = new LayoutScope(residue))
            {
                File.Delete(Path.Combine(missing.Root, residue.Replace('/', Path.DirectorySeparatorChar)));
                Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(missing.Root, "0.1.1"));
            }
            using (var unrecorded = new LayoutScope())
            {
                var path = Path.Combine(unrecorded.Root, residue.Replace('/', Path.DirectorySeparatorChar));
                File.WriteAllText(path, "unrecorded");
                Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(unrecorded.Root, "0.1.1"));
            }
        }
    }

    [TestMethod]
    [DataRow("service/extra.pdb")]
    [DataRow("desktop/nested/extra.pdb")]
    [DataRow("desktop/install.ps1")]
    [DataRow("offline-update-tool/packages.lock.JSON")]
    [DataRow("offline-update-tool/private.key")]
    public void Other_recorded_unsupported_artifacts_remain_rejected(string artifact)
    {
        using var scope = new LayoutScope(artifact);
        Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(scope.Root, "0.1.1"));
    }

    [TestMethod]
    public void Recorded_publish_residue_reparse_is_rejected_when_symbolic_links_are_permitted()
    {
        const string residue = "desktop/Vantrel.Security.Desktop.pdb";
        using var scope = new LayoutScope(residue);
        var path = Path.Combine(scope.Root, residue.Replace('/', Path.DirectorySeparatorChar));
        File.Delete(path);
        try { File.CreateSymbolicLink(path, Path.Combine(scope.Root, "desktop", "Vantrel.Security.Desktop.dll")); }
        catch (IOException error) when (error.HResult == unchecked((int)0x80070522)) { Assert.Inconclusive("Windows symbolic-link privilege is not held."); return; }
        catch (UnauthorizedAccessException error) when (error.HResult == unchecked((int)0x80070522)) { Assert.Inconclusive("Windows symbolic-link privilege is not held."); return; }

        Assert.Throws<IOException>(() => new InstallerInputValidator().CreatePlan(scope.Root, "0.1.1"));
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

        internal LayoutScope(params string[] recordedExtras)
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
            foreach (var extra in recordedExtras) Write(extra, extra);
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
