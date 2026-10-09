using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.InstallerPreflight.Tests;

[TestClass]
public sealed class MsiDistributionCommandTests
{
    [TestMethod]
    public void Cli_requires_exact_flags_absolute_paths_and_canonical_hash()
    {
        using var scope = new MsiVerificationFoundationTests.Scope();
        var options = Options(scope);
        var args = Arguments(options);
        Assert.AreEqual(options, MsiDistributionCommand.Parse(args));
        var reordered = (string[])args.Clone();
        (reordered[1], reordered[17]) = (reordered[17], reordered[1]);
        (reordered[2], reordered[18]) = (reordered[18], reordered[2]);
        Assert.AreEqual(options, MsiDistributionCommand.Parse(reordered));
        foreach (var (index, value) in new[]
        {
            (0, "create-plan"), (1, "--unknown"), (3, "--output-root"),
            (2, "relative-layout"), (8, new string('a', 64)), (18, "")
        })
        {
            var invalid = (string[])args.Clone(); invalid[index] = value;
            Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Parse(invalid));
        }
        Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Parse(args[..^2]));
        Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Parse([.. args, "--extra", "value"]));
    }

    [TestMethod]
    public void Signer_constructs_one_exact_argument_list_and_nonzero_stops()
    {
        using var scope = new MsiVerificationFoundationTests.Scope();
        var tool = Path.Combine(scope.Root, "signtool.exe");
        var dlib = Path.Combine(scope.Root, "Azure.CodeSigning.Dlib.dll");
        var metadata = Path.Combine(scope.Root, "metadata.json");
        File.WriteAllText(tool, "synthetic tool"); File.WriteAllText(dlib, "synthetic dlib");
        File.WriteAllBytes(metadata, AzureArtifactSigningMetadataCodec.CreateCanonical(new(
            AzureArtifactSigningMetadataCodec.Endpoint, AzureArtifactSigningMetadataCodec.AccountName,
            AzureArtifactSigningMetadataCodec.CertificateProfileName, Guid.NewGuid().ToString("D"), true)));
        var options = Options(scope) with { SignTool = tool, Dlib = dlib, Metadata = metadata };
        var runner = new Runner(0);
        var signer = new MsiSignToolSigningRequest(options, runner);
        Assert.IsTrue(signer.Sign(scope.Destination));
        Assert.IsFalse(signer.Sign(scope.Destination));
        Assert.AreEqual(1, runner.Calls);
        Assert.AreEqual(tool, runner.Executable);
        CollectionAssert.AreEqual(new[] { "sign", "/fd", "SHA256", "/tr", "http://timestamp.acs.microsoft.com/",
            "/td", "SHA256", "/dlib", dlib, "/dmdf", metadata, scope.Destination }, runner.Arguments);

        var failedRunner = new Runner(2);
        var failed = new MsiSignToolSigningRequest(options, failedRunner);
        Assert.IsFalse(failed.Sign(scope.Destination));
        Assert.IsFalse(failed.Sign(scope.Destination));
        Assert.AreEqual(1, failedRunner.Calls);
        File.WriteAllText(metadata, "{\"token\":\"unexpected\"}");
        Assert.ThrowsExactly<IOException>(() => new MsiSignToolSigningRequest(options, new Runner(0)));
    }

    [TestMethod]
    public void Successful_publication_binds_verified_bytes_and_both_validated_input_hashes()
    {
        using var scope = new MsiVerificationFoundationTests.Scope();
        var options = Options(scope);
        var signer = new Signer(path => File.WriteAllBytes(path, MsiCompoundFixture.Create(signatures: true)));
        var publisher = new ObservingPublisher(() =>
        {
            Assert.ThrowsExactly<IOException>(() =>
            {
                using var writer = new FileStream(scope.Destination, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            });
        });
        var result = MsiDistributionCommand.Execute(options, signer, new Inspector(), new FixedDatabase(), publisher);
        Assert.AreEqual(1, signer.Calls);
        Assert.AreEqual(1, publisher.Calls);
        Assert.AreEqual(scope.Hash(scope.Destination), result.FinalMsiSha256);
        Assert.AreEqual(scope.Hash(Path.Combine(scope.Layout, BetaReleaseLayoutValidator.RecordFileName)), result.ReleaseRecordSha256);
        Assert.AreEqual(scope.Hash(scope.Plan), result.InstallerPlanSha256);
        Assert.AreEqual("signed.msi", result.RelativeMsiFileName);
        Assert.IsTrue(MsiDistributionRecordCodec.TryParse(File.ReadAllBytes(options.DistributionRecord), out var parsed));
        Assert.AreEqual(result, parsed);
        Assert.AreEqual(scope.SourceHash, scope.Hash(scope.Source));
    }

    [TestMethod]
    public void Signer_comparison_identity_and_input_mutation_fail_without_record()
    {
        foreach (var kind in new[] { "rejected", "comparison", "identity", "input", "plan" })
        {
            using var scope = new MsiVerificationFoundationTests.Scope();
            var options = Options(scope);
            var signer = new Signer(path =>
            {
                switch (kind)
                {
                    case "comparison": File.WriteAllBytes(path, MsiCompoundFixture.Create(signatures: true, changed: "Table")); break;
                    case "identity":
                        var replacement = Path.Combine(scope.Root, "replacement.msi");
                        File.WriteAllBytes(replacement, MsiCompoundFixture.Create(signatures: true));
                        File.Move(replacement, path, true);
                        break;
                    case "input": File.AppendAllText(scope.Source, "mutation"); break;
                    case "plan": File.AppendAllText(scope.Plan, "mutation"); break;
                }
            }, kind != "rejected");
            Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Execute(
                options, signer, new Inspector(), new FixedDatabase(), new AtomicMsiDistributionRecordPublisher()), kind);
            Assert.AreEqual(1, signer.Calls, kind);
            Assert.IsFalse(File.Exists(options.DistributionRecord), kind);
        }
    }

    [TestMethod]
    public void Native_policy_failure_does_not_publish()
    {
        using var scope = new MsiVerificationFoundationTests.Scope();
        var options = Options(scope);
        var signer = new Signer(path => File.WriteAllBytes(path, MsiCompoundFixture.Create(signatures: true)));
        Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Execute(
            options, signer, new Inspector(accepted: false), new FixedDatabase(), new AtomicMsiDistributionRecordPublisher()));
        Assert.AreEqual(1, signer.Calls);
        Assert.IsFalse(File.Exists(options.DistributionRecord));
    }

    [TestMethod]
    public void Incomplete_inputs_existing_record_and_publication_failure_do_not_approve()
    {
        using (var scope = new MsiVerificationFoundationTests.Scope())
        {
            var options = Options(scope) with { UnsignedMsiSha256 = new string('A', 64) };
            var signer = new Signer(_ => { });
            Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Execute(
                options, signer, new Inspector(), new FixedDatabase(), new AtomicMsiDistributionRecordPublisher()));
            Assert.AreEqual(0, signer.Calls);
        }
        using (var scope = new MsiVerificationFoundationTests.Scope())
        {
            var options = Options(scope);
            File.Delete(Path.Combine(scope.Layout, "desktop", "Vantrel.Security.Desktop.exe"));
            var signer = new Signer(_ => { });
            Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Execute(
                options, signer, new Inspector(), new FixedDatabase(), new AtomicMsiDistributionRecordPublisher()));
            Assert.AreEqual(0, signer.Calls);
        }
        using (var scope = new MsiVerificationFoundationTests.Scope())
        {
            var options = Options(scope);
            File.WriteAllText(options.DistributionRecord, "existing");
            var signer = new Signer(_ => { });
            Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Execute(
                options, signer, new Inspector(), new FixedDatabase(), new AtomicMsiDistributionRecordPublisher()));
            Assert.AreEqual("existing", File.ReadAllText(options.DistributionRecord));
            Assert.AreEqual(0, signer.Calls);
        }
        using (var scope = new MsiVerificationFoundationTests.Scope())
        {
            var options = Options(scope);
            var signer = new Signer(path => File.WriteAllBytes(path, MsiCompoundFixture.Create(signatures: true)));
            Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Execute(
                options, signer, new Inspector(), new FixedDatabase(), new ThrowingPublisher()));
            Assert.AreEqual(1, signer.Calls);
            Assert.IsFalse(File.Exists(options.DistributionRecord));
        }
    }

    [TestMethod]
    public void Plan_parent_substitution_cannot_validate_different_canonical_bytes()
    {
        using var scope = new MsiVerificationFoundationTests.Scope();
        var parent = Path.Combine(scope.Root, "plan-parent");
        var alternate = Path.Combine(scope.Root, "alternate-plan-parent");
        var parked = Path.Combine(scope.Root, "parked-plan-parent");
        Directory.CreateDirectory(parent);
        Directory.CreateDirectory(alternate);
        var planPath = Path.Combine(parent, InstallerInputValidator.PlanFileName);
        File.Move(scope.Plan, planPath);
        File.WriteAllText(Path.Combine(alternate, InstallerInputValidator.PlanFileName),
            InstallerInputValidator.CreateCanonicalPlan(new InstallerInputValidator().CreatePlan(scope.Layout, "0.2.0")));
        var originalHash = scope.Hash(planPath);
        Assert.AreNotEqual(originalHash, scope.Hash(Path.Combine(alternate, InstallerInputValidator.PlanFileName)));
        var options = Options(scope) with { InstallerPlan = planPath };
        var substituted = false;
        try
        {
            var signer = new Signer(path =>
            {
                File.WriteAllBytes(path, MsiCompoundFixture.Create(signatures: true));
                SubstituteParent(parent, alternate, parked);
                substituted = true;
            });
            Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Execute(options, signer,
                new Inspector(), new FixedDatabase(), new AtomicMsiDistributionRecordPublisher()));
            Assert.AreEqual(1, signer.Calls);
            Assert.IsFalse(File.Exists(options.DistributionRecord));
        }
        finally
        {
            if (substituted) RestoreParent(parent, alternate, parked);
        }
        Assert.AreEqual(originalHash, scope.Hash(planPath));
    }

    [TestMethod]
    public void Release_record_parent_substitution_cannot_validate_different_canonical_bytes()
    {
        using var scope = new MsiVerificationFoundationTests.Scope();
        var parent = scope.Layout;
        var alternate = Path.Combine(scope.Root, "alternate-layout");
        var parked = Path.Combine(scope.Root, "parked-layout");
        CopyDirectory(parent, alternate);
        var recordPath = Path.Combine(parent, BetaReleaseLayoutValidator.RecordFileName);
        var alternateRecordPath = Path.Combine(alternate, BetaReleaseLayoutValidator.RecordFileName);
        Assert.IsTrue(BetaReleaseRecordCodec.TryParse(File.ReadAllBytes(alternateRecordPath), out var record));
        Assert.IsNotNull(record);
        var alternateEvidence = record.AuthenticodeEvidence.Select(item => item with { SignerPolicyId = "other-publisher-policy" }).ToArray();
        File.WriteAllBytes(alternateRecordPath, BetaReleaseRecordCodec.CreateCanonical(record with
        { AuthenticodeEvidence = Array.AsReadOnly(alternateEvidence) }));
        var originalHash = scope.Hash(recordPath);
        Assert.AreNotEqual(originalHash, scope.Hash(alternateRecordPath));
        var options = Options(scope);
        var substituted = false;
        try
        {
            var signer = new Signer(path =>
            {
                File.WriteAllBytes(path, MsiCompoundFixture.Create(signatures: true));
                SubstituteParent(parent, alternate, parked);
                substituted = true;
            });
            Assert.ThrowsExactly<IOException>(() => MsiDistributionCommand.Execute(options, signer,
                new Inspector(), new FixedDatabase(), new AtomicMsiDistributionRecordPublisher()));
            Assert.AreEqual(1, signer.Calls);
            Assert.IsFalse(File.Exists(options.DistributionRecord));
        }
        finally
        {
            if (substituted) RestoreParent(parent, alternate, parked);
        }
        Assert.AreEqual(originalHash, scope.Hash(recordPath));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void Retained_plan_and_record_bytes_survive_leaf_substitution_attempt(bool releaseRecord)
    {
        using var scope = new MsiVerificationFoundationTests.Scope();
        var path = releaseRecord ? Path.Combine(scope.Layout, BetaReleaseLayoutValidator.RecordFileName) : scope.Plan;
        var replacement = Path.Combine(scope.Root, releaseRecord ? "replacement-record.txt" : "replacement-plan.txt");
        if (releaseRecord)
        {
            Assert.IsTrue(BetaReleaseRecordCodec.TryParse(File.ReadAllBytes(path), out var parsed));
            Assert.IsNotNull(parsed);
            var evidence = parsed.AuthenticodeEvidence.Select(item => item with { SignerPolicyId = "replacement-policy" }).ToArray();
            File.WriteAllBytes(replacement, BetaReleaseRecordCodec.CreateCanonical(parsed with
            { AuthenticodeEvidence = Array.AsReadOnly(evidence) }));
        }
        else
            File.WriteAllText(replacement, InstallerInputValidator.CreateCanonicalPlan(
                new InstallerInputValidator().CreatePlan(scope.Layout, "0.2.0")));
        using var bound = RetainedCanonicalInput.Open(path);
        var initialBytes = bound.ReadBytes(1024 * 1024);
        var initialHash = Convert.ToHexString(SHA256.HashData(initialBytes));
        Assert.AreNotEqual(initialHash, scope.Hash(replacement));
        var replaced = false;
        try { File.Move(replacement, path, true); replaced = true; }
        catch (IOException) { /* The retained read handle may prevent replacement outright. */ }
        catch (UnauthorizedAccessException) { /* Windows may report a sharing denial as access denied. */ }
        Assert.AreEqual(initialHash, HashHandle(bound.Handle));
        if (replaced) Assert.ThrowsExactly<IOException>(bound.RequireUnchanged);
        else bound.RequireUnchanged();
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void Retained_plan_and_record_hashes_survive_parent_substitution_attempt(bool releaseRecord)
    {
        using var scope = new MsiVerificationFoundationTests.Scope();
        var parent = releaseRecord ? scope.Layout : Path.Combine(scope.Root, "plan-parent");
        if (!releaseRecord)
        {
            Directory.CreateDirectory(parent);
            File.Move(scope.Plan, Path.Combine(parent, InstallerInputValidator.PlanFileName));
        }
        var path = Path.Combine(parent, releaseRecord ? BetaReleaseLayoutValidator.RecordFileName : InstallerInputValidator.PlanFileName);
        var alternate = Path.Combine(scope.Root, "alternate-parent");
        var parked = Path.Combine(scope.Root, "parked-parent");
        CopyDirectory(parent, alternate);
        using var bound = RetainedCanonicalInput.Open(path);
        var initialHash = HashHandle(bound.Handle);
        var substituted = false;
        try
        {
            try { SubstituteParent(parent, alternate, parked); substituted = true; }
            catch (IOException) { /* The retained handle may prevent a parent rename. */ }
            catch (UnauthorizedAccessException) { /* Windows may report a sharing denial as access denied. */ }
            Assert.AreEqual(initialHash, HashHandle(bound.Handle));
            if (substituted) Assert.ThrowsExactly<IOException>(bound.RequireUnchanged);
            else bound.RequireUnchanged();
        }
        finally
        {
            if (substituted) RestoreParent(parent, alternate, parked);
        }
    }

    private static string HashHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle)
    {
        var length = RandomAccess.GetLength(handle);
        var bytes = new byte[checked((int)length)];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var count = RandomAccess.Read(handle, bytes.AsSpan(offset), offset);
            Assert.AreNotEqual(0, count);
            offset += count;
        }
        return Convert.ToHexString(SHA256.HashData(bytes));
    }

    private static void SubstituteParent(string parent, string alternate, string parked)
    {
        Directory.Move(parent, parked);
        try { Directory.Move(alternate, parent); }
        catch { Directory.Move(parked, parent); throw; }
    }

    private static void RestoreParent(string parent, string alternate, string parked)
    {
        Directory.Move(parent, alternate);
        Directory.Move(parked, parent);
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(source, directory)));
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
            File.Copy(file, Path.Combine(destination, Path.GetRelativePath(source, file)));
    }

    private static MsiDistributionOptions Options(MsiVerificationFoundationTests.Scope scope) =>
        new(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination,
            Path.Combine(scope.Root, MsiDistributionRecordCodec.FileName),
            Path.Combine(scope.Root, "signtool.exe"), Path.Combine(scope.Root, "dlib.dll"), Path.Combine(scope.Root, "metadata.json"));

    private static string[] Arguments(MsiDistributionOptions options) =>
    [
        "sign-msi-distribution", "--output-root", options.OutputRoot, "--installer-plan", options.InstallerPlan,
        "--unsigned-msi", options.UnsignedMsi, "--unsigned-msi-sha256", options.UnsignedMsiSha256,
        "--signed-msi", options.SignedMsi, "--distribution-record", options.DistributionRecord,
        "--signtool", options.SignTool, "--dlib", options.Dlib, "--metadata", options.Metadata
    ];

    private static MsiAuthenticodeInspectionResult GoodInspection() => new(true, NativeAuthenticodeTrustCategory.Success,
        PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256,
        TimestampPolicyCategory.ValidRfc3161, AuthenticodeEkuPolicyCategory.Match);

    private sealed class FixedDatabase : IMsiDatabaseValidator
    {
        public bool IsReadOnlyDatabase(string path) => File.ReadAllBytes(path).AsSpan().StartsWith(
            new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 });
    }
    private sealed class Inspector(bool accepted = true) : IMsiAuthenticodeInspector
    {
        public MsiAuthenticodeInspectionResult Inspect(string path) => throw new AssertFailedException();
        public MsiAuthenticodeInspectionResult Inspect(MsiFileBinding binding)
        { binding.RequireUnchanged(); return accepted ? GoodInspection() : GoodInspection() with { Success = false }; }
    }
    private sealed class Signer(Action<string> action, bool succeeds = true) : IMsiSigningRequest
    {
        internal int Calls;
        public bool Sign(string path) { Calls++; action(path); return succeeds; }
    }
    private sealed class Runner(int exitCode) : IMsiSignToolProcessRunner
    {
        internal int Calls; internal string? Executable; internal string[] Arguments = [];
        public int Run(string executable, IReadOnlyList<string> arguments)
        { Calls++; Executable = executable; Arguments = arguments.ToArray(); return exitCode; }
    }
    private sealed class ObservingPublisher(Action observe) : IMsiDistributionRecordPublisher
    {
        internal int Calls;
        public void Publish(string path, ReadOnlySpan<byte> bytes)
        { Calls++; observe(); new AtomicMsiDistributionRecordPublisher().Publish(path, bytes); }
    }
    private sealed class ThrowingPublisher : IMsiDistributionRecordPublisher
    {
        public void Publish(string path, ReadOnlySpan<byte> bytes) => throw new IOException("synthetic publication failure");
    }
}
