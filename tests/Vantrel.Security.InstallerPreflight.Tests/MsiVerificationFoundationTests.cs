using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Vantrel.Security.ManifestTool;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vantrel.Security.InstallerPreflight;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.InstallerPreflight.Tests;

[TestClass]
public sealed class MsiVerificationFoundationTests
{
    private const int PrivilegeNotHeld = unchecked((int)0x80070522);

    [TestMethod]
    public void Distribution_codec_is_canonical_public_only_and_rejects_malformed_fields()
    {
        var record = GoodRecord();
        var bytes = MsiDistributionRecordCodec.CreateCanonical(record);
        Assert.IsTrue(MsiDistributionRecordCodec.TryParse(bytes, out var parsed));
        Assert.AreEqual(record, parsed);
        var text = Encoding.ASCII.GetString(bytes);
        foreach (var changed in new[]
        {
            text.Replace("msi-file=VantrelSecurity.msi", "msi-file=../escape.msi", StringComparison.Ordinal),
            text.Replace("msi-file=VantrelSecurity.msi", "msi-file=C:escape.msi", StringComparison.Ordinal),
            text.Replace("msi-file=VantrelSecurity.msi", "msi-file=VantrelSecurity.msi\nmsi-file=duplicate.msi", StringComparison.Ordinal),
            text.Replace("schema=", "unknown=", StringComparison.Ordinal),
            text.Replace("digest=Sha256", "digest=Unsupported", StringComparison.Ordinal),
            text.Replace("timestamp=ValidRfc3161", "timestamp=Missing", StringComparison.Ordinal),
            text.Replace("\n", "\r\n", StringComparison.Ordinal)
        }) Assert.IsFalse(MsiDistributionRecordCodec.TryParse(Encoding.ASCII.GetBytes(changed), out _));
        Assert.IsFalse(MsiDistributionRecordCodec.TryParse([0xEF, 0xBB, 0xBF, .. bytes], out _));
        Assert.IsFalse(text.Contains("C:\\", StringComparison.Ordinal));
    }

    [TestMethod]
    public void One_copy_one_injected_request_and_final_hash_binding()
    {
        using var scope = new Scope();
        var signer = new Signer(path => File.WriteAllBytes(path, MsiCompoundFixture.Create(signatures: true, rootModified: 7)));
        var inspector = new Inspector(_ => GoodInspection());
        var result = NewOrchestrator(signer, inspector).CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination);
        Assert.AreEqual(1, signer.Calls);
        Assert.AreEqual(1, inspector.Calls);
        Assert.AreEqual(scope.SourceHash, scope.Hash(scope.Source));
        Assert.AreEqual(scope.Hash(scope.Destination), result.FinalMsiSha256);
        Assert.AreNotEqual(scope.SourceHash, result.FinalMsiSha256);
    }

    [TestMethod]
    public void Changed_input_and_existing_output_fail_before_signing()
    {
        using var scope = new Scope();
        var signer = new Signer(_ => { });
        var orchestrator = NewOrchestrator(signer, new Inspector(_ => GoodInspection()));
        Assert.ThrowsExactly<IOException>(() => orchestrator.CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, new string('A', 64), scope.Destination));
        Assert.AreEqual(0, signer.Calls);
        Directory.CreateDirectory(Path.GetDirectoryName(scope.Destination)!);
        System.IO.File.WriteAllText(scope.Destination, "existing");
        Assert.ThrowsExactly<IOException>(() => orchestrator.CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
        Assert.AreEqual(0, signer.Calls);
    }

    [TestMethod]
    public void A_copy_destination_inside_the_completed_layout_is_rejected()
    {
        using var scope = new Scope();
        var signer = new Signer(_ => { });
        Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, new Inspector(_ => GoodInspection()))
            .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, Path.Combine(scope.Layout, "signed.msi")));
        Assert.AreEqual(0, signer.Calls);
    }

    [TestMethod]
    public void Renamed_non_msi_input_is_rejected_before_signing()
    {
        using var scope = new Scope();
        System.IO.File.WriteAllText(scope.Source, "not an installer database");
        var signer = new Signer(_ => { });
        Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, new Inspector(_ => GoodInspection()))
            .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
        Assert.AreEqual(0, signer.Calls);
    }

    [TestMethod]
    public void Signer_failure_stops_without_retry_or_verification()
    {
        using var scope = new Scope();
        var signer = new Signer(_ => { }, succeeds: false);
        var inspector = new Inspector(_ => GoodInspection());
        Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, inspector)
            .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
        Assert.AreEqual(1, signer.Calls);
        Assert.AreEqual(0, inspector.Calls);
    }

    [TestMethod]
    public void Source_and_output_mutation_fail_closed()
    {
        using (var scope = new Scope())
        {
            var signer = new Signer(_ => System.IO.File.AppendAllText(scope.Source, "mutated"));
            Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, new Inspector(_ => GoodInspection()))
                .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
        }
        using (var scope = new Scope())
        {
            var signer = new Signer(_ => { });
            var inspector = new Inspector(path => { AppendWithSharing(path, "changed-after-inspection"); return GoodInspection(); });
            Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, inspector)
                .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
            Assert.AreEqual(1, signer.Calls);
        }
    }

    [TestMethod]
    public void Final_inspection_retains_a_write_denying_handle()
    {
        using var scope = new Scope();
        var blocked = false;
        var signer = new Signer(path => File.WriteAllBytes(path, MsiCompoundFixture.Create(signatures: true)));
        var inspector = new Inspector(path =>
        {
            try { using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); }
            catch (IOException) { blocked = true; }
            return GoodInspection();
        });
        var result = NewOrchestrator(signer, inspector).CopySignAndInspect(
            scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination);
        Assert.IsTrue(blocked);
        Assert.AreEqual(scope.Hash(scope.Destination), result.FinalMsiSha256);
    }

    [TestMethod]
    public void Changed_staging_file_acl_fails_after_signing()
    {
        using var scope = new Scope();
        var signer = new Signer(path =>
        {
            File.WriteAllBytes(path, MsiCompoundFixture.Create(signatures: true));
            var info = new FileInfo(path);
            var acl = info.GetAccessControl();
            acl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.ReadData,
                AccessControlType.Allow));
            info.SetAccessControl(acl);
        });
        Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, new Inspector(_ => GoodInspection()))
            .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
        Assert.AreEqual(1, signer.Calls);
    }

    [TestMethod]
    public void Source_replacement_is_blocked_and_destination_replacement_is_detected()
    {
        foreach (var replaceSource in new[] { true, false })
        {
            using var scope = new Scope();
            var replacement = Path.Combine(scope.Root, "replacement.msi");
            File.WriteAllBytes(replacement, File.ReadAllBytes(scope.Source));
            var signer = new Signer(_ => File.Move(replacement, replaceSource ? scope.Source : scope.Destination, true));
            var inspector = new Inspector(_ => GoodInspection());
            Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, inspector)
                .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
            Assert.AreEqual(1, signer.Calls);
            Assert.AreEqual(0, inspector.Calls);
        }
    }

    [TestMethod]
    public void Parent_substitution_is_detected_without_claiming_a_rename_barrier()
    {
        using var scope = new Scope();
        var parent = Path.GetDirectoryName(scope.Destination)!;
        var signer = new Signer(_ => Directory.Move(parent, parent + "-moved"));
        Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, new Inspector(_ => GoodInspection()))
            .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
        Assert.AreEqual(1, signer.Calls);
    }

    [TestMethod]
    public void Incomplete_layout_and_mismatched_plan_fail_before_copy()
    {
        using (var scope = new Scope())
        {
            File.Delete(Path.Combine(scope.Layout, "desktop", "Vantrel.Security.Desktop.exe"));
            var signer = new Signer(_ => { });
            Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, new Inspector(_ => GoodInspection()))
                .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
            Assert.AreEqual(0, signer.Calls);
            Assert.IsFalse(File.Exists(scope.Destination));
        }
        using (var scope = new Scope())
        {
            File.WriteAllText(scope.Plan, File.ReadAllText(scope.Plan).Replace("release-version=0.1.0-beta.1", "release-version=0.1.0-beta.2", StringComparison.Ordinal));
            var signer = new Signer(_ => { });
            Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, new Inspector(_ => GoodInspection()))
                .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
            Assert.AreEqual(0, signer.Calls);
        }
    }

    [TestMethod]
    public void Reparse_source_fails_before_signing_when_symbolic_links_are_permitted()
    {
        using var scope = new Scope();
        var link = Path.Combine(scope.Root, "linked.msi");
        try { System.IO.File.CreateSymbolicLink(link, scope.Source); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeld) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }
        var signer = new Signer(_ => { });
        Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, new Inspector(_ => GoodInspection()))
            .CopySignAndInspect(scope.Layout, scope.Plan, link, scope.SourceHash, scope.Destination));
        Assert.AreEqual(0, signer.Calls);
    }

    [TestMethod]
    public void Reparse_output_fails_before_signing_when_symbolic_links_are_permitted()
    {
        using var scope = new Scope();
        var target = Path.Combine(scope.Root, "target.msi");
        System.IO.File.WriteAllText(target, "must remain unchanged");
        Directory.CreateDirectory(Path.GetDirectoryName(scope.Destination)!);
        try { System.IO.File.CreateSymbolicLink(scope.Destination, target); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeld) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }
        var signer = new Signer(_ => { });
        Assert.ThrowsExactly<IOException>(() => NewOrchestrator(signer, new Inspector(_ => GoodInspection()))
            .CopySignAndInspect(scope.Layout, scope.Plan, scope.Source, scope.SourceHash, scope.Destination));
        Assert.AreEqual(0, signer.Calls);
        Assert.AreEqual("must remain unchanged", System.IO.File.ReadAllText(target));
    }

    private static MsiDistributionRecord GoodRecord() => new("VantrelSecurity.msi", new string('A', 64), new string('B', 64),
        new string('C', 64), MsiAuthenticodeInspectionResult.PolicyId, NativeAuthenticodeTrustCategory.Success,
        PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256,
        TimestampPolicyCategory.ValidRfc3161, AuthenticodeEkuPolicyCategory.Match);
    private static MsiAuthenticodeInspectionResult GoodInspection() => new(true, NativeAuthenticodeTrustCategory.Success,
        PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256,
        TimestampPolicyCategory.ValidRfc3161, AuthenticodeEkuPolicyCategory.Match);
    private static InjectedMsiSigningOrchestrator NewOrchestrator(IMsiSigningRequest signer, IMsiAuthenticodeInspector inspector) =>
        new(signer, inspector, new FixedDatabase());
    private static void AppendWithSharing(string path, string content)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        stream.Position = stream.Length;
        stream.Write(Encoding.ASCII.GetBytes(content));
    }
    // Synthetic acceptance exercises orchestration only; real MsiOpenDatabase rejects this tiny fixture.
    private sealed class FixedDatabase : IMsiDatabaseValidator
    {
        public bool IsReadOnlyDatabase(string path) => File.ReadAllBytes(path).AsSpan().StartsWith(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 });
    }
    private sealed class Signer(Action<string> action, bool succeeds = true) : IMsiSigningRequest
    {
        internal int Calls;
        public bool Sign(string path) { Calls++; action(path); return succeeds; }
    }
    private sealed class Inspector(Func<string, MsiAuthenticodeInspectionResult> inspect) : IMsiAuthenticodeInspector
    {
        internal int Calls; internal bool RetainedHandle;
        public MsiAuthenticodeInspectionResult Inspect(string path) => throw new AssertFailedException("Path-only inspection must not be used.");
        public MsiAuthenticodeInspectionResult Inspect(MsiFileBinding binding)
        { Calls++; RetainedHandle = !binding.Handle.IsInvalid && !binding.Handle.IsClosed; binding.RequireUnchanged(); return inspect(binding.Path); }
    }
    internal sealed class Scope : IDisposable
    {
        internal string Root = Path.Combine(Path.GetTempPath(), "vantrel-msi-foundation-" + Guid.NewGuid().ToString("N"));
        internal string Source => Path.Combine(Root, "unsigned.msi");
        internal string Destination => Path.Combine(Root, "stage", "signed.msi");
        internal string Layout => Path.Combine(Root, "layout");
        internal string Plan => Path.Combine(Root, "vantrel-installer-input-v1.txt");
        internal string SourceHash => Hash(Source);
        internal Scope()
        {
            Directory.CreateDirectory(Layout);
            var descriptor = new BetaReleaseDescriptor(new string('a', 40), "0.1.0-beta.1", 7,
                new DateTimeOffset(2026, 10, 5, 0, 0, 0, TimeSpan.Zero), "Release", "win-x64", "10.0.401", new string('0', 64));
            Write("release-notes.md", "# synthetic notes\n");
            descriptor = descriptor with { ReleaseNotesSha256 = Hash(Path.Combine(Layout, "release-notes.md")) };
            File.WriteAllBytes(Path.Combine(Layout, BetaReleaseDescriptorCodec.FileName), BetaReleaseDescriptorCodec.CreateCanonical(descriptor));
            foreach (var file in ReleasePayloadVerifier.ExactFileNames) Write("service/" + file, file);
            foreach (var file in ReleaseSigningContract.VantrelOwnedPeArtifacts.Where(item => !item.RelativePath.StartsWith("service/", StringComparison.Ordinal)))
                Write(file.RelativePath, file.RelativePath);
            Write("desktop/desktop.deps.json", "desktop dependencies");
            Write("offline-update-tool/tool.runtimeconfig.json", "tool runtime");
            var artifacts = new List<ReleaseArtifact>();
            foreach (var fixedFile in new[] { BetaReleaseDescriptorCodec.FileName, "release-notes.md" })
                artifacts.Add(new(fixedFile, Hash(Path.Combine(Layout, fixedFile))));
            foreach (var top in new[] { "service", "desktop", "offline-update-tool" })
                foreach (var file in Directory.EnumerateFiles(Path.Combine(Layout, top), "*", SearchOption.AllDirectories).OrderBy(path => path, StringComparer.Ordinal))
                    artifacts.Add(new(top + "/" + Path.GetRelativePath(Path.Combine(Layout, top), file).Replace('\\', '/'), Hash(file)));
            var evidence = ReleaseSigningContract.VantrelOwnedPeArtifacts.Select(item => new AuthenticodeReleaseEvidence(item.RelativePath,
                AuthenticodeVerificationCategory.Valid, "test-publisher-policy", PrimarySignatureCountPolicyCategory.ExactlyOne, TimestampPolicyCategory.ValidRfc3161)).ToArray();
            var record = new BetaReleaseRecord(descriptor, new Vantrel.Security.ReleaseLayoutTool.VerifiedServicePayload(descriptor.ReleaseVersion, descriptor.ReleaseVersion,
                descriptor.ReleaseSequence, new string('B', 64)), Array.AsReadOnly(artifacts.ToArray()), Array.AsReadOnly(evidence));
            File.WriteAllBytes(Path.Combine(Layout, BetaReleaseLayoutValidator.RecordFileName), BetaReleaseRecordCodec.CreateCanonical(record));
            var plan = new InstallerInputValidator().CreatePlan(Layout, "0.1.0");
            File.WriteAllText(Plan, InstallerInputValidator.CreateCanonicalPlan(plan), new UTF8Encoding(false));
            File.WriteAllBytes(Source, MsiCompoundFixture.Create());
        }
        internal void Write(string relative, string content)
        {
            var path = Path.Combine(Layout, relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, content);
        }
        internal string Hash(string path) => Convert.ToHexString(SHA256.HashData(System.IO.File.ReadAllBytes(path)));
        public void Dispose() => Directory.Delete(Root, true);
    }
}
