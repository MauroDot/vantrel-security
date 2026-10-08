using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
public sealed class SinglePeAuthenticodeInspectionTests
{
    private const int PrivilegeNotHeldHResult = unchecked((int)0x80070522);

    [TestMethod]
    public void Valid_windows_evidence_with_the_exact_ekus_is_a_sanitized_success()
    {
        using var scope = new PeScope();
        var native = new FixedNativeVerifier(ValidEvidence());

        var result = new SinglePeAuthenticodeInspector(native).Inspect(scope.PePath);

        Assert.IsTrue(result.Success);
        Assert.AreEqual(SinglePeAuthenticodeInspector.PolicyId, result.PolicyId);
        Assert.AreEqual(PrimarySignatureCountPolicyCategory.ExactlyOne, result.PrimarySignatureCount);
        Assert.AreEqual(TimestampPolicyCategory.ValidRfc3161, result.Timestamp);
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.Match, result.EkuCategory);
        Assert.AreEqual(1, native.Calls);
        Assert.IsTrue(native.ReceivedValidHandle);
    }

    [DataTestMethod]
    [DataRow(AzureArtifactSigningEkuPolicy.AzureArtifactSigningPublicTrustEku, AzureArtifactSigningEkuPolicy.VantrelCertificateProfileEku)]
    [DataRow(AzureArtifactSigningEkuPolicy.CodeSigningEku, AzureArtifactSigningEkuPolicy.VantrelCertificateProfileEku)]
    [DataRow(AzureArtifactSigningEkuPolicy.CodeSigningEku, AzureArtifactSigningEkuPolicy.AzureArtifactSigningPublicTrustEku)]
    [DataRow(AzureArtifactSigningEkuPolicy.CodeSigningEku, AzureArtifactSigningEkuPolicy.AzureArtifactSigningPublicTrustEku, "1.3.6.1.4.1.311.97.790899309.69055806.5460467.69741028")]
    public void Missing_or_wrong_required_eku_is_rejected(params string[] ekus)
    {
        using var scope = new PeScope();
        var result = new SinglePeAuthenticodeInspector(new FixedNativeVerifier(ValidEvidence(ekus))).Inspect(scope.PePath);

        Assert.IsFalse(result.Success);
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.Rejected, result.EkuCategory);
    }

    [TestMethod]
    public void Missing_or_malformed_signer_evidence_is_never_authorized()
    {
        using var scope = new PeScope();
        var evidence = new NativeAuthenticodeEvidence(NativeAuthenticodeTrustCategory.Success,
            PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256,
            TimestampPolicyCategory.ValidRfc3161, null);

        var result = new SinglePeAuthenticodeInspector(new FixedNativeVerifier(evidence)).Inspect(scope.PePath);

        Assert.IsFalse(result.Success);
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.MissingOrMalformed, result.EkuCategory);
    }

    [TestMethod]
    public void Unsigned_or_failed_wintrust_evidence_is_rejected_before_eku_evaluation()
    {
        using var scope = new PeScope();
        var evidence = new NativeAuthenticodeEvidence(NativeAuthenticodeTrustCategory.Unsigned,
            PrimarySignatureCountPolicyCategory.None, NativeDigestAlgorithmCategory.Indeterminate,
            TimestampPolicyCategory.Indeterminate, null);

        var result = new SinglePeAuthenticodeInspector(new FixedNativeVerifier(evidence)).Inspect(scope.PePath);

        Assert.IsFalse(result.Success);
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.NotEvaluated, result.EkuCategory);
    }

    [TestMethod]
    public void Altered_or_nonzero_wintrust_evidence_is_rejected_before_eku_evaluation_without_disclosure()
    {
        using var scope = new PeScope();
        var certificateHash = new string('B', 64);
        var evidence = new NativeAuthenticodeEvidence(NativeAuthenticodeTrustCategory.AlteredOrNonzero,
            PrimarySignatureCountPolicyCategory.Indeterminate, NativeDigestAlgorithmCategory.Indeterminate,
            TimestampPolicyCategory.Indeterminate, ValidEvidenceWithHash(certificateHash).Signer);

        var result = new SinglePeAuthenticodeInspector(new FixedNativeVerifier(evidence)).Inspect(scope.PePath);
        var output = SinglePeAuthenticodeInspectionOutput.Create(result);

        Assert.IsFalse(result.Success);
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.NotEvaluated, result.EkuCategory);
        AssertSanitized(output, scope, certificateHash);
    }

    [TestMethod]
    public void Malformed_extracted_eku_evidence_is_fail_closed_without_disclosure()
    {
        using var scope = new PeScope();
        var certificateHash = new string('E', 64);
        Assert.ThrowsException<ArgumentException>(() => new SignerCertificateEvidence(certificateHash, ["not-an-oid"]));

        var result = new SinglePeAuthenticodeInspector(new ThrowingNativeVerifier(new AuthenticodeProviderUnavailableException())).Inspect(scope.PePath);
        var output = SinglePeAuthenticodeInspectionOutput.Create(result);

        Assert.IsFalse(result.Success);
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.NotEvaluated, result.EkuCategory);
        AssertSanitized(output, scope, certificateHash);
    }

    [TestMethod]
    public void Missing_directory_and_non_pe_inputs_are_rejected_before_native_inspection()
    {
        using var scope = new PeScope();
        var native = new FixedNativeVerifier(ValidEvidence());
        var inspector = new SinglePeAuthenticodeInspector(native);
        var nonPe = Path.Combine(scope.Root, "not-pe.bin");
        File.WriteAllText(nonPe, "not a portable executable");

        Assert.ThrowsException<IOException>(() => inspector.Inspect(Path.Combine(scope.Root, "missing.exe")));
        Assert.ThrowsException<IOException>(() => inspector.Inspect(scope.Root));
        Assert.ThrowsException<IOException>(() => inspector.Inspect(nonPe));
        Assert.AreEqual(0, native.Calls);
    }

    [TestMethod]
    public void Reparse_input_is_rejected_when_symbolic_links_are_permitted()
    {
        using var scope = new PeScope();
        var link = Path.Combine(scope.Root, "linked.exe");
        try { File.CreateSymbolicLink(link, scope.PePath); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeldHResult) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }

        var native = new FixedNativeVerifier(ValidEvidence());
        Assert.ThrowsException<IOException>(() => new SinglePeAuthenticodeInspector(native).Inspect(link));
        Assert.AreEqual(0, native.Calls);
    }

    [TestMethod]
    public void Sanitized_output_never_contains_path_or_certificate_evidence()
    {
        using var scope = new PeScope();
        var certificateHash = new string('A', 64);
        var result = new SinglePeAuthenticodeInspector(new FixedNativeVerifier(ValidEvidenceWithHash(certificateHash))).Inspect(scope.PePath);

        var output = SinglePeAuthenticodeInspectionOutput.Create(result);

        StringAssert.Contains(output, "result=success");
        StringAssert.Contains(output, "policy-id=" + SinglePeAuthenticodeInspector.PolicyId);
        AssertSanitized(output, scope, certificateHash);
    }

    [TestMethod]
    public void Production_profile_requires_the_exact_three_ekus_and_unknown_profiles_fail_closed()
    {
        var profiles = new SourceOwnedReleaseSigningProfileSource();
        Assert.IsTrue(profiles.TryGet("vantrel-production", out var profile));
        Assert.IsTrue(profile.IsConfigured);
        Assert.AreEqual("vantrel-azure-artifact-signing-durable-eku-v1", profile.PolicyId);
        Assert.IsInstanceOfType<AzureArtifactSigningEkuPolicy>(profile.PublisherPolicy);
        Assert.AreEqual("1.3.6.1.5.5.7.3.3", AzureArtifactSigningEkuPolicy.CodeSigningEku);
        Assert.AreEqual("1.3.6.1.4.1.311.97.1.0", AzureArtifactSigningEkuPolicy.AzureArtifactSigningPublicTrustEku);
        Assert.AreEqual("1.3.6.1.4.1.311.97.790899309.69055806.5460467.69741027", AzureArtifactSigningEkuPolicy.VantrelCertificateProfileEku);
        Assert.IsTrue(profile.PublisherPolicy.Matches(ValidEvidence().Signer!));
        Assert.IsFalse(profile.PublisherPolicy.Matches(ValidEvidence(
            AzureArtifactSigningEkuPolicy.CodeSigningEku,
            AzureArtifactSigningEkuPolicy.AzureArtifactSigningPublicTrustEku,
            "1.3.6.1.4.1.311.97.790899309.69055806.5460467.69741028").Signer!));
        Assert.IsFalse(profiles.TryGet("unknown-profile", out _));
    }

    private static NativeAuthenticodeEvidence ValidEvidence(params string[] ekus) => ValidEvidenceWithHash(new string('C', 64), ekus);

    private static NativeAuthenticodeEvidence ValidEvidenceWithHash(string certificateHash, params string[] ekus) => new(
        NativeAuthenticodeTrustCategory.Success, PrimarySignatureCountPolicyCategory.ExactlyOne,
        NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.ValidRfc3161,
        new SignerCertificateEvidence(certificateHash, ekus.Length == 0 ?
        [AzureArtifactSigningEkuPolicy.CodeSigningEku, AzureArtifactSigningEkuPolicy.AzureArtifactSigningPublicTrustEku,
            AzureArtifactSigningEkuPolicy.VantrelCertificateProfileEku] : ekus));

    private static void AssertSanitized(string output, PeScope scope, string certificateHash)
    {
        Assert.IsFalse(output.Contains(scope.Root, StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(output.Contains(scope.PePath, StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(output.Contains(certificateHash, StringComparison.Ordinal));
        Assert.IsFalse(output.Contains("subject", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(output.Contains("issuer", StringComparison.OrdinalIgnoreCase));
    }

    private sealed class FixedNativeVerifier(NativeAuthenticodeEvidence evidence) : IAuthenticodeNativeVerifier
    {
        internal int Calls { get; private set; }
        internal bool ReceivedValidHandle { get; private set; }
        public NativeAuthenticodeEvidence Verify(string absolutePath, SafeFileHandle fileHandle)
        {
            Calls++;
            ReceivedValidHandle = fileHandle is not null && !fileHandle.IsClosed && !fileHandle.IsInvalid;
            return evidence;
        }
    }

    private sealed class ThrowingNativeVerifier(Exception error) : IAuthenticodeNativeVerifier
    {
        public NativeAuthenticodeEvidence Verify(string absolutePath, SafeFileHandle fileHandle) => throw error;
    }

    private sealed class PeScope : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-single-pe-" + Guid.NewGuid().ToString("N"));
        internal string PePath => Path.Combine(Root, "input.exe");

        internal PeScope()
        {
            Directory.CreateDirectory(Root);
            var bytes = new byte[0x100];
            bytes[0] = (byte)'M'; bytes[1] = (byte)'Z'; BitConverter.GetBytes(0x80).CopyTo(bytes, 60);
            bytes[0x80] = (byte)'P'; bytes[0x81] = (byte)'E';
            File.WriteAllBytes(PePath, bytes);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
