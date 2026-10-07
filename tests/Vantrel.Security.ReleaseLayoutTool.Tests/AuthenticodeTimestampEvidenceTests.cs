using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
public sealed class AuthenticodeTimestampEvidenceTests
{
    private static readonly byte[] SignedData = [1, 2, 3];
    private static readonly byte[] TimestampToken = [4, 5, 6];

    [TestMethod]
    public void Windows_rfc3161_countersignature_attribute_is_accepted_only_after_cryptographic_validation()
    {
        var result = AuthenticodeTimestampEvidence.Classify(
            [new(AuthenticodeTimestampEvidence.WindowsRfc3161CounterSignOid, [TimestampToken])], SignedData,
            new FixedTimestampVerifier(valid: true, "2.16.840.1.101.3.4.2.1"));

        Assert.AreEqual(TimestampPolicyCategory.ValidRfc3161, result);
    }

    [TestMethod]
    public void Existing_cms_timestamp_token_attribute_remains_supported()
    {
        var result = AuthenticodeTimestampEvidence.Classify(
            [new(AuthenticodeTimestampEvidence.CmsTimestampTokenOid, [TimestampToken])], SignedData,
            new FixedTimestampVerifier(valid: true, "2.16.840.1.101.3.4.2.2"));

        Assert.AreEqual(TimestampPolicyCategory.ValidRfc3161, result);
    }

    [TestMethod]
    public void Absent_legacy_unrelated_malformed_and_invalid_timestamp_evidence_remain_fail_closed()
    {
        var valid = new FixedTimestampVerifier(valid: true, "2.16.840.1.101.3.4.2.1");
        Assert.AreEqual(TimestampPolicyCategory.Missing, AuthenticodeTimestampEvidence.Classify([], SignedData, valid));
        Assert.AreEqual(TimestampPolicyCategory.LegacyOnly, AuthenticodeTimestampEvidence.Classify(
            [new(AuthenticodeTimestampEvidence.LegacyCountersignatureOid, [TimestampToken])], SignedData, valid));
        Assert.AreEqual(TimestampPolicyCategory.Missing, AuthenticodeTimestampEvidence.Classify(
            [new("1.3.6.1.4.1.311.3.3.2", [TimestampToken])], SignedData, valid));
        Assert.AreEqual(TimestampPolicyCategory.Invalid, AuthenticodeTimestampEvidence.Classify(
            [new(AuthenticodeTimestampEvidence.WindowsRfc3161CounterSignOid, Array.Empty<byte[]>())], SignedData, valid));
        Assert.AreEqual(TimestampPolicyCategory.Invalid, AuthenticodeTimestampEvidence.Classify(
            [new(AuthenticodeTimestampEvidence.WindowsRfc3161CounterSignOid, [TimestampToken, TimestampToken])], SignedData, valid));
        Assert.AreEqual(TimestampPolicyCategory.Invalid, AuthenticodeTimestampEvidence.Classify(
            [new(AuthenticodeTimestampEvidence.WindowsRfc3161CounterSignOid, [TimestampToken])], SignedData,
            new FixedTimestampVerifier(valid: false, string.Empty)));
    }

    [TestMethod]
    public void Timestamp_evidence_never_bypasses_wintrust_or_required_ekus()
    {
        using var scope = new PeScope();
        var signer = new SignerCertificateEvidence(new string('C', 64),
            [AzureArtifactSigningEkuPolicy.CodeSigningEku, AzureArtifactSigningEkuPolicy.AzureArtifactSigningPublicTrustEku]);
        var altered = new NativeAuthenticodeEvidence(NativeAuthenticodeTrustCategory.AlteredOrNonzero,
            PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256,
            TimestampPolicyCategory.ValidRfc3161, signer);
        var trustedWrongEku = altered with { Trust = NativeAuthenticodeTrustCategory.Success };

        Assert.IsFalse(new SinglePeAuthenticodeInspector(new FixedNativeVerifier(altered)).Inspect(scope.Path).Success);
        var result = new SinglePeAuthenticodeInspector(new FixedNativeVerifier(trustedWrongEku)).Inspect(scope.Path);
        Assert.IsFalse(result.Success);
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.Rejected, result.EkuCategory);
    }

    private sealed class FixedTimestampVerifier(bool valid, string algorithm) : IAuthenticodeTimestampEvidenceVerifier
    {
        public bool Verify(byte[] timestampToken, byte[] signedData, out string digestAlgorithmOid)
        {
            digestAlgorithmOid = algorithm;
            return valid;
        }
    }

    private sealed class FixedNativeVerifier(NativeAuthenticodeEvidence evidence) : IAuthenticodeNativeVerifier
    {
        public NativeAuthenticodeEvidence Verify(string absolutePath, Microsoft.Win32.SafeHandles.SafeFileHandle fileHandle) => evidence;
    }

    private sealed class PeScope : IDisposable
    {
        private readonly string _root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "vantrel-timestamp-" + Guid.NewGuid().ToString("N"));
        internal string Path => System.IO.Path.Combine(_root, "input.exe");
        internal PeScope()
        {
            Directory.CreateDirectory(_root);
            var bytes = new byte[0x100];
            bytes[0] = (byte)'M'; bytes[1] = (byte)'Z'; BitConverter.GetBytes(0x80).CopyTo(bytes, 60);
            bytes[0x80] = (byte)'P'; bytes[0x81] = (byte)'E'; File.WriteAllBytes(Path, bytes);
        }
        public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true); }
    }
}
