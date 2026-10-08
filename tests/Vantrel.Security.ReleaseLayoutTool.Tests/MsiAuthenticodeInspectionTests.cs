using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
public sealed class MsiAuthenticodeInspectionTests
{
    private const int PrivilegeNotHeld = unchecked((int)0x80070522);

    [TestMethod]
    public void Exact_native_evidence_is_inspected_with_retained_handle_and_sanitized_output()
    {
        using var scope = new Scope();
        var native = new FixedNative(Valid());
        var result = new SingleMsiAuthenticodeInspector(native, new FixedDatabase()).Inspect(scope.File);
        var output = MsiAuthenticodeInspectionOutput.Create(result);
        Assert.IsTrue(result.Success);
        Assert.IsTrue(native.ValidHandle);
        StringAssert.Contains(output, "wintrust=Success");
        Assert.IsFalse(output.Contains(scope.Root, StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(output.Contains(new string('A', 64), StringComparison.Ordinal));
        Assert.IsFalse(output.Contains("subject", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Eleven_byte_compound_header_is_not_a_real_installer_database()
    {
        using var scope = new Scope();
        var native = new FixedNative(Valid());
        Assert.ThrowsException<IOException>(() => new SingleMsiAuthenticodeInspector(native).Inspect(scope.File));
        Assert.AreEqual(0, native.Calls);
    }

    [TestMethod]
    public void Database_handle_closes_after_success_failure_and_native_exception()
    {
        foreach (var status in new[] { 0u, 13u })
        {
            var native = new FakeDatabaseNative(status);
            Assert.AreEqual(status == 0, new WindowsMsiDatabaseValidator(native).IsReadOnlyDatabase("input.msi"));
            Assert.AreEqual(1, native.Closes);
        }
        var throwing = new FakeDatabaseNative(0, throws: true);
        Assert.IsFalse(new WindowsMsiDatabaseValidator(throwing).IsReadOnlyDatabase("input.msi"));
        Assert.AreEqual(1, throwing.Closes);
        var closeFailure = new FakeDatabaseNative(0, closeStatus: 5);
        Assert.IsFalse(new WindowsMsiDatabaseValidator(closeFailure).IsReadOnlyDatabase("input.msi"));
        Assert.AreEqual(1, closeFailure.Closes);
    }

    [DataTestMethod]
    [DataRow(NativeAuthenticodeTrustCategory.Unsigned, PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.ValidRfc3161)]
    [DataRow(NativeAuthenticodeTrustCategory.AlteredOrNonzero, PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.ValidRfc3161)]
    [DataRow(NativeAuthenticodeTrustCategory.Success, PrimarySignatureCountPolicyCategory.None, NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.ValidRfc3161)]
    [DataRow(NativeAuthenticodeTrustCategory.Success, PrimarySignatureCountPolicyCategory.ExtraOrDuplicate, NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.ValidRfc3161)]
    [DataRow(NativeAuthenticodeTrustCategory.Success, PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Unsupported, TimestampPolicyCategory.ValidRfc3161)]
    [DataRow(NativeAuthenticodeTrustCategory.Success, PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.Missing)]
    [DataRow(NativeAuthenticodeTrustCategory.Success, PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.LegacyOnly)]
    [DataRow(NativeAuthenticodeTrustCategory.Success, PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.Invalid)]
    [DataRow(NativeAuthenticodeTrustCategory.Success, PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.UnsupportedAlgorithm)]
    public void Any_failed_native_requirement_stays_closed(NativeAuthenticodeTrustCategory trust,
        PrimarySignatureCountPolicyCategory signatures, NativeDigestAlgorithmCategory digest, TimestampPolicyCategory timestamp)
    {
        using var scope = new Scope();
        var evidence = Valid() with { Trust = trust, PrimarySignatureCount = signatures, DigestAlgorithm = digest, Timestamp = timestamp };
        var result = new SingleMsiAuthenticodeInspector(new FixedNative(evidence), new FixedDatabase()).Inspect(scope.File);
        Assert.IsFalse(result.Success);
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.NotEvaluated, result.EkuCategory);
    }

    [TestMethod]
    public void Wrong_or_malformed_eku_cannot_approve_msi()
    {
        using var scope = new Scope();
        var wrong = Valid() with { Signer = new SignerCertificateEvidence(new string('B', 64),
            [AzureArtifactSigningEkuPolicy.CodeSigningEku, AzureArtifactSigningEkuPolicy.AzureArtifactSigningPublicTrustEku]) };
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.Rejected, new SingleMsiAuthenticodeInspector(new FixedNative(wrong), new FixedDatabase()).Inspect(scope.File).EkuCategory);
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.MissingOrMalformed,
            new SingleMsiAuthenticodeInspector(new FixedNative(Valid() with { Signer = null }), new FixedDatabase()).Inspect(scope.File).EkuCategory);
        Assert.ThrowsException<ArgumentException>(() => new SignerCertificateEvidence(new string('B', 64), ["malformed"]));
        var malformed = new SingleMsiAuthenticodeInspector(new ThrowingNative(), new FixedDatabase()).Inspect(scope.File);
        Assert.IsFalse(malformed.Success);
        Assert.AreEqual(AuthenticodeEkuPolicyCategory.NotEvaluated, malformed.EkuCategory);
    }

    [TestMethod]
    public void Non_msi_missing_and_directory_inputs_are_rejected_before_native_work()
    {
        using var scope = new Scope();
        var native = new FixedNative(Valid());
        var inspector = new SingleMsiAuthenticodeInspector(native, new FixedDatabase());
        Assert.ThrowsException<IOException>(() => inspector.Inspect(scope.Root));
        Assert.ThrowsException<IOException>(() => inspector.Inspect(Path.Combine(scope.Root, "missing.msi")));
        var other = Path.Combine(scope.Root, "other.msi"); File.WriteAllText(other, "not compound storage");
        Assert.ThrowsException<IOException>(() => inspector.Inspect(other));
        Assert.AreEqual(0, native.Calls);
    }

    [TestMethod]
    public void Reparse_msi_is_rejected_when_symbolic_links_are_permitted()
    {
        using var scope = new Scope();
        var link = Path.Combine(scope.Root, "linked.msi");
        try { File.CreateSymbolicLink(link, scope.File); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeld) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }
        var native = new FixedNative(Valid());
        Assert.ThrowsException<IOException>(() => new SingleMsiAuthenticodeInspector(native, new FixedDatabase()).Inspect(link));
        Assert.AreEqual(0, native.Calls);
    }

    [TestMethod]
    public void Wintrust_state_is_closed_once_on_success_nonzero_and_evidence_failure()
    {
        foreach (var code in new[] { 0, unchecked((int)0x800B0100) })
        {
            var api = new FakeWinTrust(code);
            var reader = new FixedReader(Valid());
            var native = new WindowsAuthenticodeNativeVerifier(api, reader);
            using var scope = new Scope();
            using var stream = File.OpenRead(scope.File);
            _ = native.Verify(scope.File, stream.SafeFileHandle);
            Assert.AreEqual(1, api.Disposes);
            Assert.AreEqual(code == 0 ? 1 : 0, reader.Calls);
        }
        var failing = new FakeWinTrust(0);
        using (var scope = new Scope()) using (var stream = File.OpenRead(scope.File))
            _ = new WindowsAuthenticodeNativeVerifier(failing, new ThrowingReader()).Verify(scope.File, stream.SafeFileHandle);
        Assert.AreEqual(1, failing.Disposes);
    }

    private static NativeAuthenticodeEvidence Valid() => new(NativeAuthenticodeTrustCategory.Success,
        PrimarySignatureCountPolicyCategory.ExactlyOne, NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.ValidRfc3161,
        new SignerCertificateEvidence(new string('A', 64), [AzureArtifactSigningEkuPolicy.CodeSigningEku,
            AzureArtifactSigningEkuPolicy.AzureArtifactSigningPublicTrustEku, AzureArtifactSigningEkuPolicy.VantrelCertificateProfileEku]));
    private sealed class FixedNative(NativeAuthenticodeEvidence evidence) : IAuthenticodeNativeVerifier
    {
        internal bool ValidHandle; internal int Calls;
        public NativeAuthenticodeEvidence Verify(string path, SafeFileHandle handle) { Calls++; ValidHandle = !handle.IsClosed && !handle.IsInvalid; return evidence; }
    }
    private sealed class ThrowingNative : IAuthenticodeNativeVerifier
    { public NativeAuthenticodeEvidence Verify(string path, SafeFileHandle handle) => throw new AuthenticodeProviderUnavailableException(); }
    // Synthetic acceptance is a seam test, not proof that the eleven-byte fixture is an MSI database.
    private sealed class FixedDatabase : IMsiDatabaseValidator
    {
        public bool IsReadOnlyDatabase(string path) => File.ReadAllBytes(path).AsSpan().StartsWith(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 });
    }
    private sealed class FakeDatabaseNative(uint status, bool throws = false, uint closeStatus = 0) : IMsiDatabaseNativeApi
    {
        internal int Closes;
        public uint OpenReadOnly(string path, out uint database)
        {
            database = 42;
            if (throws) throw new IOException("raw database details");
            return status;
        }
        public uint Close(uint database) { Assert.AreEqual(42u, database); Closes++; return closeStatus; }
    }
    private sealed class FixedReader(NativeAuthenticodeEvidence evidence) : IWinTrustProviderEvidenceReader
    { internal int Calls; public NativeAuthenticodeEvidence Read(IWinTrustNativeCall call) { Calls++; return evidence; } }
    private sealed class ThrowingReader : IWinTrustProviderEvidenceReader
    { public NativeAuthenticodeEvidence Read(IWinTrustNativeCall call) => throw new AuthenticodeProviderUnavailableException(); }
    private sealed class FakeWinTrust(int result) : IWinTrustNativeApi
    {
        internal int Disposes;
        public IWinTrustNativeCall BeginFileVerification(string path, SafeFileHandle handle) => new Call(result, () => Disposes++);
        private sealed class Call(int result, Action dispose) : IWinTrustNativeCall
        {
            public int NativeResult => result;
            public IntPtr StateHandle => new(1);
            public string FilePath => "unobserved";
            public void Dispose() => dispose();
        }
    }
    private sealed class Scope : IDisposable
    {
        internal string Root = Path.Combine(Path.GetTempPath(), "vantrel-msi-inspect-" + Guid.NewGuid().ToString("N"));
        internal string File => Path.Combine(Root, "input.msi");
        internal Scope() { Directory.CreateDirectory(Root); System.IO.File.WriteAllBytes(File, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 1, 2, 3]); }
        public void Dispose() => Directory.Delete(Root, true);
    }
}
