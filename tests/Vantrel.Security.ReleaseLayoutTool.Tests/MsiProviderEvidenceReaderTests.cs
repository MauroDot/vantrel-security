using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
public sealed class MsiProviderEvidenceReaderTests
{
    private const string Sha256 = "2.16.840.1.101.3.4.2.1";
    private static readonly byte[] Sha256FileDigest = Convert.FromHexString(
        "30190201013014300B060960864801650304020104050102030405");

    [TestMethod]
    public void Reader_extracts_one_primary_sha256_and_verified_rfc3161_without_counting_timestamp_as_product_signature()
    {
        var fixture = new Fixture();
        var result = fixture.Read();
        Assert.AreEqual(PrimarySignatureCountPolicyCategory.ExactlyOne, result.PrimarySignatureCount);
        Assert.AreEqual(NativeDigestAlgorithmCategory.Sha256, result.DigestAlgorithm);
        Assert.AreEqual(TimestampPolicyCategory.ValidRfc3161, result.Timestamp);
        Assert.AreEqual(1, fixture.Timestamp.Calls);
        Assert.AreEqual(1, fixture.State.Disposes);
        Assert.AreEqual(1, fixture.Message.Disposes);
    }

    [TestMethod]
    public void Truncated_structures_missing_fields_and_unbounded_counts_fail_closed_and_release_state()
    {
        foreach (var corrupt in new Action<Fixture>[]
        {
            f => f.State.Value = f.State.Value with { ProviderSize = (uint)(WindowsMsiProviderEvidenceReader.RequiredProviderDataSize - 1) },
            f => f.State.Value = f.State.Value with { SignatureStateSize = (uint)(WindowsMsiProviderEvidenceReader.RequiredSignatureStateSize - 1) },
            f => f.State.Value = f.State.Value with { Message = IntPtr.Zero },
            f => f.State.Value = f.State.Value with { Primary = IntPtr.Zero },
            f => f.State.Value = f.State.Value with { Signers = 65 },
            f => f.State.Value = f.State.Value with { SecondaryCount = 65 },
            f => f.State.Value = f.State.Value with { Signer = null }
        })
        {
            var fixture = new Fixture(); corrupt(fixture);
            Assert.ThrowsException<AuthenticodeProviderUnavailableException>(() => fixture.Read());
            Assert.AreEqual(1, fixture.State.Disposes);
            Assert.AreEqual(0, fixture.Message.Disposes);
        }
    }

    [TestMethod]
    public void Zero_multiple_secondary_and_nested_product_signatures_are_distinct_from_timestamp()
    {
        var zero = new Fixture(); zero.Message.Count = PrimarySignatureCountPolicyCategory.None;
        Assert.AreEqual(PrimarySignatureCountPolicyCategory.None, zero.Read().PrimarySignatureCount);
        foreach (var corrupt in new Action<Fixture>[]
        {
            f => f.State.Value = f.State.Value with { Signers = 2 },
            f => f.State.Value = f.State.Value with { SecondaryCount = 1 },
            f => f.State.Value = f.State.Value with { ExtraProviderSigner = true },
            f => f.State.Value = f.State.Value with { Primary = new IntPtr(3) },
            f => f.Message.Count = PrimarySignatureCountPolicyCategory.ExtraOrDuplicate,
            f => f.Message.Attributes.Add(new("1.3.6.1.4.1.311.2.4.1", [new byte[] { 1 }]))
        })
        {
            var fixture = new Fixture(); corrupt(fixture);
            var result = fixture.Read();
            Assert.AreEqual(PrimarySignatureCountPolicyCategory.ExtraOrDuplicate, result.PrimarySignatureCount);
            Assert.AreEqual(TimestampPolicyCategory.Indeterminate, result.Timestamp);
            Assert.AreEqual(1, fixture.State.Disposes);
            Assert.AreEqual(1, fixture.Message.Disposes);
        }
    }

    [TestMethod]
    public void Digest_and_timestamp_failures_cannot_become_valid_evidence()
    {
        var malformed = new Fixture(); malformed.Message.DigestContent = [0x30, 0x00];
        Assert.AreEqual(NativeDigestAlgorithmCategory.Indeterminate, malformed.Read().DigestAlgorithm);
        var unsupported = new Fixture(); unsupported.Message.DigestContent = (byte[])Sha256FileDigest.Clone();
        unsupported.Message.DigestContent[19] = 2;
        Assert.AreEqual(NativeDigestAlgorithmCategory.Unsupported, unsupported.Read().DigestAlgorithm);
        var absent = new Fixture(); absent.Message.Attributes.Clear();
        Assert.AreEqual(TimestampPolicyCategory.Missing, absent.Read().Timestamp);
        var invalid = new Fixture(); invalid.Timestamp.Valid = false;
        Assert.AreEqual(TimestampPolicyCategory.Invalid, invalid.Read().Timestamp);
        var unrelated = new Fixture(); unrelated.Message.Attributes.Clear();
        unrelated.Message.Attributes.Add(new("1.2.3.4", [new byte[] { 1 }]));
        Assert.AreEqual(TimestampPolicyCategory.Missing, unrelated.Read().Timestamp);
    }

    [TestMethod]
    public void Failure_after_message_borrow_releases_wrapper_and_state_once()
    {
        var fixture = new Fixture(); fixture.Message.ThrowOnContent = true;
        Assert.ThrowsException<AuthenticodeProviderUnavailableException>(() => fixture.Read());
        Assert.AreEqual(1, fixture.State.Disposes);
        Assert.AreEqual(1, fixture.Message.Disposes);
    }

    [TestMethod]
    public void Actual_borrowed_native_message_wrapper_never_invokes_its_close_operation()
    {
        var closes = 0;
        var borrowed = NativeSignedMessage.Borrow(new IntPtr(7), _ => closes++);
        borrowed.Dispose(); borrowed.Dispose();
        Assert.AreEqual(0, closes);
    }

    private sealed class Fixture
    {
        internal readonly State State = new();
        internal readonly Message Message = new();
        internal readonly TimestampVerifier Timestamp = new();
        internal NativeAuthenticodeEvidence Read() => new WindowsMsiProviderEvidenceReader(Timestamp, new StateAccess(State), new MessageFactory(Message)).Read(new Call());
    }
    private sealed class State : IMsiProviderState
    {
        internal int Disposes;
        public MsiProviderStateEvidence Value { get; set; } = new((uint)WindowsMsiProviderEvidenceReader.RequiredProviderDataSize,
            (uint)WindowsMsiProviderEvidenceReader.RequiredSignatureStateSize, new IntPtr(1), new IntPtr(1), 1, 0, false,
            new SignerCertificateEvidence(new string('A', 64), [AzureArtifactSigningEkuPolicy.CodeSigningEku,
                AzureArtifactSigningEkuPolicy.AzureArtifactSigningPublicTrustEku, AzureArtifactSigningEkuPolicy.VantrelCertificateProfileEku]));
        public void Dispose() => Disposes++;
    }
    private sealed class StateAccess(State state) : IMsiProviderStateAccess
    {
        public IMsiProviderState Read(IntPtr handle) { Assert.AreEqual(new IntPtr(5), handle); return state; }
    }
    private sealed class Message : IMsiBorrowedMessage
    {
        internal int Disposes;
        internal bool ThrowOnContent;
        internal byte[] DigestContent = (byte[])Sha256FileDigest.Clone();
        internal PrimarySignatureCountPolicyCategory Count = PrimarySignatureCountPolicyCategory.ExactlyOne;
        internal List<AuthenticodeTimestampAttribute> Attributes = [new(AuthenticodeTimestampEvidence.WindowsRfc3161CounterSignOid, [new byte[] { 1, 2 }])];
        public PrimarySignatureCountPolicyCategory PrimarySignatureCount => Count;
        public byte[] Content() => ThrowOnContent ? throw new AuthenticodeProviderUnavailableException() : DigestContent;
        public byte[] EncryptedDigest() => [7, 8, 9];
        public IReadOnlyList<AuthenticodeTimestampAttribute> UnauthenticatedAttributes() => Attributes;
        public void Dispose() => Disposes++;
    }
    private sealed class MessageFactory(Message message) : IMsiBorrowedMessageFactory
    {
        public IMsiBorrowedMessage Borrow(IntPtr pointer) { Assert.AreEqual(new IntPtr(1), pointer); return message; }
    }
    private sealed class TimestampVerifier : IAuthenticodeTimestampEvidenceVerifier
    {
        internal int Calls; internal bool Valid = true;
        public bool Verify(byte[] token, byte[] signedData, out string digestAlgorithmOid)
        { Calls++; digestAlgorithmOid = Sha256; return Valid; }
    }
    private sealed class Call : IWinTrustNativeCall
    {
        public int NativeResult => 0;
        public IntPtr StateHandle => new(5);
        public string FilePath => "unused";
        public void Dispose() { }
    }
}
