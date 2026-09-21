using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class ReleaseMetadataProtocolTests
{
    private const string ManifestHash = "A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0";
    private static readonly DateTimeOffset PublishedAt = new(2026, 9, 20, 12, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void Canonical_metadata_round_trips_and_uses_fixed_identity()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bytes = ReleaseMetadataCodec.CreateFile(1, ManifestHash, "0.1.0", PublishedAt, key);
        Assert.IsTrue(ReleaseMetadataCodec.TryParse(bytes, out var metadata, out var failure));
        Assert.AreEqual(ReleaseMetadataParseFailure.None, failure);
        Assert.AreEqual((ulong)1, metadata!.ReleaseSequence);
        Assert.AreEqual(ManifestHash, metadata.ManifestSha256);
        Assert.IsTrue(ReleaseMetadataCodec.Verify(metadata, key.ExportSubjectPublicKeyInfo()));
        StringAssert.StartsWith(Encoding.UTF8.GetString(bytes), "schema=vantrel-release-metadata-v1\nproduct=vantrel-security\narchitecture=win-x64\nchannel=stable\n");
    }

    [TestMethod]
    public void Parser_rejects_noncanonical_identity_serialization_and_sequence()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var valid = Encoding.UTF8.GetString(ReleaseMetadataCodec.CreateFile(1, ManifestHash, "0.1.0", PublishedAt, key));
        var cases = new[]
        {
            "\uFEFF" + valid,
            valid.Replace("\n", "\r\n", StringComparison.Ordinal),
            valid.Replace("product=vantrel-security", "product=other", StringComparison.Ordinal),
            valid.Replace("release-sequence=1", "release-sequence=01", StringComparison.Ordinal),
            valid.Replace("release-sequence=1", "release-sequence=0", StringComparison.Ordinal),
            valid.Replace(ManifestHash, ManifestHash.ToLowerInvariant(), StringComparison.Ordinal),
            valid.Replace("published-at-utc=2026-09-20T12:00:00Z", "published-at-utc=2026-09-20T12:00:00+00:00", StringComparison.Ordinal),
            valid.Replace("key-id=release-metadata-p256-1", "key-id=other", StringComparison.Ordinal),
            valid + "extra=x\n"
        };
        foreach (var value in cases) Assert.IsFalse(ReleaseMetadataCodec.TryParse(Encoding.UTF8.GetBytes(value), out _, out _));
    }

    [TestMethod]
    public void Parser_rejects_duplicate_unknown_missing_bad_signature_and_overflow()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var valid = Encoding.UTF8.GetString(ReleaseMetadataCodec.CreateFile(ulong.MaxValue, ManifestHash, "0.1.0", PublishedAt, key));
        Assert.IsTrue(ReleaseMetadataCodec.TryParse(Encoding.UTF8.GetBytes(valid), out _, out _));
        var cases = new[]
        {
            valid.Replace("release-sequence=18446744073709551615", "release-sequence=18446744073709551616", StringComparison.Ordinal),
            valid.Replace("display-version=0.1.0\n", "display-version=0.1.0\ndisplay-version=0.1.0\n", StringComparison.Ordinal),
            valid.Replace("channel=stable\n", string.Empty, StringComparison.Ordinal),
            valid.Replace("signature=", "signature=!", StringComparison.Ordinal)
        };
        foreach (var value in cases) Assert.IsFalse(ReleaseMetadataCodec.TryParse(Encoding.UTF8.GetBytes(value), out _, out _));
    }

    [TestMethod]
    public void Explicit_der_signature_rejects_wrong_key_and_payload()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrong = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bytes = ReleaseMetadataCodec.CreateFile(1, ManifestHash, "0.1.0", PublishedAt, key);
        Assert.IsTrue(ReleaseMetadataCodec.TryParse(bytes, out var metadata, out _));
        Assert.IsFalse(ReleaseMetadataCodec.Verify(metadata!, wrong.ExportSubjectPublicKeyInfo()));
        Assert.IsFalse(key.VerifyData(metadata!.CanonicalPayload, metadata.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
}