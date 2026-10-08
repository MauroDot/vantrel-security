using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class OfflineReleasePublicKeysTests
{
    private const string ManifestFingerprint = "21E21285DD1BE7655F34DB1E75F826B89DD615D69C606BA090B9F0AF560DDBBD";
    private const string MetadataFingerprint = "1BA6C704BEA16085A39BCECE9600A845223943A0846F961273FCDAAC60FD2782";

    [TestMethod]
    public void Fresh_start_public_roots_are_distinct_approved_p256_keys_and_cannot_be_mutated_by_a_caller()
    {
        var manifest = OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo;
        var metadata = OfflineReleasePublicKeys.ReleaseMetadataSubjectPublicKeyInfo;
        Assert.AreEqual(ManifestFingerprint, Convert.ToHexString(SHA256.HashData(manifest)));
        Assert.AreEqual(MetadataFingerprint, Convert.ToHexString(SHA256.HashData(metadata)));
        CollectionAssert.AreNotEqual(manifest, metadata);

        using var manifestKey = ECDsa.Create();
        using var metadataKey = ECDsa.Create();
        manifestKey.ImportSubjectPublicKeyInfo(manifest, out var manifestRead);
        metadataKey.ImportSubjectPublicKeyInfo(metadata, out var metadataRead);
        Assert.AreEqual(manifest.Length, manifestRead);
        Assert.AreEqual(metadata.Length, metadataRead);
        Assert.AreEqual(256, manifestKey.KeySize);
        Assert.AreEqual(256, metadataKey.KeySize);

        manifest[0] ^= 1;
        metadata[0] ^= 1;
        Assert.AreEqual(ManifestFingerprint, Convert.ToHexString(SHA256.HashData(OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo)));
        Assert.AreEqual(MetadataFingerprint, Convert.ToHexString(SHA256.HashData(OfflineReleasePublicKeys.ReleaseMetadataSubjectPublicKeyInfo)));
    }

    [TestMethod]
    public void Synthetic_signatures_wrong_keys_and_tampered_payloads_never_pass_the_production_roots()
    {
        using var syntheticManifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var syntheticMetadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var hashes = Enum.GetValues<TrustedManifestComponent>().ToDictionary(component => component, _ => new string('A', 64));
        var manifestBytes = TrustedManifestCodec.CreateFile("0.1.0-beta.1", hashes, syntheticManifestKey);
        Assert.IsTrue(TrustedManifestCodec.TryParse(manifestBytes, out var manifest, out _));
        Assert.IsTrue(TrustedManifestCodec.Verify(manifest!, syntheticManifestKey.ExportSubjectPublicKeyInfo()));
        Assert.IsFalse(TrustedManifestCodec.Verify(manifest!, OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo));
        var malformedManifest = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(manifestBytes)[..^2] + "!\n");
        Assert.IsFalse(TrustedManifestCodec.TryParse(malformedManifest, out _, out _));
        var changedManifest = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(manifestBytes)
            .Replace("release=0.1.0-beta.1", "release=0.1.0-beta.2", StringComparison.Ordinal));
        Assert.IsTrue(TrustedManifestCodec.TryParse(changedManifest, out var alteredManifest, out _));
        Assert.IsFalse(TrustedManifestCodec.Verify(alteredManifest!, syntheticManifestKey.ExportSubjectPublicKeyInfo()));

        var manifestHash = Convert.ToHexString(SHA256.HashData(manifestBytes));
        var metadataBytes = ReleaseMetadataCodec.CreateFile(1, manifestHash, "0.1.0-beta.1",
            new DateTimeOffset(2026, 10, 8, 15, 41, 6, TimeSpan.Zero), syntheticMetadataKey);
        Assert.IsTrue(ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out _));
        Assert.IsTrue(ReleaseMetadataCodec.Verify(metadata!, syntheticMetadataKey.ExportSubjectPublicKeyInfo()));
        Assert.IsFalse(ReleaseMetadataCodec.Verify(metadata!, OfflineReleasePublicKeys.ReleaseMetadataSubjectPublicKeyInfo));
        var malformedMetadata = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(metadataBytes)[..^2] + "!\n");
        Assert.IsFalse(ReleaseMetadataCodec.TryParse(malformedMetadata, out _, out _));
        var changedMetadata = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(metadataBytes)
            .Replace("display-version=0.1.0-beta.1", "display-version=0.1.0-beta.2", StringComparison.Ordinal));
        Assert.IsTrue(ReleaseMetadataCodec.TryParse(changedMetadata, out var alteredMetadata, out _));
        Assert.IsFalse(ReleaseMetadataCodec.Verify(alteredMetadata!, syntheticMetadataKey.ExportSubjectPublicKeyInfo()));
    }
}
