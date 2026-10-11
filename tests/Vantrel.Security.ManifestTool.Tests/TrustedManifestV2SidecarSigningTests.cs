using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.ManifestTool;

namespace Vantrel.Security.ManifestTool.Tests;

[TestClass]
public sealed class TrustedManifestV2SidecarSigningTests
{
    private const string Version = "0.1.0-beta.1";
    private const ulong Sequence = 42;
    private static readonly DateTimeOffset Published = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

    private static readonly TrustedManifestV2File[] Files =
    [
        new("A.dll", new string('A', 64)),
        new("B.dll", new string('B', 64))
    ];

    [TestMethod]
    public void Produces_canonical_v2_manifest_and_bound_existing_metadata_format()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();

        var manifestBytes = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);
        var metadataBytes = TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
            manifestBytes, Version, Sequence, Published, metadataKey, manifestRoot, metadataRoot);

        Assert.IsTrue(TrustedManifestV2Codec.TryParse(manifestBytes, out var manifest, out _));
        Assert.IsNotNull(manifest);
        Assert.AreEqual(Version, manifest.Release);
        Assert.AreEqual(Sequence, manifest.ReleaseSequence);
        Assert.AreEqual(TrustedManifestV2Codec.Architecture, manifest.Architecture);
        Assert.AreEqual(TrustedManifestV2Codec.Deployment, manifest.Deployment);
        CollectionAssert.AreEqual(Files, manifest.Files.ToArray());
        Assert.IsTrue(TrustedManifestV2Codec.Verify(manifest, manifestRoot));
        Assert.IsTrue(ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out _));
        Assert.IsNotNull(metadata);
        Assert.AreEqual(ReleaseMetadataCodec.Schema, "vantrel-release-metadata-v1");
        Assert.AreEqual(Convert.ToHexString(SHA256.HashData(manifestBytes)), metadata.ManifestSha256);
        Assert.AreEqual(Version, metadata.DisplayVersion);
        Assert.AreEqual(Sequence, metadata.ReleaseSequence);
        Assert.AreEqual(Published, metadata.PublishedAtUtc);
        Assert.IsTrue(ReleaseMetadataCodec.Verify(metadata, metadataRoot));
        Assert.IsTrue(TrustedManifestV2Codec.VerifyBoundMetadata(manifestBytes, metadataBytes,
            manifestRoot, metadataRoot));
        Assert.IsFalse(manifestBytes.Contains((byte)'\r'));
        Assert.AreEqual((byte)'\n', manifestBytes[^1]);
        Assert.AreEqual((byte)'\n', metadataBytes[^1]);
    }

    [TestMethod]
    public void Wrong_manifest_key_and_wrong_metadata_key_are_rejected()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        using var wrongKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();
        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateSignedManifest(
                Version, Sequence, Files, wrongKey, manifestRoot));

        var manifestBytes = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);
        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                manifestBytes, Version, Sequence, Published, wrongKey, manifestRoot, metadataRoot));
        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                manifestBytes, Version, Sequence, Published, manifestKey, manifestRoot, manifestRoot));
    }

    [TestMethod]
    public void Purpose_swaps_and_a_valid_key_under_the_wrong_public_root_are_rejected()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        using var otherKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();
        var manifest = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);

        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateSignedManifest(
                Version, Sequence, Files, metadataKey, manifestRoot));
        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                manifest, Version, Sequence, Published, manifestKey, manifestRoot, metadataRoot));
        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateSignedManifest(
                Version, Sequence, Files, manifestKey, otherKey.ExportSubjectPublicKeyInfo()));
        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                manifest, Version, Sequence, Published, metadataKey, manifestRoot,
                otherKey.ExportSubjectPublicKeyInfo()));
    }

    [TestMethod]
    public void Metadata_cannot_be_signed_for_mutated_or_unsigned_manifest()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();
        var manifestBytes = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);
        var mutated = manifestBytes.ToArray();
        var marker = Encoding.ASCII.GetBytes("signature=");
        var start = manifestBytes.AsSpan().IndexOf(marker) + marker.Length;
        Assert.IsTrue(start >= marker.Length);
        mutated[start] = mutated[start] == (byte)'A' ? (byte)'B' : (byte)'A';
        Assert.AreNotEqual(Convert.ToHexString(SHA256.HashData(manifestBytes)),
            Convert.ToHexString(SHA256.HashData(mutated)));
        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                mutated, Version, Sequence, Published, metadataKey, manifestRoot, metadataRoot));

        var unsigned = TrustedManifestV2Codec.CreateCanonicalPayload(Version, Sequence, Files);
        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                unsigned, Version, Sequence, Published, metadataKey, manifestRoot, metadataRoot));
    }

    [TestMethod]
    public void Metadata_is_bound_to_the_full_final_signed_manifest_bytes()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();
        var manifestBytes = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);
        var metadataBytes = TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
            manifestBytes, Version, Sequence, Published, metadataKey, manifestRoot, metadataRoot);
        var altered = manifestBytes.ToArray();
        var start = manifestBytes.AsSpan().IndexOf("signature="u8) + "signature="u8.Length;
        altered[start] = altered[start] == (byte)'A' ? (byte)'B' : (byte)'A';

        Assert.IsFalse(TrustedManifestV2Codec.VerifyBoundMetadata(altered, metadataBytes,
            manifestRoot, metadataRoot));
        Assert.AreNotEqual(Convert.ToHexString(SHA256.HashData(manifestBytes)),
            Convert.ToHexString(SHA256.HashData(altered)));
    }

    [TestMethod]
    public void Metadata_for_one_valid_signed_manifest_rejects_another_valid_signed_manifest()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();
        var first = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);
        var changedFiles = Files.ToArray();
        changedFiles[0] = changedFiles[0] with { Sha256 = new string('C', 64) };
        var second = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, changedFiles, manifestKey, manifestRoot);
        var metadata = TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
            first, Version, Sequence, Published, metadataKey, manifestRoot, metadataRoot);

        Assert.IsTrue(TrustedManifestV2Codec.TryParse(second, out var secondParsed, out _));
        Assert.IsNotNull(secondParsed);
        Assert.IsTrue(TrustedManifestV2Codec.Verify(secondParsed, manifestRoot));
        Assert.IsFalse(TrustedManifestV2Codec.VerifyBoundMetadata(second, metadata,
            manifestRoot, metadataRoot));
    }

    [TestMethod]
    public void Changed_metadata_bytes_do_not_verify()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();
        var manifest = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);
        var metadata = TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
            manifest, Version, Sequence, Published, metadataKey, manifestRoot, metadataRoot);
        var changed = metadata.ToArray();
        var start = changed.AsSpan().IndexOf("signature="u8) + "signature="u8.Length;
        changed[start] = changed[start] == (byte)'A' ? (byte)'B' : (byte)'A';

        Assert.IsFalse(TrustedManifestV2Codec.VerifyBoundMetadata(manifest, changed,
            manifestRoot, metadataRoot));
    }

    [TestMethod]
    public void V1_manifest_is_rejected_and_v2_is_not_accepted_as_v1()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();
        var v1Hashes = Enum.GetValues<TrustedManifestComponent>()
            .ToDictionary(component => component, _ => new string('A', 64));
        var v1 = TrustedManifestCodec.CreateFile(Version, v1Hashes, manifestKey);
        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                v1, Version, Sequence, Published, metadataKey, manifestRoot, metadataRoot));

        var v2 = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);
        Assert.IsFalse(TrustedManifestCodec.TryParse(v2, out _, out var failure));
        Assert.AreEqual(TrustedManifestParseFailure.Malformed, failure);
    }

    [TestMethod]
    public void Wrong_release_identity_or_sequence_fails_before_metadata_signing()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();
        var manifestBytes = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);

        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                manifestBytes, "0.1.0-beta.2", Sequence, Published, metadataKey,
                manifestRoot, metadataRoot));
        Assert.ThrowsException<InvalidDataException>(() =>
            TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                manifestBytes, Version, Sequence + 1, Published, metadataKey,
                manifestRoot, metadataRoot));
    }

    [TestMethod]
    public void Wrong_deployment_or_architecture_cannot_be_bound_as_v2_metadata()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();
        var signed = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);
        var text = Encoding.ASCII.GetString(signed);

        foreach (var changed in new[]
        {
            text.Replace("deployment=framework-dependent", "deployment=self-contained",
                StringComparison.Ordinal),
            text.Replace("architecture=win-x64", "architecture=win-arm64",
                StringComparison.Ordinal)
        })
        {
            Assert.AreNotEqual(text, changed);
            Assert.ThrowsException<InvalidDataException>(() =>
                TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                    Encoding.ASCII.GetBytes(changed), Version, Sequence, Published,
                    metadataKey, manifestRoot, metadataRoot));
        }
    }

    [TestMethod]
    public void Malformed_signature_duplicate_field_and_trailing_bytes_fail_closed()
    {
        using var manifestKey = NewKey();
        using var metadataKey = NewKey();
        var manifestRoot = manifestKey.ExportSubjectPublicKeyInfo();
        var metadataRoot = metadataKey.ExportSubjectPublicKeyInfo();
        var signed = TrustedManifestV2SidecarSigning.CreateSignedManifest(
            Version, Sequence, Files, manifestKey, manifestRoot);
        var text = Encoding.ASCII.GetString(signed);
        foreach (var malformed in new[]
        {
            Encoding.ASCII.GetBytes(text.Replace("signature=", "signature=not-base64!", StringComparison.Ordinal)),
            Encoding.ASCII.GetBytes(text + "signature=AAAA\n"),
            Encoding.ASCII.GetBytes(text + "trailing")
        })
            Assert.ThrowsException<InvalidDataException>(() =>
                TrustedManifestV2SidecarSigning.CreateBoundReleaseMetadata(
                    malformed, Version, Sequence, Published, metadataKey,
                    manifestRoot, metadataRoot));
    }

    private static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);
}
