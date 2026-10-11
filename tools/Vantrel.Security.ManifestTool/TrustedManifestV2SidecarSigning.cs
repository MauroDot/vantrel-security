using System.Security.Cryptography;
using Vantrel.Security.Core;

namespace Vantrel.Security.ManifestTool;

/// <summary>
/// Pure v2 sidecar producer. The caller owns the signing keys and must separately approve and
/// retain the final Service layout before publishing these returned bytes with create-new writes.
/// </summary>
public static class TrustedManifestV2SidecarSigning
{
    private const string Invalid = "V2 sidecar signing failed.";
    private const string P256Oid = "1.2.840.10045.3.1.7";

    public static byte[] CreateSignedManifest(string releaseVersion, ulong releaseSequence,
        IReadOnlyList<TrustedManifestV2File> approvedFiles, ECDsa manifestSigningKey,
        ReadOnlySpan<byte> expectedManifestSpki)
    {
        ArgumentNullException.ThrowIfNull(approvedFiles);
        ArgumentNullException.ThrowIfNull(manifestSigningKey);
        var files = approvedFiles.ToArray();
        var publicRoot = expectedManifestSpki.ToArray();
        RequireApprovedKey(manifestSigningKey, publicRoot);

        var bytes = TrustedManifestV2Codec.CreateFile(releaseVersion, releaseSequence,
            files, manifestSigningKey);
        if (!TrustedManifestV2Codec.TryParse(bytes, out var parsed, out _) || parsed is null ||
            parsed.Release != releaseVersion || parsed.ReleaseSequence != releaseSequence ||
            !parsed.Files.SequenceEqual(files) ||
            !TrustedManifestV2Codec.Verify(parsed, publicRoot))
            throw new InvalidDataException(Invalid);
        return bytes;
    }

    public static byte[] CreateBoundReleaseMetadata(ReadOnlySpan<byte> signedManifestBytes,
        string expectedReleaseVersion, ulong expectedReleaseSequence, DateTimeOffset publishedAtUtc,
        ECDsa metadataSigningKey, ReadOnlySpan<byte> expectedManifestSpki,
        ReadOnlySpan<byte> expectedMetadataSpki)
    {
        ArgumentNullException.ThrowIfNull(metadataSigningKey);
        var manifestRoot = expectedManifestSpki.ToArray();
        var metadataRoot = expectedMetadataSpki.ToArray();
        if (manifestRoot.Length == 0 || metadataRoot.Length == 0 ||
            manifestRoot.AsSpan().SequenceEqual(metadataRoot) ||
            !TrustedManifestV2Codec.TryParse(signedManifestBytes, out var manifest, out _) ||
            manifest is null || manifest.Release != expectedReleaseVersion ||
            manifest.ReleaseSequence != expectedReleaseSequence ||
            !TrustedManifestV2Codec.Verify(manifest, manifestRoot))
            throw new InvalidDataException(Invalid);
        RequireApprovedKey(metadataSigningKey, metadataRoot);

        var manifestHash = Convert.ToHexString(SHA256.HashData(signedManifestBytes));
        var bytes = ReleaseMetadataCodec.CreateFile(expectedReleaseSequence, manifestHash,
            expectedReleaseVersion, publishedAtUtc, metadataSigningKey);
        if (!ReleaseMetadataCodec.TryParse(bytes, out var metadata, out _) || metadata is null ||
            metadata.ReleaseSequence != expectedReleaseSequence ||
            metadata.DisplayVersion != expectedReleaseVersion ||
            metadata.PublishedAtUtc != publishedAtUtc ||
            metadata.ManifestSha256 != manifestHash ||
            !ReleaseMetadataCodec.Verify(metadata, metadataRoot) ||
            !TrustedManifestV2Codec.VerifyBoundMetadata(signedManifestBytes, bytes,
                manifestRoot, metadataRoot))
            throw new InvalidDataException(Invalid);
        return bytes;
    }

    private static void RequireApprovedKey(ECDsa signingKey, ReadOnlySpan<byte> expectedPublicSpki)
    {
        if (expectedPublicSpki.IsEmpty) throw new InvalidDataException(Invalid);
        try
        {
            var actualPublicSpki = signingKey.ExportSubjectPublicKeyInfo();
            if (signingKey.KeySize != 256 ||
                signingKey.ExportParameters(false).Curve.Oid.Value != P256Oid ||
                actualPublicSpki.Length != expectedPublicSpki.Length ||
                !CryptographicOperations.FixedTimeEquals(actualPublicSpki, expectedPublicSpki))
                throw new InvalidDataException(Invalid);
        }
        catch (Exception error) when (error is CryptographicException or NotSupportedException or
            ObjectDisposedException)
        { throw new InvalidDataException(Invalid); }
    }
}
