using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Vantrel.Security.Core;

public enum ReleaseMetadataParseFailure { None, Unavailable, Malformed, UnsupportedSchema, WrongProduct, WrongArchitecture, WrongChannel, UnknownKeyId }

/// <summary>Strict, independently signed release provenance bound to a trusted-manifest hash.</summary>
public sealed record ReleaseMetadata(ulong ReleaseSequence, string ManifestSha256, string DisplayVersion,
    DateTimeOffset PublishedAtUtc, byte[] CanonicalPayload, byte[] Signature);

public static class ReleaseMetadataCodec
{
    public const int MaximumBytes = 4096;
    public const string Schema = "vantrel-release-metadata-v1";
    public const string Product = "vantrel-security";
    public const string Architecture = "win-x64";
    public const string Channel = "stable";
    public const string KeyId = "release-metadata-p256-1";
    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static byte[] CreateCanonicalPayload(ulong releaseSequence, string manifestSha256, string displayVersion,
        DateTimeOffset publishedAtUtc)
    {
        if (releaseSequence == 0) throw new ArgumentOutOfRangeException(nameof(releaseSequence));
        if (!IsUpperHash(manifestSha256)) throw new ArgumentException("A 64-character uppercase SHA-256 is required.", nameof(manifestSha256));
        if (!IsDisplayVersion(displayVersion)) throw new ArgumentException("Display version must be bounded printable ASCII.", nameof(displayVersion));
        if (publishedAtUtc.Offset != TimeSpan.Zero || publishedAtUtc.Ticks % TimeSpan.TicksPerSecond != 0)
            throw new ArgumentException("Publication time must be UTC at whole-second precision.", nameof(publishedAtUtc));
        var text = $"schema={Schema}\nproduct={Product}\narchitecture={Architecture}\nchannel={Channel}\nrelease-sequence={releaseSequence.ToString(CultureInfo.InvariantCulture)}\nmanifest-sha256={manifestSha256}\ndisplay-version={displayVersion}\npublished-at-utc={publishedAtUtc.ToString(TimestampFormat, CultureInfo.InvariantCulture)}\nkey-id={KeyId}\n";
        return Utf8.GetBytes(text);
    }

    public static byte[] CreateFile(ulong releaseSequence, string manifestSha256, string displayVersion,
        DateTimeOffset publishedAtUtc, ECDsa signingKey)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        var canonical = CreateCanonicalPayload(releaseSequence, manifestSha256, displayVersion, publishedAtUtc);
        var signature = signingKey.SignData(canonical, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return Utf8.GetBytes(Utf8.GetString(canonical) + "signature=" + Convert.ToBase64String(signature) + "\n");
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out ReleaseMetadata? metadata, out ReleaseMetadataParseFailure failure)
    {
        metadata = null;
        if (bytes.Length == 0) { failure = ReleaseMetadataParseFailure.Unavailable; return false; }
        if (bytes.Length > MaximumBytes || HasBom(bytes) || bytes.IndexOf((byte)'\r') >= 0)
        { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        string text;
        try { text = Utf8.GetString(bytes); } catch (DecoderFallbackException) { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        if (!text.EndsWith('\n') || text.Contains("\n\n", StringComparison.Ordinal)) { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        var lines = text.Split('\n');
        if (lines.Length != 11 || lines[^1].Length != 0) { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        if (lines[0] != "schema=" + Schema)
        { failure = lines[0].StartsWith("schema=", StringComparison.Ordinal) ? ReleaseMetadataParseFailure.UnsupportedSchema : ReleaseMetadataParseFailure.Malformed; return false; }
        if (lines[1] != "product=" + Product) { failure = ReleaseMetadataParseFailure.WrongProduct; return false; }
        if (lines[2] != "architecture=" + Architecture) { failure = ReleaseMetadataParseFailure.WrongArchitecture; return false; }
        if (lines[3] != "channel=" + Channel) { failure = ReleaseMetadataParseFailure.WrongChannel; return false; }
        if (lines[8] != "key-id=" + KeyId) { failure = ReleaseMetadataParseFailure.UnknownKeyId; return false; }
        if (!TryField(lines[4], "release-sequence", out var sequenceText) || !IsCanonicalSequence(sequenceText, out var sequence))
        { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        if (!TryField(lines[5], "manifest-sha256", out var manifestSha256) || !IsUpperHash(manifestSha256))
        { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        if (!TryField(lines[6], "display-version", out var displayVersion) || !IsDisplayVersion(displayVersion))
        { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        if (!TryField(lines[7], "published-at-utc", out var publishedText) ||
            !DateTimeOffset.TryParseExact(publishedText, TimestampFormat, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var publishedAtUtc) ||
            publishedAtUtc.ToString(TimestampFormat, CultureInfo.InvariantCulture) != publishedText)
        { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        if (!TryField(lines[9], "signature", out var signatureText)) { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        byte[] signature;
        try { signature = Convert.FromBase64String(signatureText); } catch (FormatException) { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        if (signature.Length == 0 || !string.Equals(signatureText, Convert.ToBase64String(signature), StringComparison.Ordinal)) { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        var canonical = CreateCanonicalPayload(sequence, manifestSha256, displayVersion, publishedAtUtc);
        if (bytes.Length != canonical.Length + Utf8.GetByteCount(lines[9]) + 1 || !bytes[..canonical.Length].SequenceEqual(canonical))
        { failure = ReleaseMetadataParseFailure.Malformed; return false; }
        metadata = new(sequence, manifestSha256, displayVersion, publishedAtUtc, canonical, signature);
        failure = ReleaseMetadataParseFailure.None;
        return true;
    }

    public static bool Verify(ReleaseMetadata metadata, ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var read);
            return read == subjectPublicKeyInfo.Length && key.KeySize == 256 &&
                key.VerifyData(metadata.CanonicalPayload, metadata.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException) { return false; }
    }

    private static bool TryField(string line, string field, out string value)
    {
        var prefix = field + "=";
        if (!line.StartsWith(prefix, StringComparison.Ordinal)) { value = string.Empty; return false; }
        value = line[prefix.Length..]; return true;
    }
    private static bool IsCanonicalSequence(string value, out ulong sequence)
    {
        sequence = 0;
        return value.Length > 0 && value[0] is >= '1' and <= '9' && value.All(c => c is >= '0' and <= '9') &&
            ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out sequence);
    }
    private static bool IsUpperHash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool IsDisplayVersion(string? value) => value is { Length: > 0 and <= 64 } && value.All(c => c is >= (char)0x21 and <= (char)0x7e && c is not '=');
    private static bool HasBom(ReadOnlySpan<byte> bytes) => bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
}
