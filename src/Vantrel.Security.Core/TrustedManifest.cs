using System.Security.Cryptography;
using System.Text;

namespace Vantrel.Security.Core;

public enum TrustedManifestParseFailure { None, Unavailable, Malformed, UnsupportedSchema }

public sealed record TrustedManifest(string Release, IReadOnlyDictionary<TrustedManifestComponent, string> Hashes,
    byte[] CanonicalPayload, byte[] Signature);

/// <summary>Strict parser and verifier for the fixed signed Vantrel installation manifest.</summary>
public static class TrustedManifestCodec
{
    public const int MaximumBytes = 4096;
    public const string Schema = "vantrel-trusted-manifest-v1";
    public const string PolicyRevision = "trusted-manifest-integrity-v1";
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly (string Field, TrustedManifestComponent Component)[] Components =
    [
        ("ServiceExe", TrustedManifestComponent.ServiceExe),
        ("ServiceAssembly", TrustedManifestComponent.ServiceAssembly),
        ("InfrastructureAssembly", TrustedManifestComponent.InfrastructureAssembly),
        ("CoreAssembly", TrustedManifestComponent.CoreAssembly),
        ("Deps", TrustedManifestComponent.Deps),
        ("RuntimeConfig", TrustedManifestComponent.RuntimeConfig),
        ("EventLogResource", TrustedManifestComponent.EventLogResource)
    ];

    public static byte[] CreateCanonicalPayload(string release, IReadOnlyDictionary<TrustedManifestComponent, string> hashes)
    {
        if (string.IsNullOrEmpty(release) || release.Any(char.IsWhiteSpace) || release.Any(c => c > 0x7f))
            throw new ArgumentException("Release must be non-empty ASCII without whitespace.", nameof(release));
        var builder = new StringBuilder();
        builder.Append("schema=").Append(Schema).Append('\n');
        builder.Append("release=").Append(release).Append('\n');
        foreach (var (field, component) in Components)
        {
            if (!hashes.TryGetValue(component, out var hash) || !IsUpperHash(hash))
                throw new ArgumentException($"A 64-character uppercase SHA-256 is required for {field}.", nameof(hashes));
            builder.Append(field).Append('=').Append(hash).Append('\n');
        }
        return Utf8.GetBytes(builder.ToString());
    }

    public static byte[] CreateFile(string release, IReadOnlyDictionary<TrustedManifestComponent, string> hashes,
        ECDsa signingKey)
    {
        var canonical = CreateCanonicalPayload(release, hashes);
        var signature = signingKey.SignData(canonical, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return Utf8.GetBytes(Utf8.GetString(canonical) + "signature=" + Convert.ToBase64String(signature) + "\n");
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out TrustedManifest? manifest, out TrustedManifestParseFailure failure)
    {
        manifest = null;
        if (bytes.Length == 0) { failure = TrustedManifestParseFailure.Unavailable; return false; }
        if (bytes.Length > MaximumBytes || HasBom(bytes) || bytes.IndexOf((byte)'\r') >= 0 || HasNonAscii(bytes))
        { failure = TrustedManifestParseFailure.Malformed; return false; }
        string text;
        try { text = Utf8.GetString(bytes); } catch (DecoderFallbackException) { failure = TrustedManifestParseFailure.Malformed; return false; }
        if (!text.EndsWith('\n') || text.Contains("\n\n", StringComparison.Ordinal)) { failure = TrustedManifestParseFailure.Malformed; return false; }
        var lines = text.Split('\n');
        if (lines.Length != 11 || lines[^1].Length != 0) { failure = TrustedManifestParseFailure.Malformed; return false; }
        if (!lines[0].StartsWith("schema=", StringComparison.Ordinal)) { failure = TrustedManifestParseFailure.Malformed; return false; }
        if (lines[0] != "schema=" + Schema) { failure = lines[0].StartsWith("schema=", StringComparison.Ordinal) ? TrustedManifestParseFailure.UnsupportedSchema : TrustedManifestParseFailure.Malformed; return false; }
        if (!lines[1].StartsWith("release=", StringComparison.Ordinal) || lines[1].Length == "release=".Length || lines[1]["release=".Length..].Any(char.IsWhiteSpace)) { failure = TrustedManifestParseFailure.Malformed; return false; }
        var hashes = new Dictionary<TrustedManifestComponent, string>();
        for (var index = 0; index < Components.Length; index++)
        {
            var (field, component) = Components[index];
            var line = lines[index + 2];
            if (!line.StartsWith(field + "=", StringComparison.Ordinal)) { failure = TrustedManifestParseFailure.Malformed; return false; }
            var value = line[(field.Length + 1)..];
            if (!IsUpperHash(value)) { failure = TrustedManifestParseFailure.Malformed; return false; }
            hashes.Add(component, value);
        }
        if (!lines[9].StartsWith("signature=", StringComparison.Ordinal)) { failure = TrustedManifestParseFailure.Malformed; return false; }
        var signatureText = lines[9]["signature=".Length..];
        byte[] signature;
        try { signature = Convert.FromBase64String(signatureText); }
        catch (FormatException) { failure = TrustedManifestParseFailure.Malformed; return false; }
        if (signature.Length == 0 || !string.Equals(signatureText, Convert.ToBase64String(signature), StringComparison.Ordinal)) { failure = TrustedManifestParseFailure.Malformed; return false; }
        var canonical = CreateCanonicalPayload(lines[1]["release=".Length..], hashes);
        if (bytes.Length != canonical.Length + Utf8.GetByteCount(lines[9]) + 1 || !bytes[..canonical.Length].SequenceEqual(canonical)) { failure = TrustedManifestParseFailure.Malformed; return false; }
        manifest = new(lines[1]["release=".Length..], hashes, canonical, signature); failure = TrustedManifestParseFailure.None; return true;
    }

    public static bool Verify(TrustedManifest manifest, ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var read);
            return read == subjectPublicKeyInfo.Length && key.KeySize == 256 &&
                key.VerifyData(manifest.CanonicalPayload, manifest.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException) { return false; }
    }

    private static bool IsUpperHash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool HasBom(ReadOnlySpan<byte> bytes) => bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
    private static bool HasNonAscii(ReadOnlySpan<byte> bytes) { foreach (var value in bytes) if (value > 0x7f) return true; return false; }
}
