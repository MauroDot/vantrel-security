using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Vantrel.Security.Core;

/// <summary>One file in the v2 Service-root-relative, signed inventory.</summary>
public sealed record TrustedManifestV2File(string Path, string Sha256);

/// <summary>
/// Parsed v2 evidence. The inventory and signed bytes are privately owned so callers cannot
/// change the meaning of an already verified manifest.
/// </summary>
public sealed class TrustedManifestV2
{
    private readonly byte[] _canonicalPayload;
    private readonly byte[] _signature;

    internal TrustedManifestV2(string release, ulong releaseSequence,
        IReadOnlyList<TrustedManifestV2File> files, byte[] canonicalPayload, byte[] signature)
    {
        Release = release;
        ReleaseSequence = releaseSequence;
        Files = new ReadOnlyCollection<TrustedManifestV2File>(files.ToArray());
        _canonicalPayload = canonicalPayload.ToArray();
        _signature = signature.ToArray();
    }

    public string Release { get; }
    public ulong ReleaseSequence { get; }
    public string Architecture => TrustedManifestV2Codec.Architecture;
    public string Deployment => TrustedManifestV2Codec.Deployment;
    public IReadOnlyList<TrustedManifestV2File> Files { get; }

    internal ReadOnlySpan<byte> CanonicalPayload => _canonicalPayload;
    internal ReadOnlySpan<byte> Signature => _signature;
}

/// <summary>
/// Isolated v2 signed-inventory format. This codec does not enumerate files or prove .deps.json
/// closure; future filesystem consumers must establish both before accepting a release.
/// </summary>
public static class TrustedManifestV2Codec
{
    public const string Schema = "vantrel-trusted-manifest-v2";
    public const string Architecture = "win-x64";
    public const string Deployment = "framework-dependent";
    public const int MaximumBytes = 256 * 1024;
    public const int MaximumFiles = 512;
    public const int MaximumPathLength = 240;
    public const int MaximumSegmentLength = 120;
    public const int MaximumDepth = 8;

    private static readonly Encoding Ascii = Encoding.ASCII;
    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    public static byte[] CreateCanonicalPayload(string release, ulong releaseSequence,
        IReadOnlyList<TrustedManifestV2File> files)
    {
        if (!IsCanonicalReleaseVersion(release))
            throw new ArgumentException("Release version is not canonical.", nameof(release));
        if (releaseSequence == 0)
            throw new ArgumentOutOfRangeException(nameof(releaseSequence));
        ArgumentNullException.ThrowIfNull(files);
        if (!IsCanonicalInventory(files))
            throw new ArgumentException("Service inventory is not canonical.", nameof(files));

        var text = new StringBuilder()
            .Append("schema=").Append(Schema).Append('\n')
            .Append("release=").Append(release).Append('\n')
            .Append("release-sequence=").Append(releaseSequence.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("architecture=").Append(Architecture).Append('\n')
            .Append("deployment=").Append(Deployment).Append('\n')
            .Append("file-count=").Append(files.Count.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (var file in files)
            text.Append("file=").Append(file.Path).Append('|').Append(file.Sha256).Append('\n');
        var bytes = Ascii.GetBytes(text.ToString());
        // Leave room for the bounded DER signature and its canonical Base64 line.
        if (bytes.Length + 4 * ((256 + 2) / 3) + "signature=\n".Length > MaximumBytes)
            throw new ArgumentException("Service manifest exceeds its size bound.", nameof(files));
        return bytes;
    }

    public static byte[] CreateFile(string release, ulong releaseSequence,
        IReadOnlyList<TrustedManifestV2File> files, ECDsa signingKey)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        if (!IsNistP256(signingKey))
            throw new ArgumentException("A P-256 signing key is required.", nameof(signingKey));
        var canonical = CreateCanonicalPayload(release, releaseSequence, files);
        var signature = signingKey.SignData(canonical, HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        if (signature.Length is < 1 or > 256)
            throw new CryptographicException("Manifest signature is outside its size bound.");
        return Ascii.GetBytes(Ascii.GetString(canonical) + "signature=" + Convert.ToBase64String(signature) + "\n");
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out TrustedManifestV2? manifest,
        out TrustedManifestParseFailure failure)
    {
        manifest = null;
        if (bytes.IsEmpty) { failure = TrustedManifestParseFailure.Unavailable; return false; }
        if (bytes.Length > MaximumBytes || bytes[^1] != (byte)'\n')
        { failure = TrustedManifestParseFailure.Malformed; return false; }
        var newlineCount = 0;
        foreach (var value in bytes)
        {
            if (value == (byte)'\n' && ++newlineCount > MaximumFiles + 7)
            { failure = TrustedManifestParseFailure.Malformed; return false; }
            if (value != (byte)'\n' && (value < 0x20 || value > 0x7E))
            { failure = TrustedManifestParseFailure.Malformed; return false; }
        }

        var text = Ascii.GetString(bytes);
        if (text.Contains("\n\n", StringComparison.Ordinal))
        { failure = TrustedManifestParseFailure.Malformed; return false; }
        var lines = text.Split('\n');
        if (lines[^1].Length != 0 || !lines[0].StartsWith("schema=", StringComparison.Ordinal))
        { failure = TrustedManifestParseFailure.Malformed; return false; }
        if (lines[0] != "schema=" + Schema)
        { failure = TrustedManifestParseFailure.UnsupportedSchema; return false; }
        if (lines.Length < 9)
        { failure = TrustedManifestParseFailure.Malformed; return false; }
        if (!TryField(lines[1], "release", out var release) || !IsCanonicalReleaseVersion(release) ||
            !TryField(lines[2], "release-sequence", out var sequenceText) ||
            !TryCanonicalPositiveNumber(sequenceText, out ulong sequence) ||
            lines[3] != "architecture=" + Architecture || lines[4] != "deployment=" + Deployment ||
            !TryField(lines[5], "file-count", out var countText) ||
            !TryCanonicalPositiveNumber(countText, out uint count) || count > MaximumFiles ||
            lines.Length != count + 8)
        { failure = TrustedManifestParseFailure.Malformed; return false; }

        var files = new List<TrustedManifestV2File>((int)count);
        for (var i = 0; i < count; i++)
        {
            if (!TryField(lines[i + 6], "file", out var entry))
            { failure = TrustedManifestParseFailure.Malformed; return false; }
            var separator = entry.IndexOf('|');
            if (separator < 1 || separator != entry.LastIndexOf('|'))
            { failure = TrustedManifestParseFailure.Malformed; return false; }
            files.Add(new(entry[..separator], entry[(separator + 1)..]));
        }
        if (!IsCanonicalInventory(files) || !TryField(lines[(int)count + 6], "signature", out var signatureText))
        { failure = TrustedManifestParseFailure.Malformed; return false; }
        if (signatureText.Length > 4 * ((256 + 2) / 3))
        { failure = TrustedManifestParseFailure.Malformed; return false; }
        byte[] signature;
        try { signature = Convert.FromBase64String(signatureText); }
        catch (FormatException) { failure = TrustedManifestParseFailure.Malformed; return false; }
        if (signature.Length is < 1 or > 256 ||
            signatureText != Convert.ToBase64String(signature))
        { failure = TrustedManifestParseFailure.Malformed; return false; }

        byte[] canonical;
        try { canonical = CreateCanonicalPayload(release, sequence, files); }
        catch (ArgumentException) { failure = TrustedManifestParseFailure.Malformed; return false; }
        if (bytes.Length != canonical.Length + lines[(int)count + 6].Length + 1 ||
            !bytes[..canonical.Length].SequenceEqual(canonical))
        { failure = TrustedManifestParseFailure.Malformed; return false; }
        manifest = new(release, sequence, files, canonical, signature);
        failure = TrustedManifestParseFailure.None;
        return true;
    }

    public static bool Verify(TrustedManifestV2 manifest, ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var read);
            return read == subjectPublicKeyInfo.Length && IsNistP256(key) &&
                key.VerifyData(manifest.CanonicalPayload, manifest.Signature,
                    HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException) { return false; }
    }

    /// <summary>
    /// Compares a lossless caller-enumerated file/hash inventory to the signed inventory.
    /// The caller must enumerate every physical entry without collapsing case variants.
    /// </summary>
    public static bool MatchesInventory(TrustedManifestV2 manifest,
        IReadOnlyCollection<TrustedManifestV2File> actualFiles)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(actualFiles);
        if (actualFiles.Count != manifest.Files.Count) return false;
        var files = actualFiles.ToArray();
        if (files.Length != manifest.Files.Count || files.Any(file => file is null)) return false;
        Array.Sort(files, static (left, right) => StringComparer.Ordinal.Compare(left.Path, right.Path));
        if (!IsCanonicalInventory(files)) return false;
        for (var i = 0; i < files.Length; i++)
        {
            if (files[i] != manifest.Files[i]) return false;
        }
        return true;
    }

    /// <summary>
    /// Verifies both signed files and the metadata's exact full-manifest-byte hash, sequence,
    /// and release identity. Production callers must supply the two distinct approved roots.
    /// </summary>
    public static bool VerifyBoundMetadata(ReadOnlySpan<byte> manifestBytes,
        ReadOnlySpan<byte> metadataBytes, ReadOnlySpan<byte> manifestPublicKeyInfo,
        ReadOnlySpan<byte> metadataPublicKeyInfo)
    {
        if (!TryParse(manifestBytes, out var manifest, out _) || manifest is null ||
            !ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out _) || metadata is null ||
            !Verify(manifest, manifestPublicKeyInfo) ||
            !ReleaseMetadataCodec.Verify(metadata, metadataPublicKeyInfo))
            return false;
        return metadata.ManifestSha256 == Convert.ToHexString(SHA256.HashData(manifestBytes)) &&
            metadata.ReleaseSequence == manifest.ReleaseSequence &&
            metadata.DisplayVersion == manifest.Release;
    }

    /// <summary>Checks a v2 pair against the established, separate production public roots.</summary>
    public static bool VerifyProductionBoundMetadata(ReadOnlySpan<byte> manifestBytes,
        ReadOnlySpan<byte> metadataBytes) => VerifyBoundMetadata(manifestBytes, metadataBytes,
            OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo,
            OfflineReleasePublicKeys.ReleaseMetadataSubjectPublicKeyInfo);

    private static bool IsCanonicalInventory(IReadOnlyList<TrustedManifestV2File> files)
    {
        if (files.Count is < 1 or > MaximumFiles) return false;
        var seenFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenDirectories = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? previous = null;
        foreach (var file in files)
        {
            if (file is null || !IsSafeRelativePath(file.Path) || !IsUpperHash(file.Sha256) ||
                !seenFiles.Add(file.Path) ||
                (previous is not null && StringComparer.Ordinal.Compare(previous, file.Path) >= 0) ||
                seenDirectories.ContainsKey(file.Path)) return false;
            for (var slash = file.Path.IndexOf('/'); slash >= 0; slash = file.Path.IndexOf('/', slash + 1))
            {
                var directory = file.Path[..slash];
                if (seenFiles.Contains(directory)) return false;
                if (seenDirectories.TryGetValue(directory, out var original) && original != directory) return false;
                seenDirectories[directory] = directory;
            }
            previous = file.Path;
        }
        return true;
    }

    private static bool IsSafeRelativePath(string? path)
    {
        if (path is not { Length: > 0 and <= MaximumPathLength }) return false;
        var segments = path.Split('/');
        if (segments.Length > MaximumDepth) return false;
        foreach (var segment in segments)
        {
            if (segment.Length is < 1 or > MaximumSegmentLength ||
                !IsEndpointCharacter(segment[0]) || !IsEndpointCharacter(segment[^1]) ||
                ReservedDeviceNames.Contains(segment.Split('.')[0])) return false;
            foreach (var character in segment)
            {
                if (!IsEndpointCharacter(character) && character is not '.' and not '-') return false;
            }
        }
        return !IsSidecarPath(path, "Vantrel.Security.TrustedManifest") &&
            !IsSidecarPath(path, "Vantrel.Security.ReleaseMetadata");
    }

    private static bool IsSidecarPath(string path, string sidecar) =>
        path.Equals(sidecar, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(sidecar + "/", StringComparison.OrdinalIgnoreCase);

    private static bool IsEndpointCharacter(char c) => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or
        >= '0' and <= '9' or '_';

    private static bool IsCanonicalReleaseVersion(string? value)
    {
        if (value is not { Length: > 0 and <= 64 }) return false;
        var dash = value.IndexOf('-');
        var core = dash < 0 ? value : value[..dash];
        var numbers = core.Split('.');
        if (numbers.Length != 3 || numbers.Any(part => part.Length == 0 ||
            (part.Length > 1 && part[0] == '0') ||
            part.Any(c => c is < '0' or > '9'))) return false;
        if (dash < 0) return true;
        var prerelease = value[(dash + 1)..].Split('.');
        return prerelease.All(part => part.Length > 0 &&
            part.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'Z' or >= 'a' and <= 'z'));
    }

    private static bool TryField(string line, string name, out string value)
    {
        var prefix = name + "=";
        if (!line.StartsWith(prefix, StringComparison.Ordinal)) { value = string.Empty; return false; }
        value = line[prefix.Length..];
        return true;
    }

    private static bool TryCanonicalPositiveNumber<T>(string value, out T number) where T : struct, IParsable<T>
    {
        number = default;
        return value.Length > 0 && value[0] is >= '1' and <= '9' &&
            value.All(c => c is >= '0' and <= '9') &&
            T.TryParse(value, CultureInfo.InvariantCulture, out number);
    }

    private static bool IsUpperHash(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool IsNistP256(ECDsa key)
    {
        try { return key.KeySize == 256 && key.ExportParameters(false).Curve.Oid.Value == "1.2.840.10045.3.1.7"; }
        catch (CryptographicException) { return false; }
    }
}

/// <summary>
/// Explicit schema dispatch for callers that opt into version-aware parsing. Existing v1
/// production callers remain bound to <see cref="TrustedManifestCodec"/> until integration.
/// </summary>
public static class TrustedManifestSchemaCodec
{
    public static bool TryParse(ReadOnlySpan<byte> bytes, out TrustedManifest? v1,
        out TrustedManifestV2? v2, out TrustedManifestParseFailure failure)
    {
        v1 = null;
        v2 = null;
        if (bytes.IsEmpty) { failure = TrustedManifestParseFailure.Unavailable; return false; }
        var newline = bytes.IndexOf((byte)'\n');
        if (newline is < 1 or > 64)
        { failure = TrustedManifestParseFailure.Malformed; return false; }
        var header = bytes[..newline];
        if (header.SequenceEqual("schema=vantrel-trusted-manifest-v1"u8))
            return TrustedManifestCodec.TryParse(bytes, out v1, out failure);
        if (header.SequenceEqual("schema=vantrel-trusted-manifest-v2"u8))
            return TrustedManifestV2Codec.TryParse(bytes, out v2, out failure);
        failure = header.StartsWith("schema="u8) ?
            TrustedManifestParseFailure.UnsupportedSchema : TrustedManifestParseFailure.Malformed;
        return false;
    }
}
