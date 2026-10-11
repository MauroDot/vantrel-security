using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>Public, immutable evidence for an explicitly selected v2 Service release gate.</summary>
public sealed class BetaReleaseRecordV2
{
    public BetaReleaseRecordV2(BetaReleaseDescriptor descriptor, string sourceLockSha256,
        string signedManifestSha256, string manifestPayloadSha256, string signedMetadataSha256,
        IReadOnlyList<TrustedManifestV2File> serviceFiles,
        IReadOnlyList<AuthenticodeReleaseEvidence> authenticodeEvidence,
        IReadOnlyList<TrustedManifestV2File> diagnosticSymbols)
    {
        Descriptor = descriptor;
        SourceLockSha256 = sourceLockSha256;
        SignedManifestSha256 = signedManifestSha256;
        ManifestPayloadSha256 = manifestPayloadSha256;
        SignedMetadataSha256 = signedMetadataSha256;
        ServiceFiles = new ReadOnlyCollection<TrustedManifestV2File>(serviceFiles.ToArray());
        AuthenticodeEvidence = new ReadOnlyCollection<AuthenticodeReleaseEvidence>(authenticodeEvidence.ToArray());
        DiagnosticSymbols = new ReadOnlyCollection<TrustedManifestV2File>(diagnosticSymbols.ToArray());
    }

    public BetaReleaseDescriptor Descriptor { get; }
    public string SourceLockSha256 { get; }
    public string SignedManifestSha256 { get; }
    public string ManifestPayloadSha256 { get; }
    public string SignedMetadataSha256 { get; }
    public IReadOnlyList<TrustedManifestV2File> ServiceFiles { get; }
    public IReadOnlyList<AuthenticodeReleaseEvidence> AuthenticodeEvidence { get; }
    public IReadOnlyList<TrustedManifestV2File> DiagnosticSymbols { get; }
}

/// <summary>
/// Strict v2-only Service record. Parsing this file never falls back to the historical v1
/// record. Hashes and categories are public evidence, not certificate or signer diagnostics.
/// </summary>
public static class BetaReleaseRecordV2Codec
{
    public const string FileName = "beta-release-record-v2.txt";
    public const string Schema = "vantrel-beta-release-record-v2";
    public const string TargetFramework = "net10.0-windows";
    public const string SdkVersion = "10.0.401";
    public const string SigningProfileAlias = "vantrel-production";
    public const string SigningPolicyId = "vantrel-azure-artifact-signing-durable-eku-v1";
    private const int FixedLineCount = 22;
    private const int MaxBytes = 512 * 1024;
    private static readonly Encoding Ascii = Encoding.ASCII;

    private static readonly string[] FixedKeys =
    [
        "schema", "source-commit", "release-version", "release-sequence", "published-at-utc",
        "configuration", "target-framework", "runtime", "deployment", "sdk-version",
        "source-lock-sha256", "release-notes-sha256", "locked-restore",
        "trusted-manifest-v2-file-sha256", "trusted-manifest-v2-payload-sha256",
        "release-metadata-file-sha256", "manifest-metadata-binding", "service-file-count", "diagnostic-symbol-count",
        "authenticode-profile-alias", "authenticode-policy-id", "authenticode-artifact-count"
    ];

    public static byte[] CreateCanonical(BetaReleaseRecordV2 record)
    {
        Validate(record);
        var descriptor = record.Descriptor;
        var text = new StringBuilder()
            .Append("schema=").Append(Schema).Append('\n')
            .Append("source-commit=").Append(descriptor.SourceCommit).Append('\n')
            .Append("release-version=").Append(descriptor.ReleaseVersion).Append('\n')
            .Append("release-sequence=").Append(descriptor.ReleaseSequence.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("published-at-utc=").Append(descriptor.PublishedAtUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)).Append('\n')
            .Append("configuration=Release\n")
            .Append("target-framework=").Append(TargetFramework).Append('\n')
            .Append("runtime=win-x64\n")
            .Append("deployment=").Append(TrustedManifestV2Codec.Deployment).Append('\n')
            .Append("sdk-version=").Append(SdkVersion).Append('\n')
            .Append("source-lock-sha256=").Append(record.SourceLockSha256).Append('\n')
            .Append("release-notes-sha256=").Append(descriptor.ReleaseNotesSha256).Append('\n')
            .Append("locked-restore=valid\n")
            .Append("trusted-manifest-v2-file-sha256=").Append(record.SignedManifestSha256).Append('\n')
            .Append("trusted-manifest-v2-payload-sha256=").Append(record.ManifestPayloadSha256).Append('\n')
            .Append("release-metadata-file-sha256=").Append(record.SignedMetadataSha256).Append('\n')
            .Append("manifest-metadata-binding=valid\n")
            .Append("service-file-count=").Append(record.ServiceFiles.Count.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("diagnostic-symbol-count=").Append(record.DiagnosticSymbols.Count.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("authenticode-profile-alias=").Append(SigningProfileAlias).Append('\n')
            .Append("authenticode-policy-id=").Append(SigningPolicyId).Append('\n')
            .Append("authenticode-artifact-count=").Append(record.AuthenticodeEvidence.Count.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (var evidence in record.AuthenticodeEvidence)
            text.Append("authenticode=").Append(evidence.RelativePath).Append('|').Append(evidence.Category).Append('|')
                .Append(evidence.SignerPolicyId).Append('|').Append(evidence.PrimarySignatureCount).Append('|')
                .Append(evidence.Timestamp).Append('\n');
        foreach (var file in record.ServiceFiles)
            text.Append("file=").Append(file.Path).Append('|').Append(file.Sha256).Append('\n');
        foreach (var file in record.DiagnosticSymbols)
            text.Append("diagnostic-symbol=").Append(file.Path).Append('|').Append(file.Sha256).Append('\n');
        var bytes = Ascii.GetBytes(text.ToString());
        if (bytes.Length > MaxBytes) throw new ArgumentException("V2 release record is oversized.", nameof(record));
        return bytes;
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out BetaReleaseRecordV2? record)
    {
        record = null;
        if (bytes.IsEmpty || bytes.Length > MaxBytes || bytes[^1] != (byte)'\n') return false;
        foreach (var value in bytes)
            if (value != (byte)'\n' && (value < 0x20 || value > 0x7E)) return false;
        var lines = Ascii.GetString(bytes).Split('\n');
        if (lines.Length < FixedLineCount + 1 || lines[^1].Length != 0) return false;
        var values = new string[FixedLineCount];
        for (var i = 0; i < FixedLineCount; i++)
        {
            var prefix = FixedKeys[i] + "=";
            if (!lines[i].StartsWith(prefix, StringComparison.Ordinal)) return false;
            values[i] = lines[i][prefix.Length..];
        }
        if (values[0] != Schema || values[6] != TargetFramework || values[8] != TrustedManifestV2Codec.Deployment ||
            values[9] != SdkVersion || values[12] != "valid" || values[16] != "valid" ||
            values[19] != SigningProfileAlias || values[20] != SigningPolicyId ||
            !IsHash(values[10]) || !IsHash(values[13]) || !IsHash(values[14]) || !IsHash(values[15]) ||
            !TryCanonicalCount(values[17], TrustedManifestV2Codec.MaximumFiles, out var fileCount) ||
            !TryCanonicalCount(values[18], 3, out var diagnosticCount) || diagnosticCount != 3 ||
            !TryCanonicalCount(values[21], 4, out var evidenceCount) || evidenceCount != 4 ||
            lines.Length != FixedLineCount + evidenceCount + fileCount + diagnosticCount + 1) return false;

        var descriptorBytes = Ascii.GetBytes($"schema={BetaReleaseDescriptorCodec.Schema}\n" +
            $"source-commit={values[1]}\nrelease-version={values[2]}\nrelease-sequence={values[3]}\n" +
            $"published-at-utc={values[4]}\nconfiguration={values[5]}\nruntime={values[7]}\n" +
            $"sdk-version={values[9]}\nrelease-notes-sha256={values[11]}\n");
        if (!BetaReleaseDescriptorCodec.TryParse(descriptorBytes, out var descriptor) || descriptor is null) return false;

        var evidence = new AuthenticodeReleaseEvidence[evidenceCount];
        for (var i = 0; i < evidence.Length; i++)
        {
            var line = lines[FixedLineCount + i];
            if (!line.StartsWith("authenticode=", StringComparison.Ordinal)) return false;
            var parts = line["authenticode=".Length..].Split('|');
            if (parts.Length != 5 ||
                !Enum.TryParse<AuthenticodeVerificationCategory>(parts[1], false, out var category) ||
                !Enum.TryParse<PrimarySignatureCountPolicyCategory>(parts[3], false, out var primary) ||
                !Enum.TryParse<TimestampPolicyCategory>(parts[4], false, out var timestamp)) return false;
            evidence[i] = new(parts[0], category, parts[2], primary, timestamp);
        }
        var files = new TrustedManifestV2File[fileCount];
        for (var i = 0; i < files.Length; i++)
        {
            var line = lines[FixedLineCount + evidenceCount + i];
            if (!line.StartsWith("file=", StringComparison.Ordinal)) return false;
            var parts = line["file=".Length..].Split('|');
            if (parts.Length != 2) return false;
            files[i] = new(parts[0], parts[1]);
        }
        var diagnostics = new TrustedManifestV2File[diagnosticCount];
        for (var i = 0; i < diagnostics.Length; i++)
        {
            var line = lines[FixedLineCount + evidenceCount + fileCount + i];
            if (!line.StartsWith("diagnostic-symbol=", StringComparison.Ordinal)) return false;
            var parts = line["diagnostic-symbol=".Length..].Split('|');
            if (parts.Length != 2) return false;
            diagnostics[i] = new(parts[0], parts[1]);
        }
        try
        {
            var candidate = new BetaReleaseRecordV2(descriptor, values[10], values[13], values[14],
                values[15], files, evidence, diagnostics);
            if (!bytes.SequenceEqual(CreateCanonical(candidate))) return false;
            record = candidate;
            return true;
        }
        catch (ArgumentException) { return false; }
    }

    private static void Validate(BetaReleaseRecordV2 record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.Descriptor is null || record.Descriptor.SdkVersion != SdkVersion ||
            !BetaReleaseDescriptorCodec.TryParse(BetaReleaseDescriptorCodec.CreateCanonical(record.Descriptor), out _) ||
            !IsHash(record.SourceLockSha256) || !IsHash(record.SignedManifestSha256) ||
            !IsHash(record.ManifestPayloadSha256) || !IsHash(record.SignedMetadataSha256) ||
            record.ServiceFiles.Count is < 1 or > TrustedManifestV2Codec.MaximumFiles ||
            record.ServiceFiles.Any(file => file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase) ||
                file.Path.Equals("packages.lock.json", StringComparison.OrdinalIgnoreCase) ||
                file.Path.EndsWith("/packages.lock.json", StringComparison.OrdinalIgnoreCase)) ||
            record.AuthenticodeEvidence.Count != 4)
            throw new ArgumentException("V2 release record is invalid.", nameof(record));

        if (record.DiagnosticSymbols.Count != 3 ||
            !record.DiagnosticSymbols.Select(file => file.Path).SequenceEqual(
                new[] { "Vantrel.Security.Core.pdb", "Vantrel.Security.Infrastructure.pdb",
                    "Vantrel.Security.Service.pdb" }, StringComparer.Ordinal) ||
            record.DiagnosticSymbols.Any(file => !IsHash(file.Sha256)))
            throw new ArgumentException("V2 diagnostic-symbol record is invalid.", nameof(record));

        _ = TrustedManifestV2Codec.CreateCanonicalPayload(record.Descriptor.ReleaseVersion,
            record.Descriptor.ReleaseSequence, record.ServiceFiles);
        var targets = ServiceReleaseV2PeContract.VantrelOwnedPeArtifacts.ToArray();
        for (var i = 0; i < targets.Length; i++)
        {
            var evidence = record.AuthenticodeEvidence[i];
            if (evidence.RelativePath != targets[i].RelativePath ||
                evidence.Category != AuthenticodeVerificationCategory.Valid ||
                evidence.SignerPolicyId != SigningPolicyId ||
                evidence.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne ||
                evidence.Timestamp != TimestampPolicyCategory.ValidRfc3161 ||
                !record.ServiceFiles.Any(file => "service/" + file.Path == evidence.RelativePath))
                throw new ArgumentException("V2 release record is invalid.", nameof(record));
        }
    }

    private static bool IsHash(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool TryCanonicalCount(string text, int maximum, out int value)
    {
        value = 0;
        return text.Length > 0 && text[0] is >= '1' and <= '9' &&
            text.All(c => c is >= '0' and <= '9') &&
            int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value) &&
            value <= maximum;
    }
}
