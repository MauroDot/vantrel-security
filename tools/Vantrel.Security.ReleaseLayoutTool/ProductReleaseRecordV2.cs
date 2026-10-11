using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>Public release-gate evidence; it is not an installer plan or a standalone signature.</summary>
public sealed class ProductReleaseRecordV2
{
    public ProductReleaseRecordV2(BetaReleaseDescriptor descriptor, string serviceRecordSha256,
        string serviceManifestSha256, string serviceMetadataSha256,
        string desktopSourceLockSha256, string toolSourceLockSha256,
        IReadOnlyList<TrustedManifestV2File> serviceFiles,
        IReadOnlyList<TrustedManifestV2File> desktopFiles,
        IReadOnlyList<TrustedManifestV2File> toolFiles,
        IReadOnlyList<TrustedManifestV2File> diagnosticSymbols,
        IReadOnlyList<TrustedManifestV2File> excludedBuildArtifacts,
        IReadOnlyList<AuthenticodeReleaseEvidence> authenticodeEvidence)
    {
        Descriptor = descriptor;
        ServiceRecordSha256 = serviceRecordSha256;
        ServiceManifestSha256 = serviceManifestSha256;
        ServiceMetadataSha256 = serviceMetadataSha256;
        DesktopSourceLockSha256 = desktopSourceLockSha256;
        ToolSourceLockSha256 = toolSourceLockSha256;
        ServiceFiles = Copy(serviceFiles);
        DesktopFiles = Copy(desktopFiles);
        ToolFiles = Copy(toolFiles);
        DiagnosticSymbols = Copy(diagnosticSymbols);
        ExcludedBuildArtifacts = Copy(excludedBuildArtifacts);
        AuthenticodeEvidence = new ReadOnlyCollection<AuthenticodeReleaseEvidence>(authenticodeEvidence.ToArray());
    }

    private static IReadOnlyList<TrustedManifestV2File> Copy(IReadOnlyList<TrustedManifestV2File> source) =>
        new ReadOnlyCollection<TrustedManifestV2File>(source.ToArray());

    public BetaReleaseDescriptor Descriptor { get; }
    public string ServiceRecordSha256 { get; }
    public string ServiceManifestSha256 { get; }
    public string ServiceMetadataSha256 { get; }
    public string DesktopSourceLockSha256 { get; }
    public string ToolSourceLockSha256 { get; }
    public IReadOnlyList<TrustedManifestV2File> ServiceFiles { get; }
    public IReadOnlyList<TrustedManifestV2File> DesktopFiles { get; }
    public IReadOnlyList<TrustedManifestV2File> ToolFiles { get; }
    public IReadOnlyList<TrustedManifestV2File> DiagnosticSymbols { get; }
    public IReadOnlyList<TrustedManifestV2File> ExcludedBuildArtifacts { get; }
    public IReadOnlyList<AuthenticodeReleaseEvidence> AuthenticodeEvidence { get; }
}

/// <summary>Strict, bounded ASCII/LF v2 product record. No v1 dispatch exists here.</summary>
public static class ProductReleaseRecordV2Codec
{
    public const string FileName = "product-release-record-v2.txt";
    public const string Schema = "vantrel-product-release-record-v2";
    private const int MaximumBytes = 512 * 1024;
    private static readonly Encoding Ascii = Encoding.ASCII;
    private static readonly string[] Keys =
    [
        "schema", "source-commit", "release-version", "release-sequence", "published-at-utc",
        "configuration", "target-framework", "runtime", "deployment", "sdk-version",
        "release-notes-sha256", "service-record-sha256", "service-manifest-sha256",
        "service-metadata-sha256", "desktop-source-lock-sha256", "tool-source-lock-sha256",
        "authenticode-policy-id", "authenticode-artifact-count", "service-file-count",
        "desktop-file-count", "tool-file-count", "diagnostic-symbol-count", "source-residue-count",
        "installer-sidecar-count"
    ];

    public static byte[] CreateCanonical(ProductReleaseRecordV2 record)
    {
        Validate(record);
        var d = record.Descriptor;
        var text = new StringBuilder()
            .Append("schema=").Append(Schema).Append('\n')
            .Append("source-commit=").Append(d.SourceCommit).Append('\n')
            .Append("release-version=").Append(d.ReleaseVersion).Append('\n')
            .Append("release-sequence=").Append(d.ReleaseSequence.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("published-at-utc=").Append(d.PublishedAtUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)).Append('\n')
            .Append("configuration=Release\n")
            .Append("target-framework=").Append(BetaReleaseRecordV2Codec.TargetFramework).Append('\n')
            .Append("runtime=win-x64\n")
            .Append("deployment=").Append(TrustedManifestV2Codec.Deployment).Append('\n')
            .Append("sdk-version=").Append(BetaReleaseRecordV2Codec.SdkVersion).Append('\n')
            .Append("release-notes-sha256=").Append(d.ReleaseNotesSha256).Append('\n')
            .Append("service-record-sha256=").Append(record.ServiceRecordSha256).Append('\n')
            .Append("service-manifest-sha256=").Append(record.ServiceManifestSha256).Append('\n')
            .Append("service-metadata-sha256=").Append(record.ServiceMetadataSha256).Append('\n')
            .Append("desktop-source-lock-sha256=").Append(record.DesktopSourceLockSha256).Append('\n')
            .Append("tool-source-lock-sha256=").Append(record.ToolSourceLockSha256).Append('\n')
            .Append("authenticode-policy-id=").Append(BetaReleaseRecordV2Codec.SigningPolicyId).Append('\n')
            .Append("authenticode-artifact-count=9\n")
            .Append("service-file-count=").Append(record.ServiceFiles.Count).Append('\n')
            .Append("desktop-file-count=").Append(record.DesktopFiles.Count).Append('\n')
            .Append("tool-file-count=").Append(record.ToolFiles.Count).Append('\n')
            .Append("diagnostic-symbol-count=").Append(record.DiagnosticSymbols.Count).Append('\n')
            .Append("source-residue-count=").Append(record.ExcludedBuildArtifacts.Count).Append('\n')
            .Append("installer-sidecar-count=2\n");
        foreach (var evidence in record.AuthenticodeEvidence)
            text.Append("authenticode=").Append(evidence.RelativePath).Append('|')
                .Append(evidence.Category).Append('|').Append(evidence.SignerPolicyId).Append('|')
                .Append(evidence.PrimarySignatureCount).Append('|').Append(evidence.Timestamp).Append('\n');
        Emit(text, "service-file", record.ServiceFiles);
        Emit(text, "desktop-file", record.DesktopFiles);
        Emit(text, "tool-file", record.ToolFiles);
        text.Append("installer-sidecar=service/Vantrel.Security.TrustedManifest|")
            .Append(record.ServiceManifestSha256).Append('\n')
            .Append("installer-sidecar=service/Vantrel.Security.ReleaseMetadata|")
            .Append(record.ServiceMetadataSha256).Append('\n');
        Emit(text, "diagnostic-symbol", record.DiagnosticSymbols);
        Emit(text, "source-residue", record.ExcludedBuildArtifacts);
        var bytes = Ascii.GetBytes(text.ToString());
        if (bytes.Length > MaximumBytes) throw new ArgumentException("Product record is oversized.");
        return bytes;
    }

    private static void Emit(StringBuilder builder, string key, IReadOnlyList<TrustedManifestV2File> entries)
    {
        foreach (var file in entries)
            builder.Append(key).Append('=').Append(file.Path).Append('|').Append(file.Sha256).Append('\n');
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out ProductReleaseRecordV2? record)
    {
        record = null;
        if (bytes.IsEmpty || bytes.Length > MaximumBytes || bytes[^1] != (byte)'\n' ||
            bytes.ToArray().Any(value => value != (byte)'\n' && (value < 0x20 || value > 0x7E))) return false;
        var lines = Ascii.GetString(bytes).Split('\n');
        if (lines[^1].Length != 0 || lines.Length < Keys.Length + 1) return false;
        var values = new string[Keys.Length];
        for (var i = 0; i < Keys.Length; i++)
        {
            var prefix = Keys[i] + "=";
            if (!lines[i].StartsWith(prefix, StringComparison.Ordinal)) return false;
            values[i] = lines[i][prefix.Length..];
        }
        if (values[0] != Schema || values[6] != BetaReleaseRecordV2Codec.TargetFramework ||
            values[8] != TrustedManifestV2Codec.Deployment ||
            values[9] != BetaReleaseRecordV2Codec.SdkVersion ||
            values[16] != BetaReleaseRecordV2Codec.SigningPolicyId || values[17] != "9" ||
            values[23] != "2" ||
            !TryCount(values[18], TrustedManifestV2Codec.MaximumFiles, out var serviceCount) ||
            !TryCount(values[19], TrustedManifestV2Codec.MaximumFiles, out var desktopCount) ||
            !TryCount(values[20], TrustedManifestV2Codec.MaximumFiles, out var toolCount) ||
            !TryCount(values[21], 64, out var diagnosticCount, allowZero: true) ||
            !TryCount(values[22], 16, out var residueCount, allowZero: true) ||
            lines.Length != Keys.Length + 9 + serviceCount + desktopCount + toolCount + 2 +
                diagnosticCount + residueCount + 1) return false;
        var descriptorBytes = Ascii.GetBytes($"schema={BetaReleaseDescriptorCodec.Schema}\n" +
            $"source-commit={values[1]}\nrelease-version={values[2]}\nrelease-sequence={values[3]}\n" +
            $"published-at-utc={values[4]}\nconfiguration={values[5]}\nruntime={values[7]}\n" +
            $"sdk-version={values[9]}\nrelease-notes-sha256={values[10]}\n");
        if (!BetaReleaseDescriptorCodec.TryParse(descriptorBytes, out var descriptor) || descriptor is null) return false;
        var cursor = Keys.Length;
        var evidence = new AuthenticodeReleaseEvidence[9];
        for (var i = 0; i < evidence.Length; i++)
        {
            if (!Take(lines, ref cursor, "authenticode", out var value)) return false;
            var fields = value.Split('|');
            if (fields.Length != 5 ||
                !Enum.TryParse<AuthenticodeVerificationCategory>(fields[1], out var category) ||
                !Enum.TryParse<PrimarySignatureCountPolicyCategory>(fields[3], out var primary) ||
                !Enum.TryParse<TimestampPolicyCategory>(fields[4], out var timestamp)) return false;
            evidence[i] = new(fields[0], category, fields[2], primary, timestamp);
        }
        if (!TakeFiles(lines, ref cursor, "service-file", serviceCount, out var service) ||
            !TakeFiles(lines, ref cursor, "desktop-file", desktopCount, out var desktop) ||
            !TakeFiles(lines, ref cursor, "tool-file", toolCount, out var tool) ||
            !Take(lines, ref cursor, "installer-sidecar", out var manifestSidecar) ||
            !Take(lines, ref cursor, "installer-sidecar", out var metadataSidecar) ||
            manifestSidecar != "service/Vantrel.Security.TrustedManifest|" + values[12] ||
            metadataSidecar != "service/Vantrel.Security.ReleaseMetadata|" + values[13] ||
            !TakeFiles(lines, ref cursor, "diagnostic-symbol", diagnosticCount, out var diagnostics) ||
            !TakeFiles(lines, ref cursor, "source-residue", residueCount, out var residue) ||
            cursor != lines.Length - 1) return false;
        try
        {
            var candidate = new ProductReleaseRecordV2(descriptor, values[11], values[12], values[13],
                values[14], values[15], service, desktop, tool, diagnostics, residue, evidence);
            if (!bytes.SequenceEqual(CreateCanonical(candidate))) return false;
            record = candidate;
            return true;
        }
        catch (ArgumentException) { return false; }
    }

    private static bool Take(string[] lines, ref int cursor, string key, out string value)
    {
        value = string.Empty;
        var prefix = key + "=";
        if (cursor >= lines.Length - 1 || !lines[cursor].StartsWith(prefix, StringComparison.Ordinal))
            return false;
        value = lines[cursor++][prefix.Length..];
        return true;
    }

    private static bool TakeFiles(string[] lines, ref int cursor, string key, int count,
        out TrustedManifestV2File[] files)
    {
        files = new TrustedManifestV2File[count];
        for (var i = 0; i < count; i++)
        {
            if (!Take(lines, ref cursor, key, out var value)) return false;
            var fields = value.Split('|');
            if (fields.Length != 2) return false;
            files[i] = new(fields[0], fields[1]);
        }
        return true;
    }

    private static void Validate(ProductReleaseRecordV2 record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.Descriptor is null || record.Descriptor.SdkVersion != BetaReleaseRecordV2Codec.SdkVersion ||
            !BetaReleaseDescriptorCodec.TryParse(BetaReleaseDescriptorCodec.CreateCanonical(record.Descriptor), out _) ||
            !Hash(record.ServiceRecordSha256) || !Hash(record.ServiceManifestSha256) ||
            !Hash(record.ServiceMetadataSha256) || !Hash(record.DesktopSourceLockSha256) ||
            !Hash(record.ToolSourceLockSha256) || record.AuthenticodeEvidence.Count != 9 ||
            record.DiagnosticSymbols.Count > 64 || record.ExcludedBuildArtifacts.Count > 16)
            throw new ArgumentException("Product record is invalid.");
        ValidateGroup(record.Descriptor, record.ServiceFiles, "service");
        ValidateGroup(record.Descriptor, record.DesktopFiles, "desktop");
        ValidateGroup(record.Descriptor, record.ToolFiles, "offline-update-tool");
        ValidateOther(record.DiagnosticSymbols, "diagnostic-symbols", ".pdb");
        ValidateOther(record.ExcludedBuildArtifacts, "publish", null);
        string[] expectedDiagnostics =
        [
            "diagnostic-symbols/Vantrel.Security.Core.pdb",
            "diagnostic-symbols/Vantrel.Security.Infrastructure.pdb",
            "diagnostic-symbols/Vantrel.Security.Service.pdb",
            "diagnostic-symbols/desktop/Vantrel.Security.Core.pdb",
            "diagnostic-symbols/desktop/Vantrel.Security.Desktop.pdb",
            "diagnostic-symbols/desktop/Vantrel.Security.Infrastructure.pdb",
            "diagnostic-symbols/offline-update-tool/Vantrel.Security.Core.pdb",
            "diagnostic-symbols/offline-update-tool/Vantrel.Security.Infrastructure.pdb",
            "diagnostic-symbols/offline-update-tool/Vantrel.Security.OfflineUpdateTool.pdb",
            "diagnostic-symbols/offline-update-tool/Vantrel.Security.Service.pdb"
        ];
        string[] expectedResidue =
        [
            "publish/offline-update-tool/Vantrel.Security.Service.deps.json",
            "publish/offline-update-tool/Vantrel.Security.Service.exe",
            "publish/offline-update-tool/Vantrel.Security.Service.runtimeconfig.json",
            "publish/offline-update-tool/packages.lock.json"
        ];
        var actualResidue = record.ExcludedBuildArtifacts;
        var hasDesktopLock = actualResidue.Count == expectedResidue.Length + 1 &&
            actualResidue[0].Path == "publish/desktop/packages.lock.json" &&
            actualResidue[0].Sha256 == record.DesktopSourceLockSha256;
        if (!record.DiagnosticSymbols.Select(file => file.Path).SequenceEqual(
                expectedDiagnostics.OrderBy(path => path, StringComparer.Ordinal)) ||
            !(actualResidue.Count == expectedResidue.Length || hasDesktopLock) ||
            !actualResidue.Skip(hasDesktopLock ? 1 : 0).Select(file => file.Path)
                .SequenceEqual(expectedResidue))
            throw new ArgumentException("Product excluded inventory is invalid.");
        var owned = ReleaseSigningContract.VantrelOwnedPeArtifacts.Skip(4).ToArray();
        for (var i = 0; i < owned.Length; i++)
        {
            var evidence = record.AuthenticodeEvidence[i];
            if (evidence.RelativePath != owned[i].RelativePath ||
                evidence.Category != AuthenticodeVerificationCategory.Valid ||
                evidence.SignerPolicyId != BetaReleaseRecordV2Codec.SigningPolicyId ||
                evidence.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne ||
                evidence.Timestamp != TimestampPolicyCategory.ValidRfc3161 ||
                !(evidence.RelativePath.StartsWith("desktop/", StringComparison.Ordinal)
                    ? record.DesktopFiles : record.ToolFiles).Any(file =>
                    evidence.RelativePath.EndsWith("/" + file.Path, StringComparison.Ordinal)))
                throw new ArgumentException("Product Authenticode evidence is invalid.");
        }
    }

    private static void ValidateGroup(BetaReleaseDescriptor descriptor,
        IReadOnlyList<TrustedManifestV2File> files, string group)
    {
        _ = TrustedManifestV2Codec.CreateCanonicalPayload(descriptor.ReleaseVersion,
            descriptor.ReleaseSequence, files);
        if (files.Any(file => file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase) ||
            file.Path.Equals("packages.lock.json", StringComparison.OrdinalIgnoreCase) ||
            file.Path.EndsWith("/packages.lock.json", StringComparison.OrdinalIgnoreCase) ||
            file.Path.StartsWith("Vantrel.Security.TrustedManifest", StringComparison.OrdinalIgnoreCase) ||
            file.Path.StartsWith("Vantrel.Security.ReleaseMetadata", StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException(group + " inventory contains residue.");
    }

    private static void ValidateOther(IReadOnlyList<TrustedManifestV2File> files,
        string root, string? suffix)
    {
        if (files.Count == 0) return;
        _ = TrustedManifestV2Codec.CreateCanonicalPayload("0.0.0", 1, files);
        if (files.Any(file => !file.Path.StartsWith(root + "/", StringComparison.Ordinal) ||
            (suffix is not null && !file.Path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))))
            throw new ArgumentException("Product excluded inventory is invalid.");
    }

    private static bool Hash(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool TryCount(string text, int max, out int value, bool allowZero = false)
    {
        value = 0;
        return (allowZero && text == "0") ||
            (text.Length > 0 && text[0] is >= '1' and <= '9' &&
             text.All(c => c is >= '0' and <= '9') &&
             int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value) &&
             value <= max);
    }
}
