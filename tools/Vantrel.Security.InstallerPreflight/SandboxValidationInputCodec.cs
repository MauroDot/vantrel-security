using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Vantrel.Security.InstallerPreflight;

/// <summary>Canonical public-only input for a later, isolated Windows Sandbox validation run.</summary>
public sealed record SandboxValidationInput(
    string SourceCommit,
    string ReleaseVersion,
    ulong ReleaseSequence,
    DateTimeOffset PublishedAtUtc,
    string MsiProductVersion,
    string MsiSha256,
    string InstallerPlanSha256,
    IReadOnlyList<InstallerPlanArtifact> Artifacts);

public static class SandboxValidationInputCodec
{
    public const string FileName = "vantrel-sandbox-input-v1.txt";
    public const string Schema = "vantrel-sandbox-input-v1";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static void CreateAndWrite(
        string installerPlanPath,
        string msiPath,
        string outputPath,
        string sourceCommit,
        string releaseVersion,
        string releaseSequence,
        string publishedAtUtc,
        string msiProductVersion)
    {
        var planBytes = ReadRegularFile(installerPlanPath, "Installer input plan is unavailable.");
        if (!InstallerInputPlanCodec.TryParse(planBytes, out var plan) || plan is null ||
            !ulong.TryParse(releaseSequence, NumberStyles.None, CultureInfo.InvariantCulture, out var expectedSequence) ||
            !DateTimeOffset.TryParseExact(publishedAtUtc, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var expectedPublishedAt) ||
            !MsiProductVersion.TryParse(msiProductVersion, out _) ||
            !string.Equals(plan.Descriptor.SourceCommit, sourceCommit, StringComparison.Ordinal) ||
            !string.Equals(plan.Descriptor.ReleaseVersion, releaseVersion, StringComparison.Ordinal) ||
            plan.Descriptor.ReleaseSequence != expectedSequence ||
            plan.Descriptor.PublishedAtUtc != expectedPublishedAt ||
            !string.Equals(plan.MsiProductVersion, msiProductVersion, StringComparison.Ordinal))
            throw new IOException("Sandbox validation metadata is unavailable.");

        var msiHash = HashRegularFile(msiPath, "Unsigned MSI is unavailable.");
        var input = new SandboxValidationInput(
            plan.Descriptor.SourceCommit,
            plan.Descriptor.ReleaseVersion,
            plan.Descriptor.ReleaseSequence,
            plan.Descriptor.PublishedAtUtc,
            plan.MsiProductVersion,
            msiHash,
            Convert.ToHexString(SHA256.HashData(planBytes)),
            plan.Artifacts);
        WriteAtomically(outputPath, CreateCanonical(input));
    }

    public static string CreateCanonical(SandboxValidationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!IsHash(input.MsiSha256) || !IsHash(input.InstallerPlanSha256) ||
            string.IsNullOrWhiteSpace(input.SourceCommit) || input.SourceCommit.Length != 40 || !input.SourceCommit.All(value => value is >= '0' and <= '9' or >= 'a' and <= 'f') ||
            !MsiProductVersion.TryParse(input.MsiProductVersion, out _) || input.Artifacts.Count == 0 ||
            input.Artifacts.Any(item => item is null || !InstallerInputValidator.IsInstallArtifact(item.SourceRelativePath) ||
                !InstallerInputValidator.IsAllowedArtifactPath(item.SourceRelativePath) || item.Destination != InstallerInputValidator.DestinationFor(item.SourceRelativePath) || !IsHash(item.Sha256)) ||
            input.Artifacts.Select(item => item.SourceRelativePath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != input.Artifacts.Count)
            throw new ArgumentException("Sandbox validation input is not canonical.", nameof(input));

        var text = new StringBuilder()
            .Append("schema=").Append(Schema).Append('\n')
            .Append("source-commit=").Append(input.SourceCommit).Append('\n')
            .Append("release-version=").Append(input.ReleaseVersion).Append('\n')
            .Append("release-sequence=").Append(input.ReleaseSequence.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("published-at-utc=").Append(input.PublishedAtUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)).Append('\n')
            .Append("msi-product-version=").Append(input.MsiProductVersion).Append('\n')
            .Append("msi-sha256=").Append(input.MsiSha256).Append('\n')
            .Append("installer-plan-sha256=").Append(input.InstallerPlanSha256).Append('\n')
            .Append("artifact-count=").Append(input.Artifacts.Count.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (var artifact in input.Artifacts.OrderBy(item => item.SourceRelativePath, StringComparer.Ordinal))
            text.Append("artifact=").Append(artifact.SourceRelativePath).Append('|').Append(artifact.Destination.DirectoryId).Append('\\').Append(artifact.Destination.RelativePath).Append('|').Append(artifact.Sha256).Append('\n');
        return text.ToString();
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out SandboxValidationInput? input)
    {
        input = null;
        if (bytes.Length is 0 or > 1024 * 1024 || bytes.IndexOf((byte)'\r') >= 0 || HasBom(bytes) || HasNonAscii(bytes)) return false;
        string text;
        try { text = Utf8.GetString(bytes); } catch (DecoderFallbackException) { return false; }
        if (!text.EndsWith('\n')) return false;
        var lines = text.Split('\n');
        if (lines.Length < 11 || lines[^1].Length != 0) return false;
        var keys = new[] { "schema", "source-commit", "release-version", "release-sequence", "published-at-utc", "msi-product-version", "msi-sha256", "installer-plan-sha256", "artifact-count" };
        var values = new string[keys.Length];
        for (var index = 0; index < keys.Length; index++)
        {
            var prefix = keys[index] + "=";
            if (!lines[index].StartsWith(prefix, StringComparison.Ordinal)) return false;
            values[index] = lines[index][prefix.Length..];
        }
        if (values[0] != Schema || values[1].Length != 40 || !values[1].All(value => value is >= '0' and <= '9' or >= 'a' and <= 'f') ||
            !ulong.TryParse(values[3], NumberStyles.None, CultureInfo.InvariantCulture, out var sequence) ||
            !DateTimeOffset.TryParseExact(values[4], "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var publishedAt) ||
            !MsiProductVersion.TryParse(values[5], out _) || !IsHash(values[6]) || !IsHash(values[7]) ||
            !uint.TryParse(values[8], NumberStyles.None, CultureInfo.InvariantCulture, out var count) || count == 0 || count > int.MaxValue ||
            (long)lines.Length != 10L + count)
            return false;
        var artifacts = new List<InstallerPlanArtifact>((int)count);
        for (var index = 0; index < count; index++)
        {
            var line = lines[9 + index];
            if (!line.StartsWith("artifact=", StringComparison.Ordinal)) return false;
            var parts = line["artifact=".Length..].Split('|');
            if (parts.Length != 3 || !InstallerInputValidator.IsInstallArtifact(parts[0]) || !InstallerInputValidator.IsAllowedArtifactPath(parts[0]) ||
                !TryParseDestination(parts[1], out var destination) || destination != InstallerInputValidator.DestinationFor(parts[0]) || !IsHash(parts[2])) return false;
            artifacts.Add(new(parts[0], destination, parts[2]));
        }
        if (artifacts.Select(item => item.SourceRelativePath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != artifacts.Count) return false;
        try
        {
            input = new(values[1], values[2], sequence, publishedAt, values[5], values[6], values[7], Array.AsReadOnly(artifacts.ToArray()));
            return bytes.SequenceEqual(Utf8.GetBytes(CreateCanonical(input)));
        }
        catch (ArgumentException) { input = null; return false; }
    }

    private static bool TryParseDestination(string value, out InstallerDestination destination)
    {
        destination = null!;
        const string prefix = "ProgramFiles64Folder\\";
        if (!value.StartsWith(prefix, StringComparison.Ordinal) || value.Length == prefix.Length || value.Contains('|') || value.Contains(':') || value.Contains("\\\\", StringComparison.Ordinal)) return false;
        destination = new("ProgramFiles64Folder", value[prefix.Length..]);
        return true;
    }

    private static byte[] ReadRegularFile(string path, string message)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException(message);
        return File.ReadAllBytes(path);
    }

    private static string HashRegularFile(string path, string message)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException(message);
        var before = new FileInfo(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        var after = new FileInfo(path);
        if (!after.Exists || (after.Attributes & FileAttributes.ReparsePoint) != 0 || before.Length != after.Length || before.LastWriteTimeUtc != after.LastWriteTimeUtc) throw new IOException(message);
        return hash;
    }

    private static void WriteAtomically(string path, string content)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new IOException("Sandbox validation manifest is unavailable.");
        var full = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(full);
        if (string.IsNullOrWhiteSpace(parent) || Directory.Exists(full) || (File.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) ||
            (Directory.Exists(parent) && (File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0)) throw new IOException("Sandbox validation manifest is unavailable.");
        Directory.CreateDirectory(parent);
        var temporary = full + ".tmp";
        try { File.WriteAllBytes(temporary, Utf8.GetBytes(content)); File.Move(temporary, full, true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(value => value is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool HasBom(ReadOnlySpan<byte> bytes) => bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
    private static bool HasNonAscii(ReadOnlySpan<byte> bytes) { foreach (var value in bytes) if (value > 0x7f) return true; return false; }
}
