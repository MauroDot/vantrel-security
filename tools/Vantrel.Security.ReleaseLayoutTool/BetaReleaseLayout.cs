using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.ManifestTool;

namespace Vantrel.Security.ReleaseLayoutTool;

public sealed record BetaReleaseDescriptor(string SourceCommit, string ReleaseVersion, ulong ReleaseSequence,
    DateTimeOffset PublishedAtUtc, string Configuration, string Runtime, string SdkVersion, string ReleaseNotesSha256);

public static class BetaReleaseDescriptorCodec
{
    public const string FileName = "beta-release-descriptor-v1.txt";
    public const string Schema = "vantrel-beta-release-descriptor-v1";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static byte[] CreateCanonical(BetaReleaseDescriptor descriptor)
    {
        Validate(descriptor);
        return Utf8.GetBytes($"schema={Schema}\nsource-commit={descriptor.SourceCommit}\nrelease-version={descriptor.ReleaseVersion}\nrelease-sequence={descriptor.ReleaseSequence.ToString(CultureInfo.InvariantCulture)}\npublished-at-utc={descriptor.PublishedAtUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)}\nconfiguration={descriptor.Configuration}\nruntime={descriptor.Runtime}\nsdk-version={descriptor.SdkVersion}\nrelease-notes-sha256={descriptor.ReleaseNotesSha256}\n");
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out BetaReleaseDescriptor? descriptor)
    {
        descriptor = null;
        if (bytes.Length is 0 or > 2048 || bytes.IndexOf((byte)'\r') >= 0 || HasBom(bytes) || HasNonAscii(bytes)) return false;
        string text;
        try { text = Utf8.GetString(bytes); } catch (DecoderFallbackException) { return false; }
        var lines = text.Split('\n');
        if (!text.EndsWith('\n') || lines.Length != 10 || lines[^1].Length != 0) return false;
        var expected = new[] { "schema", "source-commit", "release-version", "release-sequence", "published-at-utc", "configuration", "runtime", "sdk-version", "release-notes-sha256" };
        var values = new string[expected.Length];
        for (var index = 0; index < expected.Length; index++)
        {
            var prefix = expected[index] + "=";
            if (!lines[index].StartsWith(prefix, StringComparison.Ordinal)) return false;
            values[index] = lines[index][prefix.Length..];
        }
        if (values[0] != Schema || !IsCommit(values[1]) || !CanonicalReleaseVersion.IsValid(values[2]) || !TrySequence(values[3], out var sequence) ||
            !DateTimeOffset.TryParseExact(values[4], "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var published) ||
            published.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture) != values[4] ||
            values[5] != "Release" || values[6] != "win-x64" || !IsSdkVersion(values[7]) || !IsHash(values[8])) return false;
        descriptor = new(values[1], values[2], sequence, published, values[5], values[6], values[7], values[8]);
        return bytes.SequenceEqual(CreateCanonical(descriptor));
    }

    private static void Validate(BetaReleaseDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (!IsCommit(descriptor.SourceCommit) || !CanonicalReleaseVersion.IsValid(descriptor.ReleaseVersion) || descriptor.ReleaseSequence == 0 ||
            descriptor.PublishedAtUtc.Offset != TimeSpan.Zero || descriptor.PublishedAtUtc.Ticks % TimeSpan.TicksPerSecond != 0 ||
            descriptor.Configuration != "Release" || descriptor.Runtime != "win-x64" || !IsSdkVersion(descriptor.SdkVersion) || !IsHash(descriptor.ReleaseNotesSha256))
            throw new ArgumentException("Beta release descriptor is not canonical.", nameof(descriptor));
    }
    private static bool IsCommit(string? value) => value is { Length: 40 } && value.All(value => value is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool IsSdkVersion(string? value) => value is { Length: > 0 and <= 64 } && System.Text.RegularExpressions.Regex.IsMatch(value, "^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.]+)?$");
    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(value => value is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool TrySequence(string value, out ulong sequence) { sequence = 0; return value.Length > 0 && value[0] is >= '1' and <= '9' && value.All(value => value is >= '0' and <= '9') && ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out sequence); }
    private static bool HasBom(ReadOnlySpan<byte> bytes) => bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
    private static bool HasNonAscii(ReadOnlySpan<byte> bytes) { foreach (var value in bytes) if (value > 0x7f) return true; return false; }
}

public sealed record VerifiedServicePayload(string TrustedManifestRelease, string ReleaseMetadataDisplayVersion,
    ulong ReleaseSequence, string TrustedManifestSha256);
public interface IServicePayloadSignatureVerifier { VerifiedServicePayload Verify(string payloadDirectory); }
public sealed class ExistingServicePayloadSignatureVerifier : IServicePayloadSignatureVerifier
{
    public VerifiedServicePayload Verify(string payloadDirectory)
    {
        var result = ReleasePayloadVerifier.Verify(payloadDirectory);
        return new(result.TrustedManifestRelease, result.ReleaseMetadataDisplayVersion, result.ReleaseSequence, result.TrustedManifestSha256);
    }
}

public sealed record ReleaseArtifact(string RelativePath, string Sha256);
public sealed record BetaReleaseRecord(BetaReleaseDescriptor Descriptor, VerifiedServicePayload ServicePayload,
    IReadOnlyList<ReleaseArtifact> Artifacts);

public sealed class BetaReleaseLayoutValidator
{
    public const string ReleaseNotesFileName = "release-notes.md";
    public const string ServiceDirectoryName = "service";
    public const string DesktopDirectoryName = "desktop";
    public const string OfflineUpdateToolDirectoryName = "offline-update-tool";
    public const string RecordFileName = "beta-release-record-v1.txt";
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly HashSet<string> SecretExtensions = new(StringComparer.OrdinalIgnoreCase) { ".pk8", ".pem", ".key", ".pfx", ".p12", ".snk" };
    private readonly IServicePayloadSignatureVerifier _signatureVerifier;

    public BetaReleaseLayoutValidator(IServicePayloadSignatureVerifier? signatureVerifier = null) =>
        _signatureVerifier = signatureVerifier ?? new ExistingServicePayloadSignatureVerifier();

    public BetaReleaseRecord ValidateAndWriteRecord(string outputRoot)
    {
        var root = RequireDirectory(outputRoot);
        var recordPath = Path.Combine(root, RecordFileName);
        if (File.Exists(recordPath) || Directory.Exists(recordPath)) throw new IOException("Release record already exists.");
        var entries = Directory.EnumerateFileSystemEntries(root).ToArray();
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            BetaReleaseDescriptorCodec.FileName, ReleaseNotesFileName, ServiceDirectoryName, DesktopDirectoryName, OfflineUpdateToolDirectoryName
        };
        if (entries.Length != expected.Count || entries.Any(path => !expected.Remove(Path.GetFileName(path))))
            throw new IOException("Release layout root is not exact.");
        var descriptorPath = Path.Combine(root, BetaReleaseDescriptorCodec.FileName);
        if (!BetaReleaseDescriptorCodec.TryParse(ReadFile(descriptorPath), out var descriptor) || descriptor is null)
            throw new IOException("Release descriptor is unavailable or malformed.");
        var notesPath = Path.Combine(root, ReleaseNotesFileName);
        if (!string.Equals(HashFile(notesPath), descriptor.ReleaseNotesSha256, StringComparison.Ordinal))
            throw new IOException("Release notes hash does not match the descriptor.");
        var service = RequireDirectory(Path.Combine(root, ServiceDirectoryName));
        var desktop = RequireDirectory(Path.Combine(root, DesktopDirectoryName));
        var offlineUpdateTool = RequireDirectory(Path.Combine(root, OfflineUpdateToolDirectoryName));
        RequireRegularFile(Path.Combine(desktop, "Vantrel.Security.Desktop.exe"));
        RequireRegularFile(Path.Combine(offlineUpdateTool, "Vantrel.Security.OfflineUpdateTool.exe"));
        ValidateFlatExactServiceDirectory(service);
        VerifiedServicePayload servicePayload;
        try { servicePayload = _signatureVerifier.Verify(service); }
        catch (Exception) { throw new IOException("Service payload signature verification failed."); }
        if (!string.Equals(servicePayload.TrustedManifestRelease, descriptor.ReleaseVersion, StringComparison.Ordinal) ||
            !string.Equals(servicePayload.ReleaseMetadataDisplayVersion, descriptor.ReleaseVersion, StringComparison.Ordinal) ||
            servicePayload.ReleaseSequence != descriptor.ReleaseSequence || !IsHash(servicePayload.TrustedManifestSha256))
            throw new IOException("Service payload identity does not match the descriptor.");
        var artifacts = new List<ReleaseArtifact>
        {
            new(BetaReleaseDescriptorCodec.FileName, HashFile(descriptorPath)),
            new(ReleaseNotesFileName, descriptor.ReleaseNotesSha256)
        };
        artifacts.AddRange(CollectArtifacts(root, ServiceDirectoryName, requireFiles: true));
        artifacts.AddRange(CollectArtifacts(root, DesktopDirectoryName, requireFiles: true));
        artifacts.AddRange(CollectArtifacts(root, OfflineUpdateToolDirectoryName, requireFiles: true));
        var ordered = artifacts.OrderBy(item => item.RelativePath, StringComparer.Ordinal).ToArray();
        var releaseRecord = new BetaReleaseRecord(descriptor, servicePayload, ordered);
        WriteRecord(root, releaseRecord);
        return releaseRecord;
    }

    private static string RequireDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new IOException("Release layout root is unavailable.");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var current = new DirectoryInfo(full);
        for (; current is not null; current = current.Parent)
        {
            if (!current.Exists || (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Release layout root is unavailable or redirected.");
        }
        return full;
    }
    private static void ValidateFlatExactServiceDirectory(string service)
    {
        var expected = ReleasePayloadVerifier.ExactFileNames.ToHashSet(StringComparer.Ordinal);
        var entries = Directory.EnumerateFileSystemEntries(service).ToArray();
        if (entries.Length != expected.Count || entries.Any(path => !File.Exists(path) || IsReparse(path) || IsSecret(path) || !expected.Remove(Path.GetFileName(path))))
            throw new IOException("Service payload is not exact.");
    }
    private static void RequireRegularFile(string path)
    {
        if (!File.Exists(path) || IsReparse(path) || IsSecret(path)) throw new IOException("Required release artifact is unavailable.");
    }
    private static IEnumerable<ReleaseArtifact> CollectArtifacts(string root, string directoryName, bool requireFiles)
    {
        var directory = RequireDirectory(Path.Combine(root, directoryName));
        var files = new List<string>(); var pending = new Stack<string>(); pending.Push(directory);
        while (pending.Count != 0)
        {
            var current = pending.Pop();
            foreach (var entry in Directory.EnumerateFileSystemEntries(current))
            {
                if (IsReparse(entry)) throw new IOException("Release artifact is redirected.");
                if (Directory.Exists(entry)) { pending.Push(entry); continue; }
                if (!File.Exists(entry) || IsSecret(entry)) throw new IOException("Release artifact is unsafe.");
                files.Add(entry);
            }
        }
        if (requireFiles && files.Count == 0) throw new IOException("Release artifact directory is empty.");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files.OrderBy(path => path, StringComparer.Ordinal))
        {
            var relative = directoryName + "/" + Path.GetRelativePath(directory, file).Replace('\\', '/');
            if (relative.Contains("..", StringComparison.Ordinal) || !seen.Add(relative)) throw new IOException("Release artifact identity is invalid.");
            yield return new ReleaseArtifact(relative, HashFile(file));
        }
    }
    private static bool IsSecret(string path) => SecretExtensions.Contains(Path.GetExtension(path));
    private static bool IsReparse(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
    private static byte[] ReadFile(string path)
    {
        if (!File.Exists(path) || IsReparse(path) || IsSecret(path)) throw new IOException("Release artifact is unsafe.");
        return File.ReadAllBytes(path);
    }
    private static string HashFile(string path)
    {
        var before = new FileInfo(path);
        if (!before.Exists || IsReparse(path) || IsSecret(path)) throw new IOException("Release artifact is unsafe.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        var after = new FileInfo(path);
        if (!after.Exists || IsReparse(path) || before.Length != after.Length || before.LastWriteTimeUtc != after.LastWriteTimeUtc)
            throw new IOException("Release artifact changed while hashing.");
        return hash;
    }
    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(value => value is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static void WriteRecord(string root, BetaReleaseRecord record)
    {
        var d = record.Descriptor; var s = record.ServicePayload;
        var text = new StringBuilder()
            .Append("schema=vantrel-beta-release-record-v1\n")
            .Append("source-commit=").Append(d.SourceCommit).Append('\n')
            .Append("release-version=").Append(d.ReleaseVersion).Append('\n')
            .Append("release-sequence=").Append(d.ReleaseSequence.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("published-at-utc=").Append(d.PublishedAtUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)).Append('\n')
            .Append("configuration=").Append(d.Configuration).Append('\n')
            .Append("runtime=").Append(d.Runtime).Append('\n')
            .Append("sdk-version=").Append(d.SdkVersion).Append('\n')
            .Append("release-notes-sha256=").Append(d.ReleaseNotesSha256).Append('\n')
            .Append("service-payload-validation=valid\n")
            .Append("trusted-manifest-signature=valid\n")
            .Append("release-metadata-signature=valid\n")
            .Append("manifest-metadata-binding=valid\n")
            .Append("trusted-manifest-release=").Append(s.TrustedManifestRelease).Append('\n')
            .Append("release-metadata-display-version=").Append(s.ReleaseMetadataDisplayVersion).Append('\n')
            .Append("trusted-manifest-sha256=").Append(s.TrustedManifestSha256).Append('\n')
            .Append("artifact-count=").Append(record.Artifacts.Count.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (var artifact in record.Artifacts) text.Append("artifact=").Append(artifact.RelativePath).Append('|').Append(artifact.Sha256).Append('\n');
        var finalPath = Path.Combine(root, RecordFileName); var temporary = finalPath + ".tmp";
        try { File.WriteAllBytes(temporary, Utf8.GetBytes(text.ToString())); File.Move(temporary, finalPath); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
