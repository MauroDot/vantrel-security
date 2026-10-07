using System.Security.Cryptography;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Vantrel.Security.ManifestTool;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>Strict, non-secret metadata for the externally supplied Artifact Signing dlib.</summary>
public sealed record AzureArtifactSigningMetadata(string Endpoint, string CodeSigningAccountName,
    string CertificateProfileName, string? CorrelationId, bool InteractiveBrowserOnly = false);

public static class AzureArtifactSigningMetadataCodec
{
    public const string LocalMetadataFileName = "AzureArtifactSigning.metadata.local.json";
    public const string TemplateFileName = "AzureArtifactSigning.metadata.template.json";
    public const string Endpoint = "https://cus.codesigning.azure.net";
    public const string AccountName = "vantrel-signing";
    public const string CertificateProfileName = "vantrelpublic";
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly string[] RequiredNames = ["Endpoint", "CodeSigningAccountName", "CertificateProfileName"];
    private static readonly string[] InteractiveBrowserOnlyExcludedCredentials =
    [
        "EnvironmentCredential", "ManagedIdentityCredential", "WorkloadIdentityCredential", "SharedTokenCacheCredential",
        "VisualStudioCredential", "VisualStudioCodeCredential", "AzureCliCredential", "AzurePowerShellCredential",
        "AzureDeveloperCliCredential"
    ];

    public static byte[] CreateCanonical(AzureArtifactSigningMetadata metadata)
    {
        Validate(metadata);
        var correlation = metadata.CorrelationId is null ? string.Empty : $",\"CorrelationId\":\"{metadata.CorrelationId}\"";
        var credentials = metadata.InteractiveBrowserOnly
            ? $",\"ExcludeCredentials\":[{string.Join(',', InteractiveBrowserOnlyExcludedCredentials.Select(value => $"\"{value}\""))}]" : string.Empty;
        return Utf8.GetBytes($"{{\"Endpoint\":\"{Endpoint}\",\"CodeSigningAccountName\":\"{AccountName}\",\"CertificateProfileName\":\"{CertificateProfileName}\"{correlation}{credentials}}}\n");
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out AzureArtifactSigningMetadata? metadata)
    {
        metadata = null;
        if (bytes.Length is 0 or > 1024 || HasBom(bytes) || HasNonAscii(bytes) || bytes.IndexOf((byte)'\r') >= 0) return false;
        try
        {
            using var document = JsonDocument.Parse(bytes.ToArray());
            if (document.RootElement.ValueKind != JsonValueKind.Object) return false;
            var properties = document.RootElement.EnumerateObject().ToArray();
            if (properties.Length is < 3 or > 5) return false;
            var hasCorrelation = properties.Any(item => item.NameEquals("CorrelationId"));
            var hasCredentials = properties.Any(item => item.NameEquals("ExcludeCredentials"));
            var expected = RequiredNames
                .Concat(hasCorrelation ? ["CorrelationId"] : [])
                .Concat(hasCredentials ? ["ExcludeCredentials"] : []).ToArray();
            if (!properties.Select(item => item.Name).SequenceEqual(expected, StringComparer.Ordinal)) return false;
            if (properties.Take(3).Any(item => item.Value.ValueKind != JsonValueKind.String)) return false;
            var correlation = hasCorrelation ? properties.Single(item => item.NameEquals("CorrelationId")).Value.GetString() : null;
            if (hasCorrelation && correlation is null) return false;
            var browserOnly = hasCredentials && IsInteractiveBrowserOnly(properties.Single(item => item.NameEquals("ExcludeCredentials")).Value);
            if (hasCredentials && !browserOnly) return false;
            var candidate = new AzureArtifactSigningMetadata(properties[0].Value.GetString()!, properties[1].Value.GetString()!, properties[2].Value.GetString()!, correlation, browserOnly);
            Validate(candidate);
            if (!bytes.SequenceEqual(CreateCanonical(candidate))) return false;
            metadata = candidate;
            return true;
        }
        catch (JsonException) { return false; }
        catch (ArgumentException) { return false; }
    }

    public static AzureArtifactSigningMetadata ReadValidatedLocalFile(string metadataPath)
    {
        var bytes = ReadSafeLocalFile(metadataPath, "Signing metadata is unavailable.");
        if (!TryParse(bytes, out var metadata) || metadata is null) throw new IOException("Signing metadata is unavailable.");
        return metadata;
    }

    internal static byte[] ReadSafeLocalFile(string path, string failure)
    {
        try
        {
            var full = Path.GetFullPath(path);
            ValidateSafeAncestors(full, failure);
            if (!File.Exists(full) || Directory.Exists(full) || IsReparse(full)) throw new IOException(failure);
            return File.ReadAllBytes(full);
        }
        catch (IOException) { throw new IOException(failure); }
        catch (UnauthorizedAccessException) { throw new IOException(failure); }
        catch (ArgumentException) { throw new IOException(failure); }
        catch (NotSupportedException) { throw new IOException(failure); }
    }

    internal static void ValidateSafeAncestors(string path, string failure)
    {
        for (var current = new FileInfo(path).Directory; current is not null; current = current.Parent)
            if (!current.Exists || IsReparse(current.FullName)) throw new IOException(failure);
    }

    private static void Validate(AzureArtifactSigningMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (!string.Equals(metadata.Endpoint, Endpoint, StringComparison.Ordinal) ||
            !string.Equals(metadata.CodeSigningAccountName, AccountName, StringComparison.Ordinal) ||
            !string.Equals(metadata.CertificateProfileName, CertificateProfileName, StringComparison.Ordinal) ||
            (metadata.CorrelationId is not null && !Regex.IsMatch(metadata.CorrelationId, "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant)))
            throw new ArgumentException("Signing metadata is unavailable.", nameof(metadata));
    }

    private static bool IsInteractiveBrowserOnly(JsonElement value) => value.ValueKind == JsonValueKind.Array &&
        value.EnumerateArray().All(item => item.ValueKind == JsonValueKind.String) &&
        value.EnumerateArray().Select(item => item.GetString()).SequenceEqual(InteractiveBrowserOnlyExcludedCredentials, StringComparer.Ordinal);

    private static bool HasBom(ReadOnlySpan<byte> bytes) => bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
    private static bool HasNonAscii(ReadOnlySpan<byte> bytes) { foreach (var value in bytes) if (value > 0x7f) return true; return false; }
    private static bool IsReparse(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
}

public sealed record AzureArtifactSigningToolPaths(string SignToolPath, string DlibPath, string MetadataPath);

/// <summary>Injected only; Task 066 intentionally supplies no process implementation.</summary>
public interface IAzureArtifactSigningProcessRunner
{
    int Run(string executablePath, IReadOnlyList<string> arguments);
}

/// <summary>The sole production process boundary for explicit SignTool invocation.</summary>
internal sealed class SignToolProcessRunner : IAzureArtifactSigningProcessRunner
{
    public int Run(string executablePath, IReadOnlyList<string> arguments)
    {
        var start = new ProcessStartInfo(executablePath) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new IOException("Azure Artifact Signing preflight failed.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        Task.WaitAll(output, error);
        return process.ExitCode;
    }
}

public sealed class AzureArtifactSigningOrchestrator
{
    public const string TimestampEndpoint = "http://timestamp.acs.microsoft.com";
    private const string Failure = "Azure Artifact Signing preflight failed.";
    private readonly IAzureArtifactSigningProcessRunner _runner;
    private readonly IReleaseAuthenticodeVerification _authenticode;

    public AzureArtifactSigningOrchestrator(IAzureArtifactSigningProcessRunner runner, IReleaseAuthenticodeVerification? authenticode = null)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _authenticode = authenticode ?? new ReleaseAuthenticodeVerifier();
    }

    public void SignPreparedLayout(string releaseLayoutRoot, AzureArtifactSigningToolPaths tools)
    {
        ArgumentNullException.ThrowIfNull(tools);
        var root = ValidatePreparedLayout(releaseLayoutRoot);
        _ = AzureArtifactSigningMetadataCodec.ReadValidatedLocalFile(tools.MetadataPath);
        var signTool = ValidateToolFile(tools.SignToolPath);
        var dlib = ValidateToolFile(tools.DlibPath);
        var metadata = Path.GetFullPath(tools.MetadataPath);

        var artifacts = ReleaseSigningContract.VantrelOwnedPeArtifacts
            .Select(artifact => new PreparedArtifact(artifact.RelativePath, ResolveArtifact(root, artifact.RelativePath)))
            .Select(artifact => artifact with { Sha256 = HashSafeFile(artifact.Path) })
            .ToArray();
        if (artifacts.Length != ReleaseSigningContract.VantrelOwnedPeArtifacts.Count) throw new IOException(Failure);

        foreach (var artifact in artifacts)
        {
            if (!string.Equals(HashSafeFile(artifact.Path), artifact.Sha256, StringComparison.Ordinal)) throw new IOException(Failure);
            var arguments = new[] { "sign", "/v", "/fd", "SHA256", "/tr", TimestampEndpoint, "/td", "SHA256", "/dlib", dlib, "/dmdf", metadata, artifact.Path };
            int exitCode;
            try { exitCode = _runner.Run(signTool, Array.AsReadOnly(arguments)); }
            catch { throw new IOException(Failure); }
            if (exitCode != 0) throw new IOException(Failure);
        }
        foreach (var artifact in artifacts)
            if (_authenticode.Verify(artifact.RelativePath, artifact.Path, "vantrel-production").Category != AuthenticodeVerificationCategory.Valid)
                throw new IOException(Failure);
    }

    private static string ValidatePreparedLayout(string releaseLayoutRoot)
    {
        try
        {
            var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(releaseLayoutRoot));
            AzureArtifactSigningMetadataCodec.ValidateSafeAncestors(Path.Combine(root, "layout-sentinel"), Failure);
            if (!Directory.Exists(root) || IsReparse(root)) throw new IOException(Failure);
            var expectedRoots = new HashSet<string>(StringComparer.Ordinal)
            {
                BetaReleaseDescriptorCodec.FileName, BetaReleaseLayoutValidator.ReleaseNotesFileName,
                BetaReleaseLayoutValidator.ServiceDirectoryName, BetaReleaseLayoutValidator.DesktopDirectoryName,
                BetaReleaseLayoutValidator.OfflineUpdateToolDirectoryName
            };
            var entries = Directory.EnumerateFileSystemEntries(root).ToArray();
            if (entries.Length != expectedRoots.Count || entries.Any(entry => IsReparse(entry) || !expectedRoots.Remove(Path.GetFileName(entry)))) throw new IOException(Failure);
            if (File.Exists(Path.Combine(root, BetaReleaseLayoutValidator.RecordFileName))) throw new IOException(Failure);
            var descriptorPath = Path.Combine(root, BetaReleaseDescriptorCodec.FileName);
            var descriptorBytes = AzureArtifactSigningMetadataCodec.ReadSafeLocalFile(descriptorPath, Failure);
            if (!BetaReleaseDescriptorCodec.TryParse(descriptorBytes, out var descriptor) || descriptor is null) throw new IOException(Failure);
            var notes = Path.Combine(root, BetaReleaseLayoutValidator.ReleaseNotesFileName);
            if (!string.Equals(HashSafeFile(notes), descriptor.ReleaseNotesSha256, StringComparison.Ordinal)) throw new IOException(Failure);
            ValidateExactServicePayload(Path.Combine(root, BetaReleaseLayoutValidator.ServiceDirectoryName));
            RequireDirectory(Path.Combine(root, BetaReleaseLayoutValidator.DesktopDirectoryName));
            RequireDirectory(Path.Combine(root, BetaReleaseLayoutValidator.OfflineUpdateToolDirectoryName));
            return root;
        }
        catch (IOException) { throw new IOException(Failure); }
        catch (UnauthorizedAccessException) { throw new IOException(Failure); }
        catch (ArgumentException) { throw new IOException(Failure); }
        catch (NotSupportedException) { throw new IOException(Failure); }
    }

    private static void ValidateExactServicePayload(string serviceDirectory)
    {
        RequireDirectory(serviceDirectory);
        var expected = ReleasePayloadVerifier.ServiceComponentFileNames.ToHashSet(StringComparer.Ordinal);
        var entries = Directory.EnumerateFileSystemEntries(serviceDirectory).ToArray();
        if (entries.Length != expected.Count || entries.Any(entry => IsReparse(entry) || Directory.Exists(entry) || !File.Exists(entry) || !expected.Remove(Path.GetFileName(entry)))) throw new IOException(Failure);
    }

    private static string ResolveArtifact(string root, string relativePath)
    {
        var relative = relativePath.Replace('/', Path.DirectorySeparatorChar);
        var path = Path.GetFullPath(Path.Combine(root, relative));
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException(Failure);
        _ = AzureArtifactSigningMetadataCodec.ReadSafeLocalFile(path, Failure);
        return path;
    }

    private static string ValidateToolFile(string path)
    {
        _ = AzureArtifactSigningMetadataCodec.ReadSafeLocalFile(path, Failure);
        return Path.GetFullPath(path);
    }

    private static void RequireDirectory(string path)
    {
        AzureArtifactSigningMetadataCodec.ValidateSafeAncestors(Path.Combine(path, "directory-sentinel"), Failure);
        if (!Directory.Exists(path) || IsReparse(path)) throw new IOException(Failure);
    }

    private static string HashSafeFile(string path)
    {
        var bytes = AzureArtifactSigningMetadataCodec.ReadSafeLocalFile(path, Failure);
        return Convert.ToHexString(SHA256.HashData(bytes));
    }

    private static bool IsReparse(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
    private sealed record PreparedArtifact(string RelativePath, string Path, string Sha256 = "");
}
