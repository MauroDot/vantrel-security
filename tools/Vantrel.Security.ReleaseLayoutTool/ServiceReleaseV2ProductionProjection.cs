using System.Collections.ObjectModel;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>
/// Unsigned, dependency-complete v2 Service projection. Symbols are measured separately and
/// never become entries in the deployable Service manifest. No production release is approved
/// merely by receiving this result; a later gate must rebind every final artifact.
/// </summary>
public sealed class ServiceReleaseV2ProductionProjection
{
    private readonly byte[] _canonicalManifestPayload;

    internal ServiceReleaseV2ProductionProjection(IReadOnlyList<TrustedManifestV2File> serviceFiles,
        IReadOnlyList<TrustedManifestV2File> diagnosticSymbols,
        IReadOnlyList<ServicePublishExcludedBuildArtifact> excludedBuildArtifacts,
        byte[] canonicalManifestPayload)
    {
        ServiceFiles = new ReadOnlyCollection<TrustedManifestV2File>(serviceFiles.ToArray());
        DiagnosticSymbols = new ReadOnlyCollection<TrustedManifestV2File>(diagnosticSymbols.ToArray());
        ExcludedBuildArtifacts = new ReadOnlyCollection<ServicePublishExcludedBuildArtifact>(
            excludedBuildArtifacts.ToArray());
        _canonicalManifestPayload = canonicalManifestPayload.ToArray();
    }

    public IReadOnlyList<TrustedManifestV2File> ServiceFiles { get; }
    public IReadOnlyList<TrustedManifestV2File> DiagnosticSymbols { get; }
    public IReadOnlyList<ServicePublishExcludedBuildArtifact> ExcludedBuildArtifacts { get; }
    public byte[] CanonicalManifestPayload => _canonicalManifestPayload.ToArray();
}

/// <summary>
/// Opt-in v2 Service-only projection for a clean, locked SDK publish. It creates exactly
/// service/ and diagnostic-symbols/ under one new protected destination root. It does not
/// sign a manifest, create a release record, or change the v1 projector or updater.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2ProductionProjector
{
    public const string ServiceDirectoryName = "service";
    public const string DiagnosticDirectoryName = "diagnostic-symbols";
    private const string Invalid = "V2 Service projection did not complete.";

    private static readonly string[] ApprovedSymbols =
    [
        "Vantrel.Security.Core.pdb",
        "Vantrel.Security.Infrastructure.pdb",
        "Vantrel.Security.Service.pdb"
    ];

    public ServiceReleaseV2ProductionProjection Project(string sourcePublishRoot,
        string destinationRoot, string approvedSourceLockSha256,
        string releaseVersion, ulong releaseSequence)
    {
        try
        {
            var destination = RequireNewDestination(destinationRoot);
            if (Overlaps(destination, sourcePublishRoot)) throw new IOException(Invalid);
            var validated = ServicePublishDependencyValidator.ValidateSdkPublish(
                sourcePublishRoot, approvedSourceLockSha256);
            var symbols = validated.DeployableFiles.Where(file =>
                file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)).ToArray();
            var service = validated.DeployableFiles.Where(file =>
                !file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)).ToArray();
            RequireExactSymbols(symbols);
            var canonical = TrustedManifestV2Codec.CreateCanonicalPayload(
                releaseVersion, releaseSequence, service);

            var parent = Path.GetDirectoryName(destination)!;
            var stage = Path.Combine(parent, "." + Path.GetFileName(destination) +
                ".v2-" + Guid.NewGuid().ToString("N"));
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(stage);
            var stagedService = Path.Combine(stage, ServiceDirectoryName);
            var stagedDiagnostics = Path.Combine(stage, DiagnosticDirectoryName);
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(stagedService);
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(stagedDiagnostics);
            foreach (var file in service)
            {
                var target = CreateProtectedChildPath(stagedService, file.Path);
                ServicePublishFileSnapshot.CopyValidatedFile(sourcePublishRoot, file, target);
            }
            foreach (var file in symbols)
                ServicePublishFileSnapshot.CopyValidatedFile(sourcePublishRoot, file,
                    Path.Combine(stagedDiagnostics, file.Path));

            // The source is remeasured after all per-file copy handles close. The stage is
            // checked as a complete physical inventory, not merely against .deps.json.
            var sourceAfter = ServicePublishDependencyValidator.ValidateSdkPublish(
                sourcePublishRoot, approvedSourceLockSha256);
            if (!validated.DeployableFiles.SequenceEqual(sourceAfter.DeployableFiles) ||
                !validated.ExcludedBuildArtifacts.SequenceEqual(sourceAfter.ExcludedBuildArtifacts))
                throw new IOException(Invalid);
            _ = ServicePublishDependencyValidator.Validate(stagedService, service);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedTree(stagedService, service);
            _ = ValidateDiagnosticSymbols(stagedDiagnostics, symbols);
            RequireExactProjectionRoot(stage);

            // Move both inventories as one directory. The protected parent is a prerequisite;
            // a retained parent handle used during creation is not a permanent rename lock.
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(parent);
            if (Path.Exists(destination)) throw new IOException(Invalid);
            Directory.Move(stage, destination);
            RequireExactProjectionRoot(destination);
            var finalService = Path.Combine(destination, ServiceDirectoryName);
            var finalDiagnostics = Path.Combine(destination, DiagnosticDirectoryName);
            var measuredService = ServicePublishDependencyValidator.Validate(finalService, service);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedTree(finalService, measuredService);
            var measuredSymbols = ValidateDiagnosticSymbols(finalDiagnostics, symbols);
            var finalCanonical = TrustedManifestV2Codec.CreateCanonicalPayload(
                releaseVersion, releaseSequence, measuredService);
            if (!canonical.AsSpan().SequenceEqual(finalCanonical)) throw new IOException(Invalid);

            return new ServiceReleaseV2ProductionProjection(measuredService, measuredSymbols,
                validated.ExcludedBuildArtifacts, finalCanonical);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or InvalidDataException or CryptographicException or NotSupportedException)
        {
            // Leave failed output for inspection. A later caller must never infer completion
            // from directory presence and must not authorize release without rebinding bytes.
            throw new IOException(Invalid);
        }
    }

    internal static IReadOnlyList<TrustedManifestV2File> ValidateDiagnosticSymbols(
        string diagnosticsRoot, IReadOnlyList<TrustedManifestV2File> expected)
    {
        try
        {
            RequireExactSymbols(expected);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(diagnosticsRoot);
            var names = Directory.EnumerateFileSystemEntries(diagnosticsRoot)
                .Select(Path.GetFileName).OrderBy(name => name, StringComparer.Ordinal).ToArray();
            if (!names.SequenceEqual(ApprovedSymbols, StringComparer.Ordinal))
                throw new IOException(Invalid);
            var handles = new List<FileStream>(expected.Count);
            try
            {
                foreach (var file in expected)
                {
                    var path = Path.Combine(diagnosticsRoot, file.Path);
                    ServiceReleaseV2FileSystemSecurity.RequireProtectedFile(path);
                    handles.Add(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
                }
                for (var index = 0; index < expected.Count; index++)
                {
                    var stream = handles[index];
                    if (stream.Length < 0 || stream.Length > 1024L * 1024 * 1024 ||
                        Convert.ToHexString(SHA256.HashData(stream)) != expected[index].Sha256)
                        throw new IOException(Invalid);
                    stream.Position = 0;
                    ServiceReleaseV2FileSystemSecurity.RequireNoNamedStreams(stream.SafeFileHandle);
                }
                var after = Directory.EnumerateFileSystemEntries(diagnosticsRoot)
                    .Select(Path.GetFileName).OrderBy(name => name, StringComparer.Ordinal).ToArray();
                if (!after.SequenceEqual(names, StringComparer.Ordinal)) throw new IOException(Invalid);
                for (var index = 0; index < expected.Count; index++)
                {
                    handles[index].Position = 0;
                    if (Convert.ToHexString(SHA256.HashData(handles[index])) != expected[index].Sha256)
                        throw new IOException(Invalid);
                    ServiceReleaseV2FileSystemSecurity.RequireProtectedFile(
                        Path.Combine(diagnosticsRoot, expected[index].Path));
                }
            }
            finally { foreach (var handle in handles) handle.Dispose(); }
            return new ReadOnlyCollection<TrustedManifestV2File>(expected.ToArray());
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or InvalidDataException or CryptographicException or NotSupportedException)
        { throw new IOException("V2 diagnostic-symbol inventory is invalid."); }
    }

    private static void RequireExactSymbols(IReadOnlyList<TrustedManifestV2File> symbols)
    {
        if (symbols.Count != ApprovedSymbols.Length) throw new IOException(Invalid);
        for (var index = 0; index < ApprovedSymbols.Length; index++)
            if (symbols[index].Path != ApprovedSymbols[index] ||
                symbols[index].Sha256 is not { Length: 64 } hash ||
                hash.Any(c => !char.IsAsciiDigit(c) && c is not (>= 'A' and <= 'F')))
                throw new IOException(Invalid);
    }

    private static string CreateProtectedChildPath(string root, string relative)
    {
        var parts = relative.Split('/');
        var parent = root;
        for (var index = 0; index < parts.Length - 1; index++)
        {
            parent = Path.Combine(parent, parts[index]);
            if (!Directory.Exists(parent))
                ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(parent);
            else ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(parent);
        }
        return Path.Combine(parent, parts[^1]);
    }

    private static void RequireExactProjectionRoot(string root)
    {
        ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(root);
        var entries = Directory.EnumerateFileSystemEntries(root)
            .Select(Path.GetFileName).OrderBy(name => name, StringComparer.Ordinal).ToArray();
        if (!entries.SequenceEqual([DiagnosticDirectoryName, ServiceDirectoryName], StringComparer.Ordinal))
            throw new IOException(Invalid);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(
            Path.Combine(root, ServiceDirectoryName));
        ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(
            Path.Combine(root, DiagnosticDirectoryName));
    }

    private static string RequireNewDestination(string destination)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(destination) ||
            !Path.IsPathFullyQualified(destination) || Path.GetFullPath(destination) != destination ||
            destination.Length < 4 || destination[1] != ':' || destination[2] != '\\' ||
            new DriveInfo(destination[..3]).DriveType != DriveType.Fixed ||
            Path.Exists(destination))
            throw new IOException(Invalid);
        var parent = Path.GetDirectoryName(destination);
        if (parent is null) throw new IOException(Invalid);
        ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(parent);
        return destination;
    }

    private static bool Overlaps(string destination, string source) =>
        destination.Equals(source, StringComparison.OrdinalIgnoreCase) ||
        destination.StartsWith(Path.TrimEndingDirectorySeparator(source) + "\\",
            StringComparison.OrdinalIgnoreCase) ||
        source.StartsWith(destination + "\\", StringComparison.OrdinalIgnoreCase);
}
