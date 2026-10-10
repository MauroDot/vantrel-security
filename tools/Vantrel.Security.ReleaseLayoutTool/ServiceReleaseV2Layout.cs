using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>
/// Isolated build output for a v2 Service payload. The manifest payload is unsigned; this
/// class neither signs it nor writes a release record or a production release layout.
/// </summary>
public sealed class ServiceReleaseV2Projection
{
    private readonly byte[] _canonicalManifestPayload;

    internal ServiceReleaseV2Projection(IReadOnlyList<TrustedManifestV2File> files,
        IReadOnlyList<ServicePublishExcludedBuildArtifact> excludedBuildArtifacts,
        byte[] canonicalManifestPayload)
    {
        Files = new ReadOnlyCollection<TrustedManifestV2File>(files.ToArray());
        ExcludedBuildArtifacts = new ReadOnlyCollection<ServicePublishExcludedBuildArtifact>(
            excludedBuildArtifacts.ToArray());
        _canonicalManifestPayload = canonicalManifestPayload.ToArray();
    }

    public IReadOnlyList<TrustedManifestV2File> Files { get; }
    public IReadOnlyList<ServicePublishExcludedBuildArtifact> ExcludedBuildArtifacts { get; }
    public byte[] CanonicalManifestPayload => _canonicalManifestPayload.ToArray();
}

/// <summary>
/// Build-only, opt-in v2 projection. It does not replace ServicePayloadProjector or connect
/// to Prepare, Record, ManifestTool, installation, or offline updates.
/// </summary>
public sealed class ServiceReleaseV2Projector
{
    public ServiceReleaseV2Projection Project(string sourcePublishRoot, string destinationServiceRoot,
        string approvedSourceLockSha256, string releaseVersion, ulong releaseSequence)
    {
        // The SDK publish validator, not .deps.json alone or a caller-supplied file list,
        // decides which files are deployable. Its three explicitly named PDBs are part of
        // the current approved inventory when the SDK publishes them.
        var source = RequireSafeExistingDirectory(sourcePublishRoot);
        var validation = ServicePublishDependencyValidator.ValidateSdkPublish(source, approvedSourceLockSha256);
        var approved = validation.DeployableFiles;
        var canonical = TrustedManifestV2Codec.CreateCanonicalPayload(releaseVersion, releaseSequence, approved);

        var destination = RequireNewDestination(destinationServiceRoot);
        if (IsSameOrBelow(destination, source) || IsSameOrBelow(source, destination))
            throw new IOException("V2 Service destination overlaps the SDK publish.");
        var parent = Path.GetDirectoryName(destination)!;
        var stage = Path.Combine(parent, "." + Path.GetFileName(destination) + ".v2-" + Guid.NewGuid().ToString("N"));
        CreateNewStageDirectory(stage);
        try
        {
            RequireSafeExistingDirectory(stage);
            foreach (var file in approved)
            {
                var target = CreateStagePath(stage, file.Path);
                ServicePublishFileSnapshot.CopyValidatedFile(source, file, target);
            }

            // Revalidate source after all copy handles close, then prove the complete staged
            // directory has exactly the same names and hashes, with no lock residue.
            var afterSource = ServicePublishDependencyValidator.ValidateSdkPublish(source, approvedSourceLockSha256);
            if (!approved.SequenceEqual(afterSource.DeployableFiles) ||
                !validation.ExcludedBuildArtifacts.SequenceEqual(afterSource.ExcludedBuildArtifacts))
                throw new IOException("SDK Service publish changed during v2 projection.");
            _ = ServicePublishDependencyValidator.Validate(stage, approved);

            RequireSafeExistingDirectory(parent);
            if (Path.Exists(destination)) throw new IOException("V2 Service destination already exists.");
            Directory.Move(stage, destination);

            // The move is the handoff point. Re-enumerate the final physical directory rather
            // than trusting the pre-move snapshot or the path used for the move.
            var finalFiles = ServicePublishDependencyValidator.Validate(destination, approved);
            var finalCanonical = TrustedManifestV2Codec.CreateCanonicalPayload(
                releaseVersion, releaseSequence, finalFiles);
            if (!canonical.AsSpan().SequenceEqual(finalCanonical))
                throw new IOException("V2 Service manifest inventory changed during projection.");
            return new ServiceReleaseV2Projection(finalFiles, validation.ExcludedBuildArtifacts, finalCanonical);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // Leave a failed stage or final directory for controlled inspection. Never
            // recursively remove a directory another process could have redirected.
            throw new IOException("V2 Service projection did not complete.");
        }
    }

    private static string CreateStagePath(string stage, string relative)
    {
        var segments = relative.Split('/');
        var directory = stage;
        for (var i = 0; i < segments.Length - 1; i++)
        {
            directory = Path.Combine(directory, segments[i]);
            if (!Directory.Exists(directory)) Directory.CreateDirectory(directory);
            RequireSafeExistingDirectory(directory);
        }
        var target = Path.Combine(directory, segments[^1]);
        if (!IsSameOrBelow(target, stage) || Path.Exists(target))
            throw new IOException("V2 Service destination is unsafe.");
        return target;
    }

    internal static void CreateNewStageDirectory(string stage)
    {
        // CreateDirectoryW fails if the GUID-named directory already exists. The managed
        // CreateDirectory helper would silently adopt a directory inserted after a precheck.
        var parent = Path.GetDirectoryName(stage);
        if (string.IsNullOrEmpty(parent)) throw new IOException("V2 Service staging directory is unavailable.");
        RequireSafeExistingDirectory(parent);
        if (!CreateDirectory(stage, IntPtr.Zero))
            throw new IOException("V2 Service staging directory is unavailable.");
        RequireSafeExistingDirectory(stage);
    }

    private static string RequireNewDestination(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase) ||
            path.Length < 4 || path[1] != ':' || path[2] != '\\' ||
            new DriveInfo(path[..3]).DriveType != DriveType.Fixed ||
            Path.Exists(path))
            throw new IOException("V2 Service destination is unavailable.");
        var parent = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(parent)) throw new IOException("V2 Service destination is unavailable.");
        RequireSafeExistingDirectory(parent);
        return path;
    }

    private static string RequireSafeExistingDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase) ||
            path.Length < 3 || path[1] != ':' || path[2] != '\\' ||
            new DriveInfo(path[..3]).DriveType != DriveType.Fixed)
            throw new IOException("V2 Service directory is unavailable.");
        for (var current = new DirectoryInfo(path); current is not null; current = current.Parent)
            if (!current.Exists || (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("V2 Service directory is unavailable or redirected.");
        return path;
    }

    private static bool IsSameOrBelow(string candidate, string root) =>
        candidate.Equals(root, StringComparison.OrdinalIgnoreCase) ||
        candidate.StartsWith(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string path, IntPtr securityAttributes);
}

/// <summary>
/// Independent v2 directory check. A valid signature authenticates the inventory, but this
/// check does not bind it to a clean immutable source checkout or authorize a production release.
/// </summary>
public sealed class ServiceReleaseV2Verifier
{
    public IReadOnlyList<TrustedManifestV2File> Verify(string serviceRoot, byte[] signedManifestBytes,
        string expectedReleaseVersion, ulong expectedReleaseSequence) =>
        VerifyCore(serviceRoot, signedManifestBytes, expectedReleaseVersion, expectedReleaseSequence,
            OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo);

    // Test assemblies may supply only synthetic public keys through the existing friend-assembly
    // seam. The public entry point always uses the source-owned production manifest root.
    internal IReadOnlyList<TrustedManifestV2File> VerifyWithTestKey(string serviceRoot,
        byte[] signedManifestBytes, string expectedReleaseVersion, ulong expectedReleaseSequence,
        byte[] testPublicSpki) =>
        VerifyCore(serviceRoot, signedManifestBytes, expectedReleaseVersion, expectedReleaseSequence,
            testPublicSpki);

    private static IReadOnlyList<TrustedManifestV2File> VerifyCore(string serviceRoot,
        byte[] signedManifestBytes, string expectedReleaseVersion, ulong expectedReleaseSequence,
        byte[] publicSpki)
    {
        if (signedManifestBytes is null || publicSpki is null ||
            !TrustedManifestV2Codec.TryParse(signedManifestBytes, out var manifest, out _) ||
            manifest is null || manifest.Release != expectedReleaseVersion ||
            manifest.ReleaseSequence != expectedReleaseSequence ||
            manifest.Architecture != TrustedManifestV2Codec.Architecture ||
            manifest.Deployment != TrustedManifestV2Codec.Deployment ||
            !TrustedManifestV2Codec.Verify(manifest, publicSpki))
            throw new IOException("V2 Service manifest verification failed.");

        // The signed inventory is the authorization set. The signed .deps.json is additional
        // dependency-closure evidence; it is never allowed to add a file to that set.
        try { return ServicePublishDependencyValidator.Validate(serviceRoot, manifest.Files); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException)
        { throw new IOException("V2 Service layout verification failed."); }
    }
}
