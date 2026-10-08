using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.ManifestTool;

/// <summary>Build-time public-key verifier for the fixed nine-file service release payload.</summary>
public sealed record VerifiedServicePayload(string TrustedManifestRelease, string ReleaseMetadataDisplayVersion,
    ulong ReleaseSequence, string TrustedManifestSha256);

public sealed record ServicePayloadComponent(TrustedManifestComponent Component, string FileName);

public static class ReleasePayloadVerifier
{
    public static IReadOnlyList<ServicePayloadComponent> ServiceComponents { get; } = Array.AsReadOnly(new ServicePayloadComponent[]
    {
        new(TrustedManifestComponent.ServiceExe, "Vantrel.Security.Service.exe"),
        new(TrustedManifestComponent.ServiceAssembly, "Vantrel.Security.Service.dll"),
        new(TrustedManifestComponent.InfrastructureAssembly, "Vantrel.Security.Infrastructure.dll"),
        new(TrustedManifestComponent.CoreAssembly, "Vantrel.Security.Core.dll"),
        new(TrustedManifestComponent.Deps, "Vantrel.Security.Service.deps.json"),
        new(TrustedManifestComponent.RuntimeConfig, "Vantrel.Security.Service.runtimeconfig.json"),
        new(TrustedManifestComponent.EventLogResource, "System.Diagnostics.EventLog.Messages.dll")
    });

    public static VerifiedServicePayload Verify(string payloadDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadDirectory);
        var root = Path.GetFullPath(payloadDirectory);
        ValidateExactReleaseSet(root);
        var manifestBytes = File.ReadAllBytes(Path.Combine(root, "Vantrel.Security.TrustedManifest"));
        if (!TrustedManifestCodec.TryParse(manifestBytes, out var manifest, out _) || manifest is null ||
            !TrustedManifestCodec.Verify(manifest, OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo))
            throw new InvalidDataException("Trusted manifest verification failed.");
        var metadataBytes = File.ReadAllBytes(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"));
        if (!ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out _) || metadata is null ||
            !ReleaseMetadataCodec.Verify(metadata, OfflineReleasePublicKeys.ReleaseMetadataSubjectPublicKeyInfo))
            throw new InvalidDataException("Release metadata verification failed.");
        var manifestHash = Convert.ToHexString(SHA256.HashData(manifestBytes));
        if (!string.Equals(metadata.ManifestSha256, manifestHash, StringComparison.Ordinal))
            throw new InvalidDataException("Release metadata manifest binding failed.");
        foreach (var component in ServiceComponents)
        {
            var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(root, component.FileName))));
            if (!string.Equals(hash, manifest.Hashes[component.Component], StringComparison.Ordinal))
                throw new InvalidDataException("Trusted manifest component hash failed.");
        }
        return new VerifiedServicePayload(manifest.Release, metadata.DisplayVersion, metadata.ReleaseSequence, manifestHash);
    }

    public static IReadOnlyList<string> ServiceComponentFileNames { get; } = Array.AsReadOnly(
        ServiceComponents.Select(item => item.FileName).ToArray());
    public static IReadOnlyList<string> ExactFileNames { get; } = Array.AsReadOnly(
        ServiceComponents.Select(item => item.FileName)
            .Append("Vantrel.Security.TrustedManifest").Append("Vantrel.Security.ReleaseMetadata").ToArray());

    private static void ValidateExactReleaseSet(string root)
    {
        if (!Directory.Exists(root) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Service payload root is unavailable or redirected.");
        var expected = ExactFileNames.ToHashSet(StringComparer.Ordinal);
        var entries = Directory.EnumerateFileSystemEntries(root).ToArray();
        if (entries.Length != expected.Count || entries.Any(path =>
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 || !File.Exists(path) ||
            !expected.Remove(Path.GetFileName(path))))
            throw new InvalidDataException("Service payload is not the exact fixed release set.");
    }
}
