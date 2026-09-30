using System.Security.Cryptography;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

internal static class FixedUpdatePaths
{
    internal static readonly string VantrelRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Vantrel Security");
    internal static readonly string UpdatesRoot = Path.Combine(VantrelRoot, "Updates");
    internal static readonly string StagedCandidate = Path.Combine(UpdatesRoot, "Staged", "candidate");
    internal static readonly string TransactionsRoot = Path.Combine(UpdatesRoot, "Transactions");
    internal static readonly string BackupsRoot = Path.Combine(UpdatesRoot, "Backups");
    internal static readonly string InstalledServiceRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Vantrel Security", "Service");
}

internal static class FixedServiceReleaseFiles
{
    internal static readonly (TrustedManifestComponent Component, string Name)[] Components =
    [
        (TrustedManifestComponent.ServiceExe, "Vantrel.Security.Service.exe"),
        (TrustedManifestComponent.ServiceAssembly, "Vantrel.Security.Service.dll"),
        (TrustedManifestComponent.InfrastructureAssembly, "Vantrel.Security.Infrastructure.dll"),
        (TrustedManifestComponent.CoreAssembly, "Vantrel.Security.Core.dll"),
        (TrustedManifestComponent.Deps, "Vantrel.Security.Service.deps.json"),
        (TrustedManifestComponent.RuntimeConfig, "Vantrel.Security.Service.runtimeconfig.json"),
        (TrustedManifestComponent.EventLogResource, "System.Diagnostics.EventLog.Messages.dll")
    ];
    internal static readonly string[] AllNames = Components.Select(value => value.Name)
        .Append("Vantrel.Security.TrustedManifest").Append("Vantrel.Security.ReleaseMetadata").ToArray();
}

internal sealed record VerifiedOfflineRelease(ulong Sequence, string ManifestSha256, ReleasePolicyDecision PolicyDecision);
internal enum OfflineReleaseVerificationResult { Verified, InvalidRelease, PolicyUnavailable, PolicyMismatch, RollbackBlocked, SequenceConflict }
internal sealed record OfflineReleaseVerification(OfflineReleaseVerificationResult Result, VerifiedOfflineRelease? Release);

/// <summary>Read-only fixed-directory verifier used by the elevated installer and service recovery path. No caller controls a production root.</summary>
internal sealed class OfflineReleaseVerifier
{
    private readonly byte[] _releaseMetadataPublicKey;
    private readonly byte[] _trustedManifestPublicKey;

    internal OfflineReleaseVerifier() : this(ReleaseMetadataPublicKey.SubjectPublicKeyInfo, TrustedManifestPublicKey.SubjectPublicKeyInfo) { }

    // Internal test-only construction path. Production registration uses the parameterless constructor.
    internal OfflineReleaseVerifier(byte[] releaseMetadataPublicKey, byte[] trustedManifestPublicKey)
    {
        _releaseMetadataPublicKey = releaseMetadataPublicKey ?? throw new ArgumentNullException(nameof(releaseMetadataPublicKey));
        _trustedManifestPublicKey = trustedManifestPublicKey ?? throw new ArgumentNullException(nameof(trustedManifestPublicKey));
    }
    internal async Task<VerifiedOfflineRelease> VerifyCandidateAsync(string root, ReleasePolicyStore policy, CancellationToken token)
    {
        var verified = await VerifyChainAsync(root, token);
        var decision = await policy.EvaluateVerifiedAsync(VerifiedRelease.FromVerifiedEvidence(verified.Sequence, verified.ManifestSha256), token);
        return verified with { PolicyDecision = decision };
    }

    internal async Task<VerifiedOfflineRelease> VerifyInstalledAsync(ReleasePolicyStore policy, CancellationToken token) =>
        await VerifyCandidateAsync(FixedUpdatePaths.InstalledServiceRoot, policy, token);

    internal async Task<OfflineReleaseVerification> VerifyInstalledBaselineAsync(ReleasePolicyStore policy, CancellationToken token)
    {
        try
        {
            var release = await VerifyInstalledAsync(policy, token);
            var accepted = policy.Snapshot();
            if (release.PolicyDecision == ReleasePolicyDecision.PolicyUnavailable || accepted is null)
                return new(OfflineReleaseVerificationResult.PolicyUnavailable, null);
            if (release.PolicyDecision == ReleasePolicyDecision.RollbackBlocked) return new(OfflineReleaseVerificationResult.RollbackBlocked, null);
            if (release.PolicyDecision == ReleasePolicyDecision.SequenceConflict) return new(OfflineReleaseVerificationResult.SequenceConflict, null);
            if (release.Sequence != accepted.HighestAcceptedReleaseSequence || !string.Equals(release.ManifestSha256, accepted.AcceptedManifestSha256, StringComparison.Ordinal))
                return new(OfflineReleaseVerificationResult.PolicyMismatch, null);
            return new(OfflineReleaseVerificationResult.Verified, release);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception) { return new(OfflineReleaseVerificationResult.InvalidRelease, null); }
    }

    internal async Task<VerifiedOfflineRelease> VerifyChainAsync(string root, CancellationToken token)
    {
        root = Path.GetFullPath(root);
        ValidateExactSet(root);
        var metadataBytes = await ReadBoundedAsync(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"), ReleaseMetadataCodec.MaximumBytes, token);
        if (!ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out var metadataFailure) || metadata is null ||
            !ReleaseMetadataCodec.Verify(metadata, _releaseMetadataPublicKey))
            throw new InvalidDataException("Fixed release metadata verification failed: " + metadataFailure);
        var manifestBytes = await ReadBoundedAsync(Path.Combine(root, "Vantrel.Security.TrustedManifest"), TrustedManifestCodec.MaximumBytes, token);
        if (!TrustedManifestCodec.TryParse(manifestBytes, out var manifest, out var manifestFailure) || manifest is null ||
            !TrustedManifestCodec.Verify(manifest, _trustedManifestPublicKey))
            throw new InvalidDataException("Fixed trusted manifest verification failed: " + manifestFailure);
        var manifestHash = Convert.ToHexString(SHA256.HashData(manifestBytes));
        if (!string.Equals(metadata.ManifestSha256, manifestHash, StringComparison.Ordinal)) throw new InvalidDataException("Release metadata manifest binding failed.");
        foreach (var (component, name) in FixedServiceReleaseFiles.Components)
        {
            var observed = await HashAsync(Path.Combine(root, name), token);
            if (!string.Equals(observed, manifest.Hashes[component], StringComparison.Ordinal)) throw new InvalidDataException("Fixed component hash verification failed.");
        }
        return new VerifiedOfflineRelease(metadata.ReleaseSequence, manifestHash, ReleasePolicyDecision.PolicyUnavailable);
    }

    internal static void ValidateExactSet(string root)
    {
        root = Path.GetFullPath(root);
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException("Fixed release root is unavailable.");
        RejectReparseAncestors(root);
        var expected = new HashSet<string>(FixedServiceReleaseFiles.AllNames, StringComparer.Ordinal);
        var entries = Directory.EnumerateFileSystemEntries(root).ToArray();
        if (entries.Length != expected.Count) throw new InvalidDataException("Fixed release file set is incomplete or contains extras.");
        foreach (var entry in entries)
        {
            RejectReparseAncestors(entry);
            if (!File.Exists(entry) || !expected.Remove(Path.GetFileName(entry))) throw new InvalidDataException("Fixed release file identity rejected.");
        }
        if (expected.Count != 0) throw new InvalidDataException("Fixed release file set is incomplete.");
    }

    private static async Task<byte[]> ReadBoundedAsync(string path, int maximum, CancellationToken token)
    {
        RejectReparseAncestors(path);
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var memory = new MemoryStream();
        var buffer = new byte[65536]; int read;
        while ((read = await stream.ReadAsync(buffer, token)) != 0)
        {
            if (memory.Length + read > maximum) throw new InvalidDataException("Fixed release file exceeds its bound.");
            memory.Write(buffer, 0, read);
        }
        RejectReparseAncestors(path);
        return memory.ToArray();
    }
    private static async Task<string> HashAsync(string path, CancellationToken token)
    {
        RejectReparseAncestors(path);
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = new byte[65536]; int read; long total = 0;
        while ((read = await stream.ReadAsync(buffer, token)) != 0) { total += read; if (total > ComponentInspectionSource.MaximumBytes) throw new InvalidDataException("Fixed release component exceeds its bound."); hash.AppendData(buffer, 0, read); }
        RejectReparseAncestors(path); return Convert.ToHexString(hash.GetHashAndReset());
    }
    internal static void RejectReparseAncestors(string path)
    {
        path = Path.GetFullPath(path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Release reparse point rejected.");
        var current = Directory.Exists(path) ? new DirectoryInfo(path) : Directory.GetParent(path);
        for (; current is not null; current = current.Parent)
        {
            if ((File.GetAttributes(current.FullName) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Release reparse ancestor rejected.");
        }
    }
}
