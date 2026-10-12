using System.Collections.Immutable;
using System.Security.Cryptography;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>
/// Read-only evidence for one physical root. No result from this API authorizes the historical
/// fixed-file update transaction. A copy or a later observation needs a fresh verification.
/// </summary>
internal sealed record GenerationAwareOfflineReleaseEvidence(
    ReleaseIdentity Identity, ImmutableArray<TrustedManifestV2File> RuntimeInventory);

internal enum GenerationAwareOfflineVerificationResult
{
    Authenticated,
    Advancement,
    SameRelease,
    MigrationRequired,
    RollbackBlocked,
    SequenceConflict,
    GenerationDowngradeBlocked,
    PolicyUnavailable,
    InvalidRelease,
    UnsupportedGeneration
}

internal sealed record GenerationAwareOfflineVerification(
    GenerationAwareOfflineVerificationResult Result,
    GenerationAwareOfflineReleaseEvidence? Release,
    ReleasePolicyDecision PolicyDecision = ReleasePolicyDecision.PolicyUnavailable);

/// <summary>
/// Verifies a caller-authorized Service payload root. Root authorization belongs to the caller's
/// storage boundary; this verifier authenticates the bytes and physical inventory within that root.
/// It is deliberately separate from OfflineReleaseVerifier and has no transaction caller.
/// </summary>
internal sealed class GenerationAwareOfflineReleaseVerifier
{
    private const string ManifestName = "Vantrel.Security.TrustedManifest";
    private static readonly byte[] V1Header = "schema=vantrel-trusted-manifest-v1\n"u8.ToArray();
    private static readonly byte[] V2Header = "schema=vantrel-trusted-manifest-v2\n"u8.ToArray();
    private readonly OfflineReleaseVerifier _v1;
    private readonly Func<string, CancellationToken, Task<VerifiedOfflineRelease>> _v1Chain;
    private readonly Func<string, TrustedManifestIntegritySource> _v2Source;

    internal GenerationAwareOfflineReleaseVerifier()
        : this(ReleaseMetadataPublicKey.SubjectPublicKeyInfo, TrustedManifestPublicKey.SubjectPublicKeyInfo) { }

    // Key substitution and the source factory are internal test seams. Production uses the two
    // independently pinned public keys and native Task 077 inspection operations.
    internal GenerationAwareOfflineReleaseVerifier(byte[] metadataPublicKey, byte[] manifestPublicKey,
        Func<string, TrustedManifestIntegritySource>? v2Source = null,
        Func<string, CancellationToken, Task<VerifiedOfflineRelease>>? v1Chain = null)
    {
        ArgumentNullException.ThrowIfNull(metadataPublicKey);
        ArgumentNullException.ThrowIfNull(manifestPublicKey);
        var metadataKey = metadataPublicKey.ToArray();
        var manifestKey = manifestPublicKey.ToArray();
        _v1 = new OfflineReleaseVerifier(metadataKey, manifestKey);
        _v1Chain = v1Chain ?? _v1.VerifyChainAsync;
        _v2Source = v2Source ?? (root => new TrustedManifestIntegritySource(
            new NativeComponentInspectionHandleOperations(), () => true,
            () => new ComponentInspectionTargetIdentity(Path.Combine(root, ManifestName), root),
            manifestPublicKey: () => manifestKey, metadataPublicKey: () => metadataKey));
    }

    /// <summary>Authenticate the complete physical root without consulting or changing policy.</summary>
    internal async Task<GenerationAwareOfflineVerification> VerifyChainAsync(string authorizedRoot, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authorizedRoot);
        token.ThrowIfCancellationRequested();
        try
        {
            if (!Path.IsPathFullyQualified(authorizedRoot))
                return new(GenerationAwareOfflineVerificationResult.InvalidRelease, null);
            var root = Path.GetFullPath(authorizedRoot);
            var generation = await SelectGenerationAsync(root, token);
            if (generation is null)
                return new(GenerationAwareOfflineVerificationResult.UnsupportedGeneration, null);
            if (generation == ReleaseGeneration.V1)
            {
                // Keep every historical V1 exact-set, signature, binding and hash rule in its
                // original implementation. An invalid V1 result never enters the V2 path.
                var verified = await _v1Chain(root, token);
                var identity = new ReleaseIdentity(ReleaseGeneration.V1, verified.Sequence, verified.ManifestSha256);
                return identity.IsValid
                    ? new(GenerationAwareOfflineVerificationResult.Authenticated,
                        new(identity, ImmutableArray<TrustedManifestV2File>.Empty))
                    : new(GenerationAwareOfflineVerificationResult.InvalidRelease, null);
            }

            // The installed V2 source is scoped to this exact caller-authorized root on every
            // call. It reopens and rehashes every file, retaining handles through tree recheck.
            var observed = await _v2Source(root).CollectWithEvidenceAsync(token);
            if (observed.Snapshot is not
                { SignatureState: TrustedManifestSignatureState.Valid,
                  Evaluation: TrustedManifestInstallationEvaluation.AllMatch } ||
                observed.Identity is not { Generation: ReleaseGeneration.V2, IsValid: true } identityV2 ||
                observed.BoundMetadata is null ||
                observed.BoundMetadata.ReleaseSequence != identityV2.ReleaseSequence ||
                observed.BoundMetadata.ManifestSha256 != identityV2.ManifestSha256 ||
                observed.VerifiedInventory.IsDefaultOrEmpty)
                return new(GenerationAwareOfflineVerificationResult.InvalidRelease, null);
            return new(GenerationAwareOfflineVerificationResult.Authenticated,
                new(identityV2, observed.VerifiedInventory));
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or
            System.ComponentModel.Win32Exception or ArgumentException or NotSupportedException or
            CryptographicException)
        {
            return new(GenerationAwareOfflineVerificationResult.InvalidRelease, null);
        }
    }

    /// <summary>
    /// Read-only policy assessment of a freshly authenticated root. MigrationRequired is a
    /// planning decision, never an authorization for the existing V1 transaction.
    /// </summary>
    internal async Task<GenerationAwareOfflineVerification> VerifyCandidateAsync(
        string authorizedRoot, ReleasePolicyStore policy, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var chain = await VerifyChainAsync(authorizedRoot, token);
        if (chain.Release is null) return chain;
        (ReleaseIdentity? Identity, ReleasePolicyParseFailure Failure) accepted;
        try { accepted = await policy.ReadPolicyIdentityAsync(token); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or
            System.ComponentModel.Win32Exception or ArgumentException or NotSupportedException)
        {
            return new(GenerationAwareOfflineVerificationResult.PolicyUnavailable, chain.Release);
        }
        if (accepted.Failure != ReleasePolicyParseFailure.None || accepted.Identity is null)
            return new(GenerationAwareOfflineVerificationResult.PolicyUnavailable, chain.Release);
        var decision = GenerationAwareReleasePolicyCodec.Evaluate(
            new GenerationAwareReleasePolicyRecord(accepted.Identity), chain.Release.Identity);
        var result = decision switch
        {
            ReleasePolicyDecision.HigherRelease => GenerationAwareOfflineVerificationResult.Advancement,
            ReleasePolicyDecision.SameAcceptedRelease => GenerationAwareOfflineVerificationResult.SameRelease,
            ReleasePolicyDecision.TransitionRequiresCoordination => GenerationAwareOfflineVerificationResult.MigrationRequired,
            ReleasePolicyDecision.RollbackBlocked => GenerationAwareOfflineVerificationResult.RollbackBlocked,
            ReleasePolicyDecision.SequenceConflict => GenerationAwareOfflineVerificationResult.SequenceConflict,
            ReleasePolicyDecision.GenerationDowngradeBlocked => GenerationAwareOfflineVerificationResult.GenerationDowngradeBlocked,
            _ => GenerationAwareOfflineVerificationResult.PolicyUnavailable
        };
        return new(result, chain.Release, decision);
    }

    private static async Task<ReleaseGeneration?> SelectGenerationAsync(string root, CancellationToken token)
    {
        var manifest = Path.Combine(root, ManifestName);
        OfflineReleaseVerifier.RejectReparseAncestors(manifest);
        await using var stream = new FileStream(manifest, FileMode.Open, FileAccess.Read, FileShare.Read,
            64, FileOptions.Asynchronous | FileOptions.SequentialScan);
        // The first line alone makes the irreversible dispatch decision. A missing newline,
        // overlong line, CR, BOM, or any other noncanonical framing fails before verification.
        var header = new byte[65];
        for (var length = 0; length < header.Length; length++)
        {
            var read = await stream.ReadAsync(header.AsMemory(length, 1), token);
            if (read != 1) throw new InvalidDataException("Trusted manifest schema framing is incomplete.");
            if (header[length] != (byte)'\n') continue;
            var framed = header.AsSpan(0, length + 1);
            if (framed.SequenceEqual(V1Header)) return ReleaseGeneration.V1;
            if (framed.SequenceEqual(V2Header)) return ReleaseGeneration.V2;
            if (framed.StartsWith("schema=vantrel-trusted-manifest-v1"u8) ||
                framed.StartsWith("schema=vantrel-trusted-manifest-v2"u8))
                throw new InvalidDataException("Trusted manifest schema framing is malformed.");
            if (framed.StartsWith("schema="u8)) return null;
            throw new InvalidDataException("Trusted manifest schema framing is malformed.");
        }
        throw new InvalidDataException("Trusted manifest schema framing exceeds its bound.");
    }
}
