using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>A capability created only after full release-metadata, manifest, and component verification.</summary>
internal sealed record VerifiedRelease
{
    private VerifiedRelease(ulong sequence, string manifestSha256) { Sequence = sequence; ManifestSha256 = manifestSha256; }
    internal ulong Sequence { get; }
    internal string ManifestSha256 { get; }
    internal static VerifiedRelease AfterFullVerification(ReleaseMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        return new(metadata.ReleaseSequence, metadata.ManifestSha256);
    }
    internal static VerifiedRelease FromVerifiedEvidence(ulong sequence, string manifestSha256)
    {
        if (sequence == 0 || manifestSha256 is not { Length: 64 } || !manifestSha256.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F'))
            throw new ArgumentException("Verified release evidence is invalid.");
        return new(sequence, manifestSha256);
    }
}

/// <summary>Constructed only from a successful installed integrity observation and bound, signed metadata.</summary>
internal sealed class AuthenticatedInstalledRelease
{
    private AuthenticatedInstalledRelease(ReleaseIdentity identity) => Identity = identity;
    internal ReleaseIdentity Identity { get; }
    internal static AuthenticatedInstalledRelease? FromVerifiedObservation(TrustedManifestCollectionResult trusted,
        ReleaseMetadata metadata, ReadOnlySpan<byte> metadataPublicKey)
    {
        if (!ReleaseMetadataCodec.Verify(metadata, metadataPublicKey)) return null;
        if (trusted.Snapshot is not { SignatureState: TrustedManifestSignatureState.Valid,
            Evaluation: TrustedManifestInstallationEvaluation.AllMatch } ||
            trusted.ManifestSha256 is null || metadata.ManifestSha256 != trusted.ManifestSha256 ||
            metadata.ReleaseSequence == 0) return null;
        var identity = trusted.Identity ?? new ReleaseIdentity(ReleaseGeneration.V1, metadata.ReleaseSequence, trusted.ManifestSha256);
        if (identity.Generation == ReleaseGeneration.V2 &&
            (trusted.BoundMetadata is null || trusted.BoundMetadata.ReleaseSequence != metadata.ReleaseSequence ||
             trusted.BoundMetadata.DisplayVersion != metadata.DisplayVersion ||
             trusted.BoundMetadata.ManifestSha256 != metadata.ManifestSha256)) return null;
        return identity.IsValid && identity.ReleaseSequence == metadata.ReleaseSequence &&
            identity.ManifestSha256 == metadata.ManifestSha256 ? new(identity) : null;
    }
}

/// <summary>Fixed LocalService-owned durable high-water policy. It never accepts raw metadata, paths, or IPC input.</summary>
public sealed class ReleasePolicyStore
{
    internal const string PolicyFileName = "accepted-release-v1.json";
    private readonly string _vantrelRoot;
    private readonly string _policyDirectory;
    private readonly string _policyPath;
    private readonly bool _applyAcls;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ReleasePolicyRecord? _snapshot;
    private GenerationAwareReleasePolicyRecord? _generationSnapshot;
    private bool _bootstrapCompleted;

    public ReleasePolicyStore() : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Vantrel Security"), applyAcls: true) { }
    internal ReleasePolicyStore(string vantrelRoot, bool applyAcls = true)
    {
        _vantrelRoot = Path.GetFullPath(vantrelRoot);
        _policyDirectory = Path.Combine(_vantrelRoot, "ReleasePolicy");
        _policyPath = Path.Combine(_policyDirectory, PolicyFileName);
        _applyAcls = applyAcls;
    }

    public ReleasePolicyRecord? Snapshot() => Volatile.Read(ref _snapshot);
    internal GenerationAwareReleasePolicyRecord? GenerationSnapshot() => Volatile.Read(ref _generationSnapshot);

    /// <summary>V2 first-install only. Existing policy state is evaluated or rejected without replacement.</summary>
    internal async Task<ReleasePolicyDecision> BootstrapAuthenticatedV2Async(AuthenticatedInstalledRelease verified, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verified);
        if (verified.Identity.Generation != ReleaseGeneration.V2 || !verified.Identity.IsValid)
            return ReleasePolicyDecision.PolicyUnavailable;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var loaded = LoadExistingV2();
            if (loaded.Failure == ReleasePolicyParseFailure.None)
            {
                _bootstrapCompleted = true;
                Volatile.Write(ref _generationSnapshot, loaded.Record);
                return GenerationAwareReleasePolicyCodec.Evaluate(loaded.Record, verified.Identity);
            }
            if (loaded.Failure != ReleasePolicyParseFailure.Unavailable || _bootstrapCompleted)
                return ReleasePolicyDecision.PolicyUnavailable;
            cancellationToken.ThrowIfCancellationRequested();
            var policy = new GenerationAwareReleasePolicyRecord(verified.Identity);
            PersistGenerationPolicy(policy, cancellationToken);
            _bootstrapCompleted = true;
            Volatile.Write(ref _generationSnapshot, policy);
            return ReleasePolicyDecision.BootstrapAccepted;
        }
        finally { _gate.Release(); }
    }

    internal async Task<ReleasePolicyDecision> EvaluateAuthenticatedV2Async(AuthenticatedInstalledRelease verified, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verified);
        if (verified.Identity.Generation != ReleaseGeneration.V2 || !verified.Identity.IsValid)
            return ReleasePolicyDecision.PolicyUnavailable;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var loaded = LoadExistingV2();
            if (loaded.Failure != ReleasePolicyParseFailure.None) return ReleasePolicyDecision.PolicyUnavailable;
            _bootstrapCompleted = true;
            Volatile.Write(ref _generationSnapshot, loaded.Record);
            return GenerationAwareReleasePolicyCodec.Evaluate(loaded.Record, verified.Identity);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Projects an authenticated historical v1 policy for in-memory evaluation without changing its durable bytes.</summary>
    internal async Task<ReleasePolicyDecision> EvaluateAuthenticatedV1Async(AuthenticatedInstalledRelease verified, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verified);
        if (verified.Identity.Generation != ReleaseGeneration.V1 || !verified.Identity.IsValid)
            return ReleasePolicyDecision.PolicyUnavailable;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var old = LoadExisting();
            if (old.Failure != ReleasePolicyParseFailure.None || old.Record is null)
                return ReleasePolicyDecision.PolicyUnavailable;
            _bootstrapCompleted = true;
            Volatile.Write(ref _snapshot, old.Record);
            var policy = new GenerationAwareReleasePolicyRecord(new ReleaseIdentity(ReleaseGeneration.V1,
                old.Record.HighestAcceptedReleaseSequence, old.Record.AcceptedManifestSha256));
            Volatile.Write(ref _generationSnapshot, policy);
            return GenerationAwareReleasePolicyCodec.Evaluate(policy, verified.Identity);
        }
        finally { _gate.Release(); }
    }

    internal async Task<(ReleasePolicyRecord? Record, ReleasePolicyParseFailure Failure)> ReadDurableAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var loaded = LoadExisting();
            if (loaded.Failure == ReleasePolicyParseFailure.None) Volatile.Write(ref _snapshot, loaded.Record);
            return loaded;
        }
        finally { _gate.Release(); }
    }

    internal async Task<ReleasePolicyDecision> EvaluateVerifiedAsync(VerifiedRelease verified, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verified);
        cancellationToken.ThrowIfCancellationRequested();
        await _gate.WaitAsync(cancellationToken);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var loaded = LoadExisting();
            if (loaded.Failure != ReleasePolicyParseFailure.None)
                return ReleasePolicyDecision.PolicyUnavailable;
            _bootstrapCompleted = true;
            Volatile.Write(ref _snapshot, loaded.Record);
            return ReleasePolicyCodec.Evaluate(loaded.Record, verified.Sequence, verified.ManifestSha256);
        }
        finally { _gate.Release(); }
    }

    internal async Task<ReleasePolicyDecision> BootstrapVerifiedSequenceOneAsync(VerifiedRelease verified, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verified);
        if (verified.Sequence != 1) return ReleasePolicyDecision.PolicyUnavailable;
        cancellationToken.ThrowIfCancellationRequested();
        await _gate.WaitAsync(cancellationToken);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var loaded = LoadExisting();
            if (loaded.Failure == ReleasePolicyParseFailure.None)
            {
                _bootstrapCompleted = true;
                Volatile.Write(ref _snapshot, loaded.Record);
                return ReleasePolicyCodec.Evaluate(loaded.Record, verified.Sequence, verified.ManifestSha256);
            }
            if (loaded.Failure != ReleasePolicyParseFailure.Unavailable || _bootstrapCompleted)
                return ReleasePolicyDecision.PolicyUnavailable;
            var policy = new ReleasePolicyRecord(verified.Sequence, verified.ManifestSha256);
            PersistPolicy(policy, requireMissing: true, cancellationToken);
            _bootstrapCompleted = true;
            Volatile.Write(ref _snapshot, policy);
            return ReleasePolicyDecision.BootstrapAccepted;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Reserved for a future installer transaction after a verified release is fully installed and post-verified.</summary>
    internal async Task<ReleasePolicyDecision> CommitVerifiedInstalledReleaseAsync(VerifiedRelease verified, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verified);
        cancellationToken.ThrowIfCancellationRequested();
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var loaded = LoadExisting();
            if (loaded.Failure != ReleasePolicyParseFailure.None) return ReleasePolicyDecision.PolicyUnavailable;
            var decision = ReleasePolicyCodec.Evaluate(loaded.Record, verified.Sequence, verified.ManifestSha256);
            if (decision != ReleasePolicyDecision.HigherRelease) return decision;
            cancellationToken.ThrowIfCancellationRequested();
            var policy = new ReleasePolicyRecord(verified.Sequence, verified.ManifestSha256);
            PersistPolicy(policy, requireMissing: false, cancellationToken);
            Volatile.Write(ref _snapshot, policy);
            return ReleasePolicyDecision.HigherRelease;
        }
        finally { _gate.Release(); }
    }
    private (ReleasePolicyRecord? Record, ReleasePolicyParseFailure Failure) LoadExisting()
    {
        EnsureDirectory(_vantrelRoot, _applyAcls);
        EnsureDirectory(_policyDirectory, _applyAcls);
        if (!File.Exists(_policyPath)) return (null, ReleasePolicyParseFailure.Unavailable);
        RejectReparse(_policyPath);
        var bytes = File.ReadAllBytes(_policyPath);
        return ReleasePolicyCodec.TryParse(bytes, out var policy, out var failure) ? (policy, failure) : (null, failure);
    }

    private (GenerationAwareReleasePolicyRecord? Record, ReleasePolicyParseFailure Failure) LoadExistingV2()
    {
        EnsureDirectory(_vantrelRoot, _applyAcls);
        EnsureDirectory(_policyDirectory, _applyAcls);
        if (!File.Exists(_policyPath)) return (null, ReleasePolicyParseFailure.Unavailable);
        RejectReparse(_policyPath);
        using var stream = new FileStream(_policyPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is 0 or > GenerationAwareReleasePolicyCodec.MaximumBytes)
            return (null, ReleasePolicyParseFailure.Malformed);
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return GenerationAwareReleasePolicyCodec.TryParse(bytes, out var policy, out var failure) ? (policy, failure) : (null, failure);
    }

    private void PersistGenerationPolicy(GenerationAwareReleasePolicyRecord policy, CancellationToken cancellationToken)
    {
        EnsureDirectory(_vantrelRoot, _applyAcls);
        EnsureDirectory(_policyDirectory, _applyAcls);
        if (File.Exists(_policyPath))
        {
            RejectReparse(_policyPath);
            throw new IOException("Policy appeared during bootstrap.");
        }
        var temporary = Path.Combine(_policyDirectory, ".accepted-release-v2." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                RejectReparse(temporary);
                if (_applyAcls) ApplyFileAcl(temporary);
                var bytes = GenerationAwareReleasePolicyCodec.Serialize(policy);
                stream.Write(bytes);
                cancellationToken.ThrowIfCancellationRequested();
                stream.Flush(flushToDisk: true);
            }
            RejectReparse(temporary);
            File.Move(temporary, _policyPath, overwrite: false);
            RejectReparse(_policyPath);
            if (_applyAcls) ApplyFileAcl(_policyPath);
            var (read, failure) = LoadExistingV2();
            if (failure != ReleasePolicyParseFailure.None || read != policy)
                throw new IOException("Policy verification after atomic move failed.");
        }
        finally { if (File.Exists(temporary)) { try { RejectReparse(temporary); File.Delete(temporary); } catch { } } }
    }

    private void PersistPolicy(ReleasePolicyRecord policy, bool requireMissing, CancellationToken cancellationToken)
    {
        EnsureDirectory(_vantrelRoot, _applyAcls);
        EnsureDirectory(_policyDirectory, _applyAcls);
        var existing = File.Exists(_policyPath);
        if (existing) RejectReparse(_policyPath);
        if (requireMissing && existing) throw new IOException("Policy appeared during bootstrap.");
        var temporary = Path.Combine(_policyDirectory, ".accepted-release-v1." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                RejectReparse(temporary);
                if (_applyAcls) ApplyFileAcl(temporary);
                var bytes = ReleasePolicyCodec.Serialize(policy);
                stream.Write(bytes, 0, bytes.Length);
                cancellationToken.ThrowIfCancellationRequested();
                stream.Flush(flushToDisk: true);
            }
            RejectReparse(temporary);
            if (existing) File.Replace(temporary, _policyPath, destinationBackupFileName: null, ignoreMetadataErrors: false);
            else File.Move(temporary, _policyPath, overwrite: false);
            RejectReparse(_policyPath);
            if (_applyAcls)
            {
                ApplyFileAcl(_policyPath);
                if (existing)
                {
                    var validation = UpdateFilesystemSecurity.ValidateLocalServiceReplacedMutableFileOnDisk(new FileInfo(_policyPath));
                    if (!validation.IsMatch) throw new IOException("LocalService-replaced policy descriptor verification failed: " + validation.Mismatch);
                }
            }
            var (read, failure) = LoadExisting();
            if (failure != ReleasePolicyParseFailure.None || read != policy) throw new IOException("Policy verification after atomic move failed.");
        }
        finally
        {
            if (File.Exists(temporary)) { try { RejectReparse(temporary); File.Delete(temporary); } catch { } }
        }
    }

    private static void EnsureDirectory(string path, bool applyAcls)
    {
        if (Directory.Exists(path)) { RejectReparse(path); if (applyAcls) ApplyDirectoryAcl(path); return; }
        Directory.CreateDirectory(path);
        RejectReparse(path);
        if (applyAcls) ApplyDirectoryAcl(path);
    }

    private static void RejectReparse(string path) => RejectReparseAttributes(File.GetAttributes(path));

    internal static void RejectReparseAttributes(FileAttributes attributes)
    {
        if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Release policy reparse point rejected.");
    }

    private static void ApplyDirectoryAcl(string path)
    {
        if (OperatingSystem.IsWindows()) new DirectoryInfo(path).SetAccessControl(CreateRequiredDirectorySecurity());
    }

    private static void ApplyFileAcl(string path)
    {
        if (OperatingSystem.IsWindows()) new FileInfo(path).SetAccessControl(UpdateFilesystemSecurity.CreateMutableFileDaclDescriptor());
    }

    internal static DirectorySecurity CreateRequiredDirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null), FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    internal static FileSecurity CreateRequiredFileSecurity()
        => UpdateFilesystemSecurity.CreateMutableFileDaclDescriptor();
}
