using System.ComponentModel;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public sealed class ReleaseProvenanceStore
{
    private ReleaseProvenanceSnapshot? _snapshot;
    public ReleaseProvenanceSnapshot? Snapshot() => Volatile.Read(ref _snapshot);
    public void Update(ReleaseProvenanceSnapshot snapshot) => Volatile.Write(ref _snapshot, snapshot);
}

/// <summary>Evaluates only the fixed release-metadata sidecar and fixed trusted-manifest chain.</summary>
public sealed class ReleaseProvenanceSource
{
    private readonly IComponentInspectionHandleOperations _operations;
    private readonly Func<bool> _isEligible;
    private readonly Func<ComponentInspectionTargetIdentity> _deriveMetadata;
    private readonly Func<CancellationToken, CancellationTokenSource> _deadlineSource;
    private readonly TrustedManifestIntegritySource _manifestSource;
    private readonly ReleasePolicyStore _policyStore;

    public ReleaseProvenanceSource(TrustedManifestIntegritySource manifestSource, ReleasePolicyStore policyStore)
        : this(new NativeComponentInspectionHandleOperations(), IsInstalledScmService, DeriveMetadata, DeadlineSource, manifestSource, policyStore) { }

    internal ReleaseProvenanceSource(IComponentInspectionHandleOperations operations, Func<bool> isEligible,
        Func<ComponentInspectionTargetIdentity> deriveMetadata, Func<CancellationToken, CancellationTokenSource>? deadlineSource,
        TrustedManifestIntegritySource manifestSource, ReleasePolicyStore policyStore)
    {
        _operations = operations; _isEligible = isEligible; _deriveMetadata = deriveMetadata; _deadlineSource = deadlineSource ?? DeadlineSource;
        _manifestSource = manifestSource; _policyStore = policyStore;
    }

    public async Task<ReleaseProvenanceSnapshot> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var sampled = DateTimeOffset.UtcNow;
        if (!_isEligible()) return Result(sampled, ReleaseMetadataSignatureState.MetadataUnavailable, ReleaseManifestBindingState.ManifestUnavailable, ReleasePolicyDecision.PolicyUnavailable);
        try
        {
            var bytes = await ReadFixedMetadataAsync(cancellationToken);
            if (!ReleaseMetadataCodec.TryParse(bytes, out var metadata, out var parseFailure))
                return ParseFailure(sampled, parseFailure);
            if (!ReleaseMetadataCodec.Verify(metadata!, ReleaseMetadataPublicKey.SubjectPublicKeyInfo))
                return Result(sampled, ReleaseMetadataSignatureState.SignatureInvalid, ReleaseManifestBindingState.ManifestUnavailable, ReleasePolicyDecision.PolicyUnavailable);

            var manifestBytes = await _manifestSource.ReadManifestForReleaseProvenanceAsync(cancellationToken);
            if (manifestBytes is null) return Result(sampled, ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.ManifestUnavailable, ReleasePolicyDecision.PolicyUnavailable, metadata);
            var metadataManifestHash = Convert.ToHexString(SHA256.HashData(manifestBytes));
            if (!string.Equals(metadata!.ManifestSha256, metadataManifestHash, StringComparison.Ordinal))
                return Result(sampled, ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.ManifestMismatch, ReleasePolicyDecision.PolicyUnavailable, metadata);

            var trusted = await _manifestSource.CollectWithEvidenceAsync(cancellationToken);
            var integrity = trusted.Snapshot;
            if (integrity.SignatureState != TrustedManifestSignatureState.Valid)
                return Result(sampled, ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.ManifestInvalid, ReleasePolicyDecision.PolicyUnavailable, metadata);
            if (integrity.Evaluation == TrustedManifestInstallationEvaluation.ComponentMismatch)
                return Result(sampled, ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.ComponentMismatch, ReleasePolicyDecision.PolicyUnavailable, metadata);
            if (integrity.Evaluation != TrustedManifestInstallationEvaluation.AllMatch || trusted.ManifestSha256 is null)
                return Result(sampled, ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.ManifestUnavailable, ReleasePolicyDecision.PolicyUnavailable, metadata);
            if (!string.Equals(metadata.ManifestSha256, trusted.ManifestSha256, StringComparison.Ordinal))
                return Result(sampled, ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.ManifestMismatch, ReleasePolicyDecision.PolicyUnavailable, metadata);

            var verified = VerifiedRelease.AfterFullVerification(metadata);
            var decision = metadata.ReleaseSequence == 1
                ? await _policyStore.BootstrapVerifiedSequenceOneAsync(verified, cancellationToken)
                : await _policyStore.EvaluateVerifiedAsync(verified, cancellationToken);
            return Result(sampled, ReleaseMetadataSignatureState.Valid, ReleaseManifestBindingState.Bound, decision, metadata);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return Result(sampled, ReleaseMetadataSignatureState.MetadataUnavailable, ReleaseManifestBindingState.ManifestUnavailable, ReleasePolicyDecision.PolicyUnavailable); }
        catch (UnauthorizedAccessException) { return Result(sampled, ReleaseMetadataSignatureState.MetadataUnavailable, ReleaseManifestBindingState.ManifestUnavailable, ReleasePolicyDecision.PolicyUnavailable); }
        catch (Win32Exception) { return Result(sampled, ReleaseMetadataSignatureState.MetadataUnavailable, ReleaseManifestBindingState.ManifestUnavailable, ReleasePolicyDecision.PolicyUnavailable); }
        catch (IOException) { return Result(sampled, ReleaseMetadataSignatureState.MetadataUnavailable, ReleaseManifestBindingState.ManifestUnavailable, ReleasePolicyDecision.PolicyUnavailable); }
    }

    private async Task<byte[]> ReadFixedMetadataAsync(CancellationToken cancellationToken)
    {
        var target = _deriveMetadata();
        var root = Path.GetFullPath(target.InstallRoot);
        var path = Path.GetFullPath(target.LoadedAssemblyPath);
        if (!ComponentInspectionSource.Contained(root, path) || !string.Equals(Path.GetFileName(path), "Vantrel.Security.ReleaseMetadata", StringComparison.Ordinal))
            throw new IOException("Fixed release metadata identity rejected.");
        using var timeout = _deadlineSource(cancellationToken);
        using var handle = _operations.Open(path);
        var before = _operations.Metadata(handle);
        Validate(before, root, _operations.FinalPath(handle));
        await using var stream = _operations.CreateStream(handle);
        using var memory = new MemoryStream();
        var buffer = new byte[65536]; int read;
        while ((read = await stream.ReadAsync(buffer, timeout.Token)) != 0)
        {
            if (memory.Length + read > ReleaseMetadataCodec.MaximumBytes) throw new IOException("Release metadata exceeds its bound.");
            memory.Write(buffer, 0, read);
        }
        if (_operations.Metadata(handle) != before) throw new IOException("Release metadata changed during read.");
        return memory.ToArray();
    }

    private static void Validate(ComponentInspectionNative.Metadata metadata, string root, string finalPath)
    {
        if (metadata.IsReparsePoint || metadata.IsDirectory || metadata.Length > ReleaseMetadataCodec.MaximumBytes || !ComponentInspectionSource.Contained(root, finalPath))
            throw new IOException("Fixed release metadata validation failed.");
    }

    private static ReleaseProvenanceSnapshot ParseFailure(DateTimeOffset sampled, ReleaseMetadataParseFailure failure) => Result(sampled, failure switch
    {
        ReleaseMetadataParseFailure.Unavailable => ReleaseMetadataSignatureState.MetadataUnavailable,
        ReleaseMetadataParseFailure.UnsupportedSchema => ReleaseMetadataSignatureState.UnsupportedSchema,
        ReleaseMetadataParseFailure.WrongProduct => ReleaseMetadataSignatureState.WrongProduct,
        ReleaseMetadataParseFailure.WrongArchitecture => ReleaseMetadataSignatureState.WrongArchitecture,
        ReleaseMetadataParseFailure.WrongChannel => ReleaseMetadataSignatureState.WrongChannel,
        ReleaseMetadataParseFailure.UnknownKeyId => ReleaseMetadataSignatureState.UnknownKeyId,
        _ => ReleaseMetadataSignatureState.MetadataMalformed
    }, ReleaseManifestBindingState.ManifestUnavailable, ReleasePolicyDecision.PolicyUnavailable);

    private static ReleaseProvenanceSnapshot Result(DateTimeOffset sampled, ReleaseMetadataSignatureState signature,
        ReleaseManifestBindingState binding, ReleasePolicyDecision policy, ReleaseMetadata? metadata = null) =>
        new(sampled, signature, binding, metadata is null ? null : ReleaseMetadataCodec.Product, metadata is null ? null : ReleaseMetadataCodec.Architecture,
            metadata is null ? null : ReleaseMetadataCodec.Channel, metadata?.ReleaseSequence, metadata?.DisplayVersion, policy, metadata?.ManifestSha256);

    private static bool IsInstalledScmService() => OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService();
    private static CancellationTokenSource DeadlineSource(CancellationToken token) { var source = CancellationTokenSource.CreateLinkedTokenSource(token); source.CancelAfter(ComponentInspectionSource.Deadline); return source; }
    private static ComponentInspectionTargetIdentity DeriveMetadata() => new(Path.Combine(Path.GetDirectoryName(typeof(ReleaseProvenanceSource).Assembly.Location)!, "Vantrel.Security.ReleaseMetadata"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Vantrel Security", "Service"));
}

public sealed class ReleaseProvenanceWorker(ReleaseProvenanceStore store, ReleaseProvenanceSource source, ILogger<ReleaseProvenanceWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Yield();
            store.Update(await source.CollectAsync(stoppingToken));
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(15));
            while (await timer.WaitForNextTickAsync(stoppingToken)) store.Update(await source.CollectAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { logger.LogInformation("Release provenance sampling stopped"); }
    }
}