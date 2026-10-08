using System.ComponentModel;
using System.Collections.Immutable;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting.WindowsServices;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public sealed class TrustedManifestIntegrityStore
{
    private TrustedManifestIntegritySnapshot? _snapshot;
    public TrustedManifestIntegritySnapshot? Snapshot() => Volatile.Read(ref _snapshot);
    public void Update(TrustedManifestIntegritySnapshot snapshot) => Volatile.Write(ref _snapshot, snapshot);
}

/// <summary>Bounded immutable history of snapshots that were already published as current integrity state.</summary>
public sealed class TrustedManifestIntegrityHistoryStore
{
    private const int MaximumEntries = 12;
    private ImmutableArray<TrustedManifestIntegrityHistoryRecord> _entries = [];
    public ImmutableArray<TrustedManifestIntegrityHistoryRecord> Snapshot() { lock (this) return _entries; }
    public void AppendPublished(TrustedManifestIntegritySnapshot snapshot)
    {
        var entry = new TrustedManifestIntegrityHistoryRecord(snapshot.SampledAtUtc, snapshot.SignatureState, snapshot.Evaluation);
        lock (this) _entries = _entries
            .Append(entry)
            .OrderByDescending(static snapshot => snapshot.SampledAtUtc)
            .Take(MaximumEntries)
            .ToImmutableArray();
    }
}

/// <summary>Authenticates a fixed signed manifest, then compares exactly seven fixed installed files.</summary>
internal sealed record TrustedManifestCollectionResult(TrustedManifestIntegritySnapshot Snapshot, string? ManifestSha256);

public sealed class TrustedManifestIntegritySource
{
    private readonly IComponentInspectionHandleOperations _operations;
    private readonly Func<bool> _isEligible;
    private readonly Func<ComponentInspectionTargetIdentity> _deriveManifest;
    private readonly Func<CancellationToken, CancellationTokenSource> _deadlineSource;

    public TrustedManifestIntegritySource() : this(new NativeComponentInspectionHandleOperations(), IsInstalledScmService, DeriveManifest, DeadlineSource) { }
    internal TrustedManifestIntegritySource(IComponentInspectionHandleOperations operations, Func<bool> isEligible,
        Func<ComponentInspectionTargetIdentity> deriveManifest, Func<CancellationToken, CancellationTokenSource>? deadlineSource = null)
    { _operations = operations; _isEligible = isEligible; _deriveManifest = deriveManifest; _deadlineSource = deadlineSource ?? DeadlineSource; }

    public async Task<TrustedManifestIntegritySnapshot> CollectAsync(CancellationToken cancellationToken) =>
        (await CollectWithEvidenceAsync(cancellationToken)).Snapshot;

    internal async Task<TrustedManifestCollectionResult> CollectWithEvidenceAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var sampled = DateTimeOffset.UtcNow;
        if (!_isEligible()) return Result(sampled, TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ManifestUnavailable, ComponentInspectionReason.NotInstalledService);
        try
        {
            var target = _deriveManifest();
            var root = Path.GetFullPath(target.InstallRoot);
            var full = Path.GetFullPath(target.LoadedAssemblyPath);
            if (!ComponentInspectionSource.Contained(root, full) || !string.Equals(Path.GetFileName(full), "Vantrel.Security.TrustedManifest", StringComparison.Ordinal))
                return Result(sampled, TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ManifestUnavailable, ComponentInspectionReason.OutsideInstallRoot);
            using var timeout = _deadlineSource(cancellationToken);
            var manifestBytes = await ReadBoundedAsync(full, root, TrustedManifestCodec.MaximumBytes, timeout.Token);
            if (!TrustedManifestCodec.TryParse(manifestBytes, out var manifest, out var parseFailure))
                return parseFailure switch
                {
                    TrustedManifestParseFailure.UnsupportedSchema => Result(sampled, TrustedManifestSignatureState.UnsupportedSchema, TrustedManifestInstallationEvaluation.ManifestInvalid),
                    TrustedManifestParseFailure.Unavailable => Result(sampled, TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ManifestUnavailable),
                    _ => Result(sampled, TrustedManifestSignatureState.ManifestMalformed, TrustedManifestInstallationEvaluation.ManifestInvalid)
                };
            var authenticatedManifest = manifest!;
            var manifestSha256 = Convert.ToHexString(SHA256.HashData(manifestBytes));
            if (!TrustedManifestCodec.Verify(authenticatedManifest, TrustedManifestPublicKey.SubjectPublicKeyInfo))
                return Result(sampled, TrustedManifestSignatureState.SignatureInvalid, TrustedManifestInstallationEvaluation.ManifestInvalid);
            foreach (var (component, name) in Components)
            {
                var observed = await HashFixedComponentAsync(Path.Combine(root, name), root, timeout.Token);
                if (observed.Reason is { } reason)
                    return Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ObservationUnavailable, reason);
                if (!string.Equals(observed.Hash, authenticatedManifest.Hashes[component], StringComparison.Ordinal))
                    return Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.ComponentMismatch, null, component);
            }
            return Result(sampled, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.AllMatch, manifestSha256: manifestSha256);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return Result(sampled, TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ObservationUnavailable, ComponentInspectionReason.TimedOut); }
        catch (UnauthorizedAccessException) { return Result(sampled, TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ManifestUnavailable, ComponentInspectionReason.AccessDenied); }
        catch (Win32Exception error) when (error.NativeErrorCode == 5) { return Result(sampled, TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ManifestUnavailable, ComponentInspectionReason.AccessDenied); }
        catch (Win32Exception) { return Result(sampled, TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ManifestUnavailable, ComponentInspectionReason.IoFailure); }
        catch (IOException) { return Result(sampled, TrustedManifestSignatureState.ManifestUnavailable, TrustedManifestInstallationEvaluation.ManifestUnavailable, ComponentInspectionReason.IoFailure); }
    }

    internal async Task<byte[]?> ReadManifestForReleaseProvenanceAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_isEligible()) return null;
        var target = _deriveManifest();
        var root = Path.GetFullPath(target.InstallRoot);
        var path = Path.GetFullPath(target.LoadedAssemblyPath);
        if (!ComponentInspectionSource.Contained(root, path) || !string.Equals(Path.GetFileName(path), "Vantrel.Security.TrustedManifest", StringComparison.Ordinal))
            throw new IOException("Fixed trusted manifest identity rejected.");
        using var timeout = _deadlineSource(cancellationToken);
        return await ReadBoundedAsync(path, root, TrustedManifestCodec.MaximumBytes, timeout.Token);
    }
    private async Task<byte[]> ReadBoundedAsync(string path, string root, int maximum, CancellationToken token)
    {
        using var handle = _operations.Open(path);
        var before = _operations.Metadata(handle);
        Validate(before, root, _operations.FinalPath(handle), maximum);
        await using var stream = _operations.CreateStream(handle);
        using var memory = new MemoryStream();
        var buffer = new byte[65536];
        int read;
        while ((read = await stream.ReadAsync(buffer, token)) != 0)
        {
            if (memory.Length + read > maximum) throw new IOException("Fixed manifest exceeds its bound.");
            memory.Write(buffer, 0, read);
        }
        if (_operations.Metadata(handle) != before) throw new IOException("Fixed manifest changed during read.");
        return memory.ToArray();
    }

    private async Task<(string? Hash, ComponentInspectionReason? Reason)> HashFixedComponentAsync(string path, string root, CancellationToken token)
    {
        try
        {
            using var handle = _operations.Open(path);
            var before = _operations.Metadata(handle);
            Validate(before, root, _operations.FinalPath(handle), checked((int)ComponentInspectionSource.MaximumBytes));
            await using var stream = _operations.CreateStream(handle);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[65536]; int read;
            while ((read = await stream.ReadAsync(buffer, token)) != 0) hash.AppendData(buffer, 0, read);
            return _operations.Metadata(handle) == before ? (Convert.ToHexString(hash.GetHashAndReset()), null) : (null, ComponentInspectionReason.ChangedDuringRead);
        }
        catch (UnauthorizedAccessException) { return (null, ComponentInspectionReason.AccessDenied); }
        catch (Win32Exception error) when (error.NativeErrorCode == 5) { return (null, ComponentInspectionReason.AccessDenied); }
        catch (Win32Exception) { return (null, ComponentInspectionReason.IoFailure); }
        catch (IOException) { return (null, ComponentInspectionReason.IoFailure); }
    }

    private static void Validate(ComponentInspectionNative.Metadata metadata, string root, string finalPath, int maximum)
    {
        if (metadata.IsReparsePoint) throw new IOException("Reparse point rejected.");
        if (metadata.IsDirectory) throw new IOException("Nonregular file rejected.");
        if (metadata.Length > maximum) throw new IOException("File exceeds bound.");
        if (!ComponentInspectionSource.Contained(root, finalPath)) throw new IOException("Final path outside installation root.");
    }

    private static TrustedManifestCollectionResult Result(DateTimeOffset sampled, TrustedManifestSignatureState signature,
        TrustedManifestInstallationEvaluation evaluation, ComponentInspectionReason? reason = null, TrustedManifestComponent? mismatch = null, string? manifestSha256 = null) =>
        new(new(sampled, StatusProtocol.TrustedManifestIntegrityPolicyRevision, signature, evaluation, reason, mismatch), manifestSha256);

    private static readonly (TrustedManifestComponent Component, string FileName)[] Components =
    [
        (TrustedManifestComponent.ServiceExe, "Vantrel.Security.Service.exe"),
        (TrustedManifestComponent.ServiceAssembly, "Vantrel.Security.Service.dll"),
        (TrustedManifestComponent.InfrastructureAssembly, "Vantrel.Security.Infrastructure.dll"),
        (TrustedManifestComponent.CoreAssembly, "Vantrel.Security.Core.dll"),
        (TrustedManifestComponent.Deps, "Vantrel.Security.Service.deps.json"),
        (TrustedManifestComponent.RuntimeConfig, "Vantrel.Security.Service.runtimeconfig.json"),
        (TrustedManifestComponent.EventLogResource, "System.Diagnostics.EventLog.Messages.dll")
    ];
    private static bool IsInstalledScmService() => OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService();
    private static CancellationTokenSource DeadlineSource(CancellationToken token) { var source = CancellationTokenSource.CreateLinkedTokenSource(token); source.CancelAfter(ComponentInspectionSource.Deadline); return source; }
    private static ComponentInspectionTargetIdentity DeriveManifest() => new(Path.Combine(Path.GetDirectoryName(typeof(TrustedManifestIntegritySource).Assembly.Location)!, "Vantrel.Security.TrustedManifest"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Vantrel Security", "Service"));
}

internal static class ReleaseMetadataPublicKey
{
    internal static byte[] SubjectPublicKeyInfo => OfflineReleasePublicKeys.ReleaseMetadataSubjectPublicKeyInfo;
}

internal static class TrustedManifestPublicKey
{
    internal static byte[] SubjectPublicKeyInfo => OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo;
}

public sealed class TrustedManifestIntegrityWorker(TrustedManifestRefreshCoordinator coordinator, ILogger<TrustedManifestIntegrityWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Yield(); await coordinator.RefreshScheduledAsync(stoppingToken); logger.LogInformation("Trusted manifest integrity sampling started");
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(15));
            while (await timer.WaitForNextTickAsync(stoppingToken)) await coordinator.RefreshScheduledAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { logger.LogInformation("Trusted manifest integrity sampling stopped"); }
    }
}
