using System.ComponentModel;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting.WindowsServices;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public sealed class ComponentIntegrityStore
{
    private ComponentIntegritySnapshot? _snapshot;
    public ComponentIntegritySnapshot? Snapshot() => Volatile.Read(ref _snapshot);
    public void Update(ComponentIntegritySnapshot snapshot) => Volatile.Write(ref _snapshot, snapshot);
}

/// <summary>Compares only the fixed installed Core DLL to this Service build's compiled reference.</summary>
public sealed class ComponentIntegritySource
{
    private readonly IComponentInspectionHandleOperations _operations;
    private readonly Func<bool> _isEligible;
    private readonly Func<ComponentInspectionTargetIdentity> _deriveTarget;
    private readonly Func<CancellationToken, CancellationTokenSource> _deadlineSource;
    public ComponentIntegritySource() : this(new NativeComponentInspectionHandleOperations(), IsInstalledScmService, DeriveTarget, DeadlineSource) { }
    internal ComponentIntegritySource(IComponentInspectionHandleOperations operations, Func<bool> isEligible, Func<ComponentInspectionTargetIdentity> deriveTarget, Func<CancellationToken, CancellationTokenSource>? deadlineSource = null)
    { _operations = operations; _isEligible = isEligible; _deriveTarget = deriveTarget; _deadlineSource = deadlineSource ?? DeadlineSource; }
    public async Task<ComponentIntegritySnapshot> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); var sampled = DateTimeOffset.UtcNow;
        if (!_isEligible()) return Unavailable(sampled, ComponentInspectionReason.NotInstalledService);
        if (ComponentIntegrityReference.CoreSha256.Length != 64 || !ComponentIntegrityReference.CoreSha256.All(Uri.IsHexDigit)) return new(sampled, StatusProtocol.ComponentIntegrityPolicyRevision, ComponentIntegrityTarget.VantrelCoreAssembly, ComponentHashAlgorithm.Sha256, ComponentIntegrityEvaluation.ReferenceUnavailable, ComponentInspectionReason.IoFailure);
        try
        {
            var target = _deriveTarget(); var root = Path.GetFullPath(target.InstallRoot); var full = Path.GetFullPath(target.LoadedAssemblyPath);
            if (!ComponentInspectionSource.Contained(root, full) || !string.Equals(Path.GetFileName(full), "Vantrel.Security.Core.dll", StringComparison.OrdinalIgnoreCase)) return Unavailable(sampled, ComponentInspectionReason.OutsideInstallRoot);
            using var timeout = _deadlineSource(cancellationToken); using var handle = _operations.Open(full); var before = _operations.Metadata(handle);
            if (before.IsReparsePoint) return Unavailable(sampled, ComponentInspectionReason.ReparsePoint);
            if (before.IsDirectory) return Unavailable(sampled, ComponentInspectionReason.NotRegularFile);
            if (before.Length > ComponentInspectionSource.MaximumBytes) return Unavailable(sampled, ComponentInspectionReason.SizeLimitExceeded);
            if (!ComponentInspectionSource.Contained(root, _operations.FinalPath(handle))) return Unavailable(sampled, ComponentInspectionReason.OutsideInstallRoot);
            await using var stream = _operations.CreateStream(handle); using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = new byte[65536]; int read;
            while ((read = await stream.ReadAsync(buffer, timeout.Token)) != 0) hash.AppendData(buffer, 0, read);
            if (_operations.Metadata(handle) != before) return Unavailable(sampled, ComponentInspectionReason.ChangedDuringRead);
            return new(sampled, StatusProtocol.ComponentIntegrityPolicyRevision, ComponentIntegrityTarget.VantrelCoreAssembly, ComponentHashAlgorithm.Sha256, string.Equals(Convert.ToHexString(hash.GetHashAndReset()), ComponentIntegrityReference.CoreSha256, StringComparison.Ordinal) ? ComponentIntegrityEvaluation.Match : ComponentIntegrityEvaluation.Mismatch, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return Unavailable(sampled, ComponentInspectionReason.TimedOut); }
        catch (UnauthorizedAccessException) { return Unavailable(sampled, ComponentInspectionReason.AccessDenied); }
        catch (Win32Exception error) when (error.NativeErrorCode == 5) { return Unavailable(sampled, ComponentInspectionReason.AccessDenied); }
        catch (Win32Exception) { return Unavailable(sampled, ComponentInspectionReason.IoFailure); }
        catch (IOException) { return Unavailable(sampled, ComponentInspectionReason.IoFailure); }
    }
    private static ComponentIntegritySnapshot Unavailable(DateTimeOffset at, ComponentInspectionReason reason) => new(at, StatusProtocol.ComponentIntegrityPolicyRevision, ComponentIntegrityTarget.VantrelCoreAssembly, ComponentHashAlgorithm.Sha256, ComponentIntegrityEvaluation.ObservationUnavailable, reason);
    private static bool IsInstalledScmService() => OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService();
    private static CancellationTokenSource DeadlineSource(CancellationToken token) { var source = CancellationTokenSource.CreateLinkedTokenSource(token); source.CancelAfter(ComponentInspectionSource.Deadline); return source; }
    private static ComponentInspectionTargetIdentity DeriveTarget() => new(Path.Combine(Path.GetDirectoryName(typeof(ComponentIntegritySource).Assembly.Location)!, "Vantrel.Security.Core.dll"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Vantrel Security", "Service"));
}

public sealed class ComponentIntegrityWorker(ComponentIntegrityStore store, ComponentIntegritySource source, ILogger<ComponentIntegrityWorker> logger) : BackgroundService
{
    private readonly SemaphoreSlim _oneAtATime = new(1, 1);
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Yield(); await SampleAsync(stoppingToken); logger.LogInformation("Component integrity sampling started"); using var timer = new PeriodicTimer(TimeSpan.FromMinutes(15)); while (await timer.WaitForNextTickAsync(stoppingToken)) await SampleAsync(stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { logger.LogInformation("Component integrity sampling stopped"); }
    }
    private async Task SampleAsync(CancellationToken token) { await _oneAtATime.WaitAsync(token); try { store.Update(await source.CollectAsync(token)); } finally { _oneAtATime.Release(); } }
}
