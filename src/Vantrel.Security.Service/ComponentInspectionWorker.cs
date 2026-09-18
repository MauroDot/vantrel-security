using System.Security.Cryptography;
using System.ComponentModel;
using Microsoft.Extensions.Hosting.WindowsServices;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public sealed class ComponentInspectionStore
{
    private ComponentInspectionSnapshot? _snapshot;
    public ComponentInspectionSnapshot? Snapshot() => Volatile.Read(ref _snapshot);
    public void Update(ComponentInspectionSnapshot snapshot) => Volatile.Write(ref _snapshot, snapshot);
}

/// <summary>Inspects one internally derived loaded assembly. It never enumerates or accepts a path.</summary>
public sealed class ComponentInspectionSource
{
    public const long MaximumBytes = 16 * 1024 * 1024;
    public static readonly TimeSpan Deadline = TimeSpan.FromSeconds(5);
    private readonly IComponentInspectionHandleOperations _operations;
    private readonly Func<bool> _isEligible;
    private readonly Func<ComponentInspectionTargetIdentity> _deriveTarget;
    private readonly Func<CancellationToken, CancellationTokenSource> _deadlineSource;
    public ComponentInspectionSource() : this(new NativeComponentInspectionHandleOperations(), IsInstalledScmService, DeriveTarget, ProductionDeadlineSource) { }
    internal ComponentInspectionSource(IComponentInspectionHandleOperations operations, Func<bool> isEligible,
        Func<ComponentInspectionTargetIdentity> deriveTarget, Func<CancellationToken, CancellationTokenSource>? deadlineSource = null)
    {
        _operations = operations;
        _isEligible = isEligible;
        _deriveTarget = deriveTarget;
        _deadlineSource = deadlineSource ?? ProductionDeadlineSource;
    }

    public async Task<ComponentInspectionSnapshot> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var sampled = DateTimeOffset.UtcNow;
        if (!_isEligible()) return Failed(sampled, ComponentInspectionOutcome.Unavailable, ComponentInspectionReason.NotInstalledService);
        try
        {
            var target = _deriveTarget();
            var root = Path.GetFullPath(target.InstallRoot);
            var full = Path.GetFullPath(target.LoadedAssemblyPath);
            if (!Contained(root, full) || !string.Equals(Path.GetFileName(full), "Vantrel.Security.Service.dll", StringComparison.OrdinalIgnoreCase)) return Failed(sampled, ComponentInspectionOutcome.Unavailable, ComponentInspectionReason.OutsideInstallRoot);
            using var timeout = _deadlineSource(cancellationToken);
            using var handle = _operations.Open(full);
            var initial = _operations.Metadata(handle);
            if (initial.IsReparsePoint) return Failed(sampled, ComponentInspectionOutcome.Unavailable, ComponentInspectionReason.ReparsePoint);
            if (initial.IsDirectory) return Failed(sampled, ComponentInspectionOutcome.Unavailable, ComponentInspectionReason.NotRegularFile);
            if (initial.Length > MaximumBytes) return Failed(sampled, ComponentInspectionOutcome.Incomplete, ComponentInspectionReason.SizeLimitExceeded);
            if (!Contained(root, _operations.FinalPath(handle))) return Failed(sampled, ComponentInspectionOutcome.Unavailable, ComponentInspectionReason.OutsideInstallRoot);
            await using var stream = _operations.CreateStream(handle);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[65536]; int read;
            while ((read = await stream.ReadAsync(buffer, timeout.Token)) != 0) hash.AppendData(buffer, 0, read);
            if (_operations.Metadata(handle) != initial) return Failed(sampled, ComponentInspectionOutcome.Incomplete, ComponentInspectionReason.ChangedDuringRead);
            return new(sampled, StatusProtocol.ComponentInspectionPolicyRevision, ComponentInspectionTarget.VantrelServiceAssembly, ComponentInspectionOutcome.Observed, ComponentInspectionReason.None, ComponentHashAlgorithm.Sha256, Convert.ToHexString(hash.GetHashAndReset()), initial.Length);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return Failed(sampled, ComponentInspectionOutcome.Incomplete, ComponentInspectionReason.TimedOut); }
        catch (UnauthorizedAccessException) { return Failed(sampled, ComponentInspectionOutcome.Unavailable, ComponentInspectionReason.AccessDenied); }
        catch (Win32Exception error) when (error.NativeErrorCode == 5) { return Failed(sampled, ComponentInspectionOutcome.Unavailable, ComponentInspectionReason.AccessDenied); }
        catch (Win32Exception) { return Failed(sampled, ComponentInspectionOutcome.Unavailable, ComponentInspectionReason.IoFailure); }
        catch (IOException) { return Failed(sampled, ComponentInspectionOutcome.Unavailable, ComponentInspectionReason.IoFailure); }
    }
    private static ComponentInspectionSnapshot Failed(DateTimeOffset sampled, ComponentInspectionOutcome outcome, ComponentInspectionReason reason) => new(sampled, StatusProtocol.ComponentInspectionPolicyRevision, ComponentInspectionTarget.VantrelServiceAssembly, outcome, reason, null, null, null);
    internal static bool Contained(string root, string path)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
        return relative.Length != 0 && !Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }
    private static bool IsInstalledScmService() => OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService();
    private static CancellationTokenSource ProductionDeadlineSource(CancellationToken token) { var source = CancellationTokenSource.CreateLinkedTokenSource(token); source.CancelAfter(Deadline); return source; }
    private static ComponentInspectionTargetIdentity DeriveTarget() => new(typeof(ComponentInspectionSource).Assembly.Location,
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Vantrel Security", "Service"));
}

/// <summary>Internal test value representing production's fixed loaded-assembly derivation.</summary>
internal sealed record ComponentInspectionTargetIdentity(string LoadedAssemblyPath, string InstallRoot);

public sealed class ComponentInspectionWorker(ComponentInspectionStore store, ComponentInspectionSource source, ILogger<ComponentInspectionWorker> logger) : BackgroundService
{
    private readonly SemaphoreSlim _oneAtATime = new(1, 1);
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Yield();
            await SampleAsync(stoppingToken);
            logger.LogInformation("Component inspection sampling started");
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(15));
            while (await timer.WaitForNextTickAsync(stoppingToken)) await SampleAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { logger.LogInformation("Component inspection sampling stopped"); }
    }
    private async Task SampleAsync(CancellationToken token) { await _oneAtATime.WaitAsync(token); try { store.Update(await source.CollectAsync(token)); } finally { _oneAtATime.Release(); } }
}
