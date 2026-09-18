using Vantrel.Security.Service;
using Vantrel.Security.Core;
using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class ComponentInspectionNativeTests
{
    [TestMethod]
    public void Production_di_registration_resolves_source_and_hosted_worker()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ComponentInspectionStore>();
        services.AddSingleton<ComponentInspectionSource>();
        services.AddHostedService<ComponentInspectionWorker>();
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });
        Assert.IsNotNull(provider.GetRequiredService<ComponentInspectionSource>());
        Assert.IsTrue(provider.GetServices<IHostedService>().Any(worker => worker is ComponentInspectionWorker));
    }

    [TestMethod]
    public async Task All_five_fixed_queries_share_the_single_pipe()
    {
        var pipe = $"Vantrel.Security.Test.{Guid.NewGuid():N}"; var status = new ServiceStatusStore();
        var health = new SystemHealthStore(); var activity = new ActivityStore(status); var scan = new ScanCapabilityStore(); var inspection = new ComponentInspectionStore();
        var sample = new SystemHealthSnapshot(DateTimeOffset.UtcNow, "10.0", 1, 2, 1); health.Update(sample); activity.Update(sample); scan.Update(new ScanCapabilitySource().Collect());
        inspection.Update(new ComponentInspectionSnapshot(DateTimeOffset.UtcNow, StatusProtocol.ComponentInspectionPolicyRevision, ComponentInspectionTarget.VantrelServiceAssembly, ComponentInspectionOutcome.Observed, ComponentInspectionReason.None, ComponentHashAlgorithm.Sha256, new string('A', 64), 1));
        using var worker = new StatusPipeWorker(status, health, activity, scan, inspection, Microsoft.Extensions.Logging.Abstractions.NullLogger<StatusPipeWorker>.Instance, pipe);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var client = new Vantrel.Security.Infrastructure.NamedPipeStatusClient(pipe, TimeSpan.FromSeconds(2), true);
            Assert.IsNotNull(await client.GetStatusAsync(CancellationToken.None)); Assert.IsNotNull(await client.GetSystemHealthAsync(CancellationToken.None)); Assert.IsNotNull(await client.GetActivityAsync(CancellationToken.None)); Assert.IsNotNull(await client.GetScanCapabilityAsync(CancellationToken.None)); Assert.IsNotNull(await client.GetComponentInspectionAsync(CancellationToken.None));
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }
    [TestMethod]
    public async Task Non_scm_execution_returns_unavailable_without_opening_target()
    {
        var operations = new CountingOperations();
        var source = new ComponentInspectionSource(operations, () => false,
            () => new ComponentInspectionTargetIdentity(Path.Combine(Path.GetTempPath(), "Vantrel.Security.Service.dll"), Path.GetTempPath()));
        var result = await source.CollectAsync(CancellationToken.None);
        Assert.AreEqual(ComponentInspectionReason.NotInstalledService, result.Reason);
        Assert.AreEqual(0, operations.OpenCount);
    }

    [TestMethod]
    public async Task Caller_cancellation_propagates_before_opening_target()
    {
        var operations = new CountingOperations();
        var source = new ComponentInspectionSource(operations, () => true,
            () => new ComponentInspectionTargetIdentity(Path.Combine(Path.GetTempPath(), "Vantrel.Security.Service.dll"), Path.GetTempPath()));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => source.CollectAsync(cancelled.Token));
        Assert.AreEqual(0, operations.OpenCount);
    }

    [TestMethod]
    public async Task Policy_deadline_is_incomplete_without_hash()
    {
        var root = Path.Combine(Path.GetTempPath(), $"vantrel-timeout-{Guid.NewGuid():N}"); var path = Path.Combine(root, "Vantrel.Security.Service.dll"); Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllBytesAsync(path, new byte[1]);
            var source = new ComponentInspectionSource(new NativeComponentInspectionHandleOperations(), () => true,
                () => new ComponentInspectionTargetIdentity(path, root), _ => { var c = new CancellationTokenSource(); c.Cancel(); return c; });
            var result = await source.CollectAsync(CancellationToken.None);
            Assert.AreEqual(ComponentInspectionOutcome.Incomplete, result.Outcome); Assert.AreEqual(ComponentInspectionReason.TimedOut, result.Reason); Assert.IsNull(result.Hash);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task Caller_cancellation_takes_precedence_over_deadline_cancellation()
    {
        var operations = new CountingOperations();
        var source = new ComponentInspectionSource(operations, () => true,
            () => new ComponentInspectionTargetIdentity(Path.Combine(Path.GetTempPath(), "Vantrel.Security.Service.dll"), Path.GetTempPath()),
            _ => { var deadline = new CancellationTokenSource(); deadline.Cancel(); return deadline; });
        using var caller = new CancellationTokenSource(); caller.Cancel();
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => source.CollectAsync(caller.Token));
        Assert.AreEqual(0, operations.OpenCount);
    }

    [TestMethod]
    public async Task Store_readers_only_see_complete_immutable_snapshots_during_updates()
    {
        var store = new ComponentInspectionStore();
        var samples = Enumerable.Range(0, 200).Select(i => new ComponentInspectionSnapshot(
            DateTimeOffset.UtcNow.AddTicks(i), StatusProtocol.ComponentInspectionPolicyRevision,
            ComponentInspectionTarget.VantrelServiceAssembly, ComponentInspectionOutcome.Observed,
            ComponentInspectionReason.None, ComponentHashAlgorithm.Sha256, i.ToString("X64"), i)).ToArray();
        var writer = Task.Run(() => { foreach (var sample in samples) store.Update(sample); });
        var readers = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            while (!writer.IsCompleted)
            {
                var snapshot = store.Snapshot();
                if (snapshot is not null)
                {
                    Assert.AreEqual(ComponentInspectionOutcome.Observed, snapshot.Outcome);
                    Assert.AreEqual(ComponentInspectionReason.None, snapshot.Reason);
                    Assert.AreEqual(64, snapshot.Hash!.Length);
                    Assert.AreEqual(snapshot.ObservedByteLength!.Value.ToString("X64"), snapshot.Hash);
                }
            }
        })).ToArray();
        await Task.WhenAll(readers.Append(writer));
        Assert.AreSame(samples[^1], store.Snapshot());
    }

    [TestMethod]
    public async Task Worker_shutdown_completes_without_replacing_a_previous_snapshot()
    {
        var store = new ComponentInspectionStore();
        var prior = new ComponentInspectionSnapshot(DateTimeOffset.UtcNow, StatusProtocol.ComponentInspectionPolicyRevision,
            ComponentInspectionTarget.VantrelServiceAssembly, ComponentInspectionOutcome.Observed,
            ComponentInspectionReason.None, ComponentHashAlgorithm.Sha256, new string('B', 64), 2);
        store.Update(prior);
        var source = new ComponentInspectionSource(new CountingOperations(), () => false,
            () => new ComponentInspectionTargetIdentity(Path.Combine(Path.GetTempPath(), "Vantrel.Security.Service.dll"), Path.GetTempPath()));
        // The ComponentInspectionWorker is separately hosted in production.  Stopping a host before its
        // first collection must be benign; source cancellation propagates and never writes a synthetic result.
        using var componentWorker = new ComponentInspectionWorker(store, source,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ComponentInspectionWorker>.Instance);
        using var stopping = new CancellationTokenSource(); stopping.Cancel();
        await componentWorker.StartAsync(stopping.Token);
        await componentWorker.StopAsync(CancellationToken.None);
        Assert.AreSame(prior, store.Snapshot());
    }

    [TestMethod]
    public async Task Reparse_and_directory_are_rejected_before_stream_creation()
    {
        foreach (var metadata in new[]
        {
            new ComponentInspectionNative.Metadata(true, false, 1, 1, 1),
            new ComponentInspectionNative.Metadata(false, true, 1, 1, 1)
        })
        {
            var operations = new CountingOperations { Value = metadata };
            var source = new ComponentInspectionSource(operations, () => true,
                () => new ComponentInspectionTargetIdentity(Path.Combine(Path.GetTempPath(), "Vantrel.Security.Service.dll"), Path.GetTempPath()));
            var result = await source.CollectAsync(CancellationToken.None);
            Assert.AreEqual(metadata.IsReparsePoint ? ComponentInspectionReason.ReparsePoint : ComponentInspectionReason.NotRegularFile, result.Reason);
            Assert.AreEqual(0, operations.StreamCount);
        }
    }

    [TestMethod]
    public async Task Native_access_and_io_failures_map_to_bounded_reasons()
    {
        foreach (var pair in new[] { (5, ComponentInspectionReason.AccessDenied), (2, ComponentInspectionReason.IoFailure) })
        {
            var operations = new CountingOperations { OpenError = new Win32Exception(pair.Item1) };
            var source = new ComponentInspectionSource(operations, () => true,
                () => new ComponentInspectionTargetIdentity(Path.Combine(Path.GetTempPath(), "Vantrel.Security.Service.dll"), Path.GetTempPath()));
            Assert.AreEqual(pair.Item2, (await source.CollectAsync(CancellationToken.None)).Reason);
        }
    }

    [TestMethod]
    public async Task Over_limit_target_is_rejected_before_stream_creation()
    {
        var operations = new CountingOperations { Value = new ComponentInspectionNative.Metadata(false, false, ComponentInspectionSource.MaximumBytes + 1, 1, 1) };
        var source = new ComponentInspectionSource(operations, () => true,
            () => new ComponentInspectionTargetIdentity(Path.Combine(Path.GetTempPath(), "Vantrel.Security.Service.dll"), Path.GetTempPath()));
        var result = await source.CollectAsync(CancellationToken.None);
        Assert.AreEqual(ComponentInspectionReason.SizeLimitExceeded, result.Reason);
        Assert.AreEqual(0, operations.StreamCount);
    }

    [TestMethod]
    public async Task Exact_sixteen_mebibytes_is_observed()
    {
        var root = Path.Combine(Path.GetTempPath(), $"vantrel-boundary-{Guid.NewGuid():N}");
        var path = Path.Combine(root, "Vantrel.Security.Service.dll"); Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllBytesAsync(path, new byte[ComponentInspectionSource.MaximumBytes]);
            var source = new ComponentInspectionSource(new NativeComponentInspectionHandleOperations(), () => true,
                () => new ComponentInspectionTargetIdentity(path, root));
            var result = await source.CollectAsync(CancellationToken.None);
            Assert.AreEqual(ComponentInspectionOutcome.Observed, result.Outcome);
            Assert.AreEqual(ComponentInspectionSource.MaximumBytes, result.ObservedByteLength);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task Metadata_changes_during_read_are_incomplete()
    {
        var root = Path.Combine(Path.GetTempPath(), $"vantrel-change-{Guid.NewGuid():N}"); var path = Path.Combine(root, "Vantrel.Security.Service.dll"); Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllBytesAsync(path, [1]);
            foreach (var changed in new[] { new ComponentInspectionNative.Metadata(false, false, 1, 2, 1), new ComponentInspectionNative.Metadata(false, false, 2, 1, 1), new ComponentInspectionNative.Metadata(false, false, 1, 1, 2) })
            {
                var initial = new ComponentInspectionNative.Metadata(false, false, 1, 1, 1);
                var ops = new SequenceOperations(path, initial, changed);
                var result = await new ComponentInspectionSource(ops, () => true, () => new ComponentInspectionTargetIdentity(path, root)).CollectAsync(CancellationToken.None);
                Assert.AreEqual(ComponentInspectionReason.ChangedDuringRead, result.Reason);
            }
        }
        finally { Directory.Delete(root, true); }
    }
    [TestMethod]
    public async Task Eligible_fixed_target_produces_observed_sha256_and_exact_length()
    {
        var root = Path.Combine(Path.GetTempPath(), $"vantrel-root-{Guid.NewGuid():N}");
        var path = Path.Combine(root, "Vantrel.Security.Service.dll");
        Directory.CreateDirectory(root);
        try
        {
            var bytes = new byte[] { 1, 2, 3, 4 };
            await File.WriteAllBytesAsync(path, bytes);
            var source = new ComponentInspectionSource(new NativeComponentInspectionHandleOperations(), () => true,
                () => new ComponentInspectionTargetIdentity(path, root));
            var result = await source.CollectAsync(CancellationToken.None);
            Assert.AreEqual(ComponentInspectionOutcome.Observed, result.Outcome);
            Assert.AreEqual(4L, result.ObservedByteLength);
            Assert.AreEqual(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)), result.Hash);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task Wrong_fixed_identity_is_rejected_before_opening()
    {
        var source = new ComponentInspectionSource(new NativeComponentInspectionHandleOperations(), () => true,
            () => new ComponentInspectionTargetIdentity(Path.Combine(Path.GetTempPath(), "other.dll"), Path.GetTempPath()));
        var result = await source.CollectAsync(CancellationToken.None);
        Assert.AreEqual(ComponentInspectionReason.OutsideInstallRoot, result.Reason);
    }

    [TestMethod]
    public void Containment_rejects_sibling_prefix_and_parent_escape()
    {
        var root = Path.Combine(Path.GetTempPath(), "Vantrel", "Service");
        Assert.IsTrue(ComponentInspectionSource.Contained(root, Path.Combine(root, "Vantrel.Security.Service.dll")));
        Assert.IsFalse(ComponentInspectionSource.Contained(root, Path.Combine(Path.GetTempPath(), "Vantrel", "Service-Evil", "x.dll")));
        Assert.IsFalse(ComponentInspectionSource.Contained(root, Path.Combine(root, "..", "x.dll")));
    }

    [TestMethod]
    public void Handle_metadata_and_final_path_are_stable_for_regular_synthetic_file()
    {
        var path = Path.Combine(Path.GetTempPath(), $"vantrel-component-{Guid.NewGuid():N}.bin");
        try
        {
            File.WriteAllBytes(path, [1, 2, 3]);
            using var handle = ComponentInspectionNative.Open(path);
            var before = ComponentInspectionNative.GetMetadata(handle);
            Assert.IsFalse(before.IsReparsePoint); Assert.IsFalse(before.IsDirectory); Assert.AreEqual(3L, before.Length);
            Assert.IsTrue(ComponentInspectionNative.FinalPath(handle).EndsWith(Path.GetFileName(path), StringComparison.OrdinalIgnoreCase));
            Assert.AreEqual(before, ComponentInspectionNative.GetMetadata(handle));
        }
        finally { File.Delete(path); }
    }
}

internal sealed class SequenceOperations(string path, ComponentInspectionNative.Metadata first, ComponentInspectionNative.Metadata second) : IComponentInspectionHandleOperations
{
    private int _metadataCalls;
    public Microsoft.Win32.SafeHandles.SafeFileHandle Open(string _) => ComponentInspectionNative.Open(path);
    public ComponentInspectionNative.Metadata Metadata(Microsoft.Win32.SafeHandles.SafeFileHandle _) => Interlocked.Increment(ref _metadataCalls) == 1 ? first : second;
    public string FinalPath(Microsoft.Win32.SafeHandles.SafeFileHandle h) => ComponentInspectionNative.FinalPath(h);
    public FileStream CreateStream(Microsoft.Win32.SafeHandles.SafeFileHandle h) => new(h, FileAccess.Read, 65536, true);
}

internal sealed class CountingOperations : IComponentInspectionHandleOperations
{
    public int OpenCount;
    public int StreamCount;
    public ComponentInspectionNative.Metadata Value;
    public Exception? OpenError;
    public Microsoft.Win32.SafeHandles.SafeFileHandle Open(string path) { OpenCount++; if (OpenError is not null) throw OpenError; return new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(1), false); }
    public ComponentInspectionNative.Metadata Metadata(Microsoft.Win32.SafeHandles.SafeFileHandle handle) => Value;
    public string FinalPath(Microsoft.Win32.SafeHandles.SafeFileHandle handle) => throw new NotSupportedException();
    public FileStream CreateStream(Microsoft.Win32.SafeHandles.SafeFileHandle handle) { StreamCount++; throw new NotSupportedException(); }
}
