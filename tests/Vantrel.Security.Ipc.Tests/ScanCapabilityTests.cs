using Microsoft.Extensions.Logging.Abstractions;
using System.IO.Pipes;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class ScanCapabilityTests
{
    [TestMethod]
    public void Fixed_source_performs_no_filesystem_operation_and_returns_only_not_enabled_capability()
    {
        // The source has no filesystem dependency, path input, enumerable, stream, or hashing operation.
        var source = new ScanCapabilitySource();
        var snapshot = source.Collect();
        Assert.AreEqual(StatusProtocol.ScanCapabilitySourcePolicyRevision, snapshot.PolicyRevision);
        Assert.AreEqual(ScanCapabilityState.NotEnabled, snapshot.Capability);
        Assert.AreEqual(ScanActivityState.NotRunning, snapshot.FileScanning);
        Assert.AreEqual(ScanTargetAcceptance.None, snapshot.ClientSuppliedTargets);
        Assert.AreEqual(ScheduledScanTargets.NoneConfigured, snapshot.ScheduledTargets);
        Assert.AreEqual(ScanFeatureAvailability.NotAvailable, snapshot.Detection);
        Assert.AreEqual(ScanFeatureAvailability.NotAvailable, snapshot.Quarantine);
        Assert.AreEqual(ScanFeatureAvailability.NotAvailable, snapshot.Remediation);
        Assert.AreEqual(ScanFeatureAvailability.NotAvailable, snapshot.RealTimeProtection);
        Assert.IsTrue(typeof(ScanCapabilitySource).GetFields(
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).Length == 0);
    }

    [TestMethod]
    public async Task All_four_fixed_queries_share_pipe_and_scan_capability_recovers_after_restart()
    {
        var pipeName = $"Vantrel.Security.Test.{Guid.NewGuid():N}";
        var status = new ServiceStatusStore();
        var health = new SystemHealthStore();
        var activity = new ActivityStore(status);
        var scan = new ScanCapabilityStore();
        var sample = new SystemHealthSnapshot(DateTimeOffset.UtcNow, "10.0.1.0", 10, 100, 50,
            WindowsAntivirusHealth.Good, WindowsFirewallHealth.Good);
        health.Update(sample);
        activity.Update(sample);
        scan.Update(new ScanCapabilitySource().Collect());
        var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromSeconds(2), true);
        using (var first = new StatusPipeWorker(status, health, activity, scan,
            NullLogger<StatusPipeWorker>.Instance, pipeName))
        {
            await first.StartAsync(CancellationToken.None);
            try
            {
                Assert.IsNotNull(await client.GetStatusAsync(CancellationToken.None));
                Assert.AreEqual(sample, await client.GetSystemHealthAsync(CancellationToken.None));
                Assert.IsNotNull(await client.GetActivityAsync(CancellationToken.None));
                Assert.AreEqual(ScanCapabilityState.NotEnabled,
                    (await client.GetScanCapabilityAsync(CancellationToken.None))!.Capability);
            }
            finally { await first.StopAsync(CancellationToken.None); }
        }
        Assert.IsNull(await client.GetScanCapabilityAsync(CancellationToken.None));
        var restartedStatus = new ServiceStatusStore();
        var restartedScan = new ScanCapabilityStore();
        restartedScan.Update(new ScanCapabilitySource().Collect());
        using (var second = new StatusPipeWorker(restartedStatus, health, new ActivityStore(restartedStatus),
            restartedScan, NullLogger<StatusPipeWorker>.Instance, pipeName))
        {
            await second.StartAsync(CancellationToken.None);
            try { Assert.IsNotNull(await client.GetScanCapabilityAsync(CancellationToken.None)); }
            finally { await second.StopAsync(CancellationToken.None); }
        }
    }

    [TestMethod]
    public async Task Scan_capability_client_handles_older_server_timeout_and_cancellation()
    {
        var client = new NamedPipeStatusClient($"Vantrel.Security.Test.{Guid.NewGuid():N}",
            TimeSpan.FromMilliseconds(100), true);
        Assert.IsNull(await client.GetScanCapabilityAsync(CancellationToken.None));
        Assert.IsNotNull(client.LastDiagnostic);
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(async () =>
            await client.GetScanCapabilityAsync(new CancellationToken(canceled: true)));
    }

    [TestMethod]
    public async Task Older_server_rejects_scan_capability_without_breaking_existing_queries()
    {
        var pipeName = $"Vantrel.Security.Test.{Guid.NewGuid():N}";
        await using var server = StatusPipeServer.Create(pipeName);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var olderStatus = new ServiceStatusStore();
        var health = new SystemHealthSnapshot(DateTimeOffset.UtcNow, "10.0.1.0", 10, 100, 50);
        var serve = Task.Run(async () =>
        {
            for (var requestNumber = 0; requestNumber < 4; requestNumber++)
            {
                await server.WaitForConnectionAsync(timeout.Token);
                var request = await PipeMessages.ReadAsync(server, timeout.Token);
                Assert.IsNotNull(request);
                var sentResponse = false;
                switch (StatusProtocol.ReadRequestKind(request))
                {
                    case StatusProtocol.RequestKind.Status:
                        await PipeMessages.WriteAsync(server,
                            StatusProtocol.CreateResponse(olderStatus.Snapshot()), timeout.Token);
                        sentResponse = true;
                        break;
                    case StatusProtocol.RequestKind.SystemHealth:
                        await PipeMessages.WriteAsync(server, StatusProtocol.CreateSystemHealthResponse(health), timeout.Token);
                        sentResponse = true;
                        break;
                    case StatusProtocol.RequestKind.Activity:
                        var activity = new ActivityStore(olderStatus);
                        activity.Update(health);
                        await PipeMessages.WriteAsync(server,
                            StatusProtocol.CreateActivityResponse(activity.Snapshot()!), timeout.Token);
                        sentResponse = true;
                        break;
                    default:
                        Assert.AreEqual(StatusProtocol.RequestKind.ScanCapability,
                            StatusProtocol.ReadRequestKind(request));
                        break; // Old service closes the unsupported request without a response.
                }
                // Match the production lifecycle: DisconnectNamedPipe can discard a response the
                // client has not consumed. The client closes after reading a complete frame.
                if (sentResponse) await PipeMessages.ReadAsync(server, timeout.Token);
                server.Disconnect();
            }
        }, timeout.Token);
        var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromSeconds(2), true);
        Assert.IsNull(await client.GetScanCapabilityAsync(timeout.Token));
        Assert.IsNotNull(await client.GetStatusAsync(timeout.Token));
        Assert.AreEqual(health, await client.GetSystemHealthAsync(timeout.Token));
        Assert.IsNotNull(await client.GetActivityAsync(timeout.Token));
        await serve;
    }
}
