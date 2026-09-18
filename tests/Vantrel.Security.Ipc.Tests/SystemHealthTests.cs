using System.IO.Pipes;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class SystemHealthTests
{
    [TestMethod]
    public void Collector_keeps_other_values_when_one_or_more_sources_fail()
    {
        var source = new WindowsSystemHealthSource(
            () => throw new IOException("version unavailable"),
            () => 123,
            () => throw new UnauthorizedAccessException("volume unavailable"));
        var snapshot = source.Collect();
        Assert.IsNull(snapshot.WindowsVersion);
        Assert.AreEqual(123L, snapshot.SystemUptimeSeconds);
        Assert.IsNull(snapshot.SystemVolumeTotalBytes);
        Assert.IsNull(snapshot.SystemVolumeFreeBytes);
        Assert.IsNull(snapshot.AntivirusHealth);
        Assert.IsNull(snapshot.FirewallHealth);
        Assert.IsTrue(snapshot.CollectedAtUtc <= DateTimeOffset.UtcNow);
    }

    [TestMethod]
    public void Collector_rejects_invalid_values_without_losing_valid_ones()
    {
        var source = new WindowsSystemHealthSource(() => "10.0.26100.0", () => -1, () => (100, 101));
        var snapshot = source.Collect();
        Assert.AreEqual("10.0.26100.0", snapshot.WindowsVersion);
        Assert.IsNull(snapshot.SystemUptimeSeconds);
        Assert.IsNull(snapshot.SystemVolumeTotalBytes);
        Assert.IsNull(snapshot.SystemVolumeFreeBytes);
        Assert.IsNull(snapshot.AntivirusHealth);
        Assert.IsNull(snapshot.FirewallHealth);
    }

    [TestMethod]
    public void Collector_includes_antivirus_sample_without_affecting_other_values()
    {
        var source = new WindowsSystemHealthSource(() => "10.0.26100.0", () => 100,
            () => (1000, 500), () => WindowsAntivirusHealth.Good,
            () => WindowsFirewallHealth.Good);
        var snapshot = source.Collect();
        Assert.AreEqual(WindowsAntivirusHealth.Good, snapshot.AntivirusHealth);
        Assert.AreEqual(WindowsFirewallHealth.Good, snapshot.FirewallHealth);
        Assert.AreEqual(500L, snapshot.SystemVolumeFreeBytes);

        var failed = new WindowsSystemHealthSource(() => "10.0.26100.0", () => 100,
            () => (1000, 500), () => throw new InvalidOperationException("not available"));
        Assert.IsNull(failed.Collect().AntivirusHealth);
        Assert.AreEqual("10.0.26100.0", failed.Collect().WindowsVersion);

        var unexpected = new WindowsSystemHealthSource(() => "10.0.26100.0", () => 100,
            () => (1000, 500), () => (WindowsAntivirusHealth)99);
        Assert.IsNull(unexpected.Collect().AntivirusHealth);
        Assert.AreEqual(500L, unexpected.Collect().SystemVolumeFreeBytes);

        var firewallFailure = new WindowsSystemHealthSource(() => "10.0.26100.0", () => 100,
            () => (1000, 500), () => WindowsAntivirusHealth.Good,
            () => throw new InvalidOperationException("firewall unavailable"));
        var partial = firewallFailure.Collect();
        Assert.IsNull(partial.FirewallHealth);
        Assert.AreEqual(WindowsAntivirusHealth.Good, partial.AntivirusHealth);
        Assert.AreEqual(500L, partial.SystemVolumeFreeBytes);

        var badFirewall = new WindowsSystemHealthSource(() => "10.0.26100.0", () => 100,
            () => (1000, 500), () => WindowsAntivirusHealth.Good,
            () => (WindowsFirewallHealth)99);
        Assert.IsNull(badFirewall.Collect().FirewallHealth);
    }

    [TestMethod]
    public async Task Both_request_types_share_pipe_and_reconnect_after_invalid_request()
    {
        var pipeName = $"Vantrel.Security.Test.{Guid.NewGuid():N}";
        var store = new SystemHealthStore();
        var health = new SystemHealthSnapshot(DateTimeOffset.UtcNow, "10.0.26100.0", 123, 1000, 500,
            WindowsAntivirusHealth.Good, WindowsFirewallHealth.Good);
        store.Update(health);
        using var worker = new StatusPipeWorker(new ServiceStatusStore(), store,
            NullLogger<StatusPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromSeconds(2), true);
            var status = await client.GetStatusAsync(CancellationToken.None);
            Assert.IsNotNull(status);
            Assert.AreEqual(ProtectionState.Unavailable, status.Protection);
            Assert.AreEqual(health, await client.GetSystemHealthAsync(CancellationToken.None));
            using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2)))
            await using (var invalid = new NamedPipeClientStream(".", pipeName, StatusPipeServer.ClientRights,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                TokenImpersonationLevel.Anonymous, HandleInheritability.None))
            {
                await invalid.ConnectAsync(timeout.Token);
                await PipeMessages.WriteAsync(invalid, new byte[] { (byte)'?' }, timeout.Token);
                Assert.IsNull(await PipeMessages.ReadAsync(invalid, timeout.Token));
            }
            Assert.IsNotNull(await client.GetStatusAsync(CancellationToken.None));
            Assert.AreEqual(health, await client.GetSystemHealthAsync(CancellationToken.None));
            Assert.IsNull(client.LastDiagnostic);
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    [TestMethod]
    public async Task Health_client_times_out_without_server()
    {
        var client = new NamedPipeStatusClient($"Vantrel.Security.Test.{Guid.NewGuid():N}",
            TimeSpan.FromMilliseconds(100), true);
        Assert.IsNull(await client.GetSystemHealthAsync(CancellationToken.None));
        Assert.IsNotNull(client.LastDiagnostic);
    }

    [TestMethod]
    public async Task Health_client_recovers_when_pipe_worker_restarts()
    {
        var pipeName = $"Vantrel.Security.Test.{Guid.NewGuid():N}";
        var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromMilliseconds(300), true);
        var healthStore = new SystemHealthStore();
        healthStore.Update(new SystemHealthSnapshot(DateTimeOffset.UtcNow, "10.0.1.0", 10, 100, 50));
        using (var first = new StatusPipeWorker(new ServiceStatusStore(), healthStore,
            NullLogger<StatusPipeWorker>.Instance, pipeName))
        {
            await first.StartAsync(CancellationToken.None);
            Assert.IsNotNull(await client.GetSystemHealthAsync(CancellationToken.None));
            await first.StopAsync(CancellationToken.None);
        }
        Assert.IsNull(await client.GetSystemHealthAsync(CancellationToken.None));
        using (var second = new StatusPipeWorker(new ServiceStatusStore(), healthStore,
            NullLogger<StatusPipeWorker>.Instance, pipeName))
        {
            await second.StartAsync(CancellationToken.None);
            Assert.IsNotNull(await client.GetSystemHealthAsync(CancellationToken.None));
            await second.StopAsync(CancellationToken.None);
        }
    }
}
