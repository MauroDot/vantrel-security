using System.IO.Pipes;
using Microsoft.Extensions.Logging.Abstractions;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class ActivityPipeTests
{
    [TestMethod]
    public async Task All_three_fixed_requests_share_pipe_and_activity_recovers_after_restart()
    {
        var name = NewPipeName();
        var client = new NamedPipeStatusClient(name, TimeSpan.FromSeconds(2), true);
        var status = new ServiceStatusStore();
        var healthStore = new SystemHealthStore();
        var activity = new ActivityStore(status);
        var firstSample = Sample(DateTimeOffset.UtcNow, WindowsAntivirusHealth.Good);
        healthStore.Update(firstSample);
        activity.Update(firstSample);
        using (var first = new StatusPipeWorker(status, healthStore, activity,
            NullLogger<StatusPipeWorker>.Instance, name))
        {
            await first.StartAsync(CancellationToken.None);
            try
            {
                Assert.AreEqual(ProtectionState.Unavailable,
                    (await client.GetStatusAsync(CancellationToken.None))!.Protection);
                Assert.AreEqual(firstSample, await client.GetSystemHealthAsync(CancellationToken.None));
                Assert.AreEqual(firstSample.CollectedAtUtc,
                    (await client.GetActivityAsync(CancellationToken.None))!.SampledThroughUtc);
                Assert.IsNull(client.LastDiagnostic);
            }
            finally { await first.StopAsync(CancellationToken.None); }
        }
        Assert.IsNull(await client.GetActivityAsync(CancellationToken.None));
        var restartedStatus = new ServiceStatusStore();
        var restartedActivity = new ActivityStore(restartedStatus);
        var newSample = Sample(DateTimeOffset.UtcNow, WindowsAntivirusHealth.Poor);
        restartedActivity.Update(newSample);
        using (var second = new StatusPipeWorker(restartedStatus, healthStore, restartedActivity,
            NullLogger<StatusPipeWorker>.Instance, name))
        {
            await second.StartAsync(CancellationToken.None);
            try
            {
                var recovered = await client.GetActivityAsync(CancellationToken.None);
                Assert.IsNotNull(recovered);
                Assert.AreEqual(2, recovered.Entries.Length);
                Assert.IsTrue(recovered.Entries.All(entry => entry.IsInitial));
                Assert.AreEqual(newSample.CollectedAtUtc, recovered.SampledThroughUtc);
            }
            finally { await second.StopAsync(CancellationToken.None); }
        }
    }

    [TestMethod]
    public async Task Older_server_rejects_activity_without_breaking_status_or_health()
    {
        var name = NewPipeName();
        await using var server = StatusPipeServer.Create(name);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var health = Sample(DateTimeOffset.UtcNow, WindowsAntivirusHealth.Good);
        var serve = Task.Run(async () =>
        {
            for (var index = 0; index < 3; index++)
            {
                await server.WaitForConnectionAsync(timeout.Token);
                var request = await PipeMessages.ReadAsync(server, timeout.Token);
                Assert.IsNotNull(request);
                if (StatusProtocol.ReadRequestKind(request) == StatusProtocol.RequestKind.Status)
                    await PipeMessages.WriteAsync(server, StatusProtocol.CreateResponse(
                        new ServiceStatusStore().Snapshot()), timeout.Token);
                else if (StatusProtocol.ReadRequestKind(request) == StatusProtocol.RequestKind.SystemHealth)
                    await PipeMessages.WriteAsync(server, StatusProtocol.CreateSystemHealthResponse(health),
                        timeout.Token);
                else Assert.AreEqual(StatusProtocol.RequestKind.Activity,
                    StatusProtocol.ReadRequestKind(request));
                if (index != 0) // Activity request is first; older service closes without a response.
                {
                    var trailing = new byte[1];
                    Assert.AreEqual(0, await server.ReadAsync(trailing, timeout.Token));
                }
                server.Disconnect();
            }
        }, timeout.Token);
        var client = new NamedPipeStatusClient(name, TimeSpan.FromSeconds(2), true);
        Assert.IsNull(await client.GetActivityAsync(timeout.Token));
        Assert.IsNotNull(await client.GetStatusAsync(timeout.Token));
        Assert.AreEqual(health, await client.GetSystemHealthAsync(timeout.Token));
        await serve;
    }

    [TestMethod]
    public async Task Activity_client_obeys_deadline_and_cancellation()
    {
        var client = new NamedPipeStatusClient(NewPipeName(), TimeSpan.FromMilliseconds(150), true);
        Assert.IsNull(await client.GetActivityAsync(CancellationToken.None));
        Assert.IsNotNull(client.LastDiagnostic);
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(async () =>
            await client.GetActivityAsync(new CancellationToken(canceled: true)));
    }

    private static string NewPipeName() => $"Vantrel.Security.Test.{Guid.NewGuid():N}";

    private static SystemHealthSnapshot Sample(DateTimeOffset time, WindowsAntivirusHealth antivirus) =>
        new(time, "10.0.1.0", 10, 100, 50, antivirus, WindowsFirewallHealth.Good);
}
