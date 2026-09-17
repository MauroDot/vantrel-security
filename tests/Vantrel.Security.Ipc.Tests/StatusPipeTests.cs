using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class StatusPipeTests
{
    private static string NewPipeName() => $"Vantrel.Security.Test.{Guid.NewGuid():N}";

    [TestMethod]
    public async Task Worker_returns_status_and_stops_cleanly()
    {
        var pipeName = NewPipeName();
        using var worker = new StatusPipeWorker(new ServiceStatusStore(),
            NullLogger<StatusPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromSeconds(2), true);
            var status = await client.GetStatusAsync(CancellationToken.None);
            Assert.IsNotNull(status);
            Assert.AreEqual(ProtectionState.Unavailable, status.Protection);
            Assert.IsTrue(status.HeartbeatAtUtc >= status.StartedAtUtc);
            Assert.IsTrue(status.UptimeAt(DateTimeOffset.UtcNow) >= TimeSpan.Zero);
        }
        finally { await worker.StopAsync(CancellationToken.None); }
        Assert.IsTrue(worker.ExecuteTask?.IsCompleted);
    }

    [DataTestMethod]
    [DataRow("not json")]
    [DataRow("{\"ProtocolVersion\":2,\"Type\":\"get_status\"}")]
    [DataRow("{\"ProtocolVersion\":1,\"Type\":\"execute\"}")]
    public async Task Worker_rejects_malformed_or_unsupported_requests(string request)
    {
        var pipeName = NewPipeName();
        using var worker = new StatusPipeWorker(new ServiceStatusStore(),
            NullLogger<StatusPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var response = await SendRawAsync(pipeName, Encoding.UTF8.GetBytes(request));
            Assert.IsNull(response);
            var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromSeconds(2), true);
            Assert.IsNotNull(await client.GetStatusAsync(CancellationToken.None));
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    [TestMethod]
    public async Task Worker_rejects_oversized_message()
    {
        var pipeName = NewPipeName();
        using var worker = new StatusPipeWorker(new ServiceStatusStore(),
            NullLogger<StatusPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var response = await SendRawAsync(pipeName, new byte[StatusProtocol.MaximumMessageBytes + 1]);
            Assert.IsNull(response);
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    [TestMethod]
    public async Task Client_handles_disconnection_timeout_and_cancellation()
    {
        var missing = new NamedPipeStatusClient(NewPipeName(), TimeSpan.FromMilliseconds(150), true);
        Assert.IsNull(await missing.GetStatusAsync(CancellationToken.None));
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(async () =>
            await missing.GetStatusAsync(new CancellationToken(canceled: true)));

        var pipeName = NewPipeName();
        await using var idleServer = StatusPipeServer.Create(pipeName);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var accept = idleServer.WaitForConnectionAsync(stop.Token);
        var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromMilliseconds(150), true);
        Assert.IsNull(await client.GetStatusAsync(CancellationToken.None));
        await accept;
    }

    [TestMethod]
    public void Pipe_acl_limits_interactive_client_to_data_rights()
    {
        using var pipe = StatusPipeServer.Create(NewPipeName());
        var security = pipe.GetAccessControl();
        Assert.IsTrue(security.AreAccessRulesProtected);
        var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>().ToArray();
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        var rule = rules.Single(x => x.IdentityReference == interactive);
        Assert.AreEqual(StatusPipeServer.ClientRights, rule.PipeAccessRights);
        Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
        Assert.IsFalse(rules.Any(x => x.IdentityReference ==
            new SecurityIdentifier(WellKnownSidType.WorldSid, null)));
        Assert.IsFalse(rules.Any(x => x.IdentityReference ==
            new SecurityIdentifier(WellKnownSidType.AnonymousSid, null)));
    }

    [TestMethod]
    public void Pipe_refuses_a_second_first_instance()
    {
        var pipeName = NewPipeName();
        using var first = StatusPipeServer.Create(pipeName);
        Assert.ThrowsException<IOException>(() => StatusPipeServer.Create(pipeName));
    }

    private static async Task<byte[]?> SendRawAsync(string pipeName, byte[] request)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await using var pipe = new NamedPipeClientStream(".", pipeName, StatusPipeServer.ClientRights,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            TokenImpersonationLevel.Anonymous, HandleInheritability.None);
        await pipe.ConnectAsync(timeout.Token);
        try
        {
            await pipe.WriteAsync(request, timeout.Token);
            await pipe.WriteAsync(new byte[] { (byte)'\n' }, timeout.Token);
            await pipe.FlushAsync(timeout.Token);
            return await PipeMessages.ReadAsync(pipe, timeout.Token);
        }
        catch (IOException) { return null; } // Early server close also rejects oversized input.
    }
}
