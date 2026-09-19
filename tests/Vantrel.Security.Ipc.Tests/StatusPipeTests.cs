using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;
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

    [TestMethod]
    public async Task Worker_serves_repeated_status_requests_with_updated_heartbeat()
    {
        var pipeName = NewPipeName();
        var store = new ServiceStatusStore();
        using var worker = new StatusPipeWorker(store, NullLogger<StatusPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromSeconds(2), true);
            var first = await client.GetStatusAsync(CancellationToken.None);
            Assert.IsNotNull(first);
            await Task.Delay(50);
            store.UpdateHeartbeat();
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var current = await client.GetStatusAsync(CancellationToken.None);
                Assert.IsNotNull(current, $"Status request {attempt + 2} failed.");
                Assert.IsTrue(current.HeartbeatAtUtc > first.HeartbeatAtUtc);
            }
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    [TestMethod]
    public async Task Worker_recovers_after_client_closes_without_request()
    {
        var pipeName = NewPipeName();
        using var worker = new StatusPipeWorker(new ServiceStatusStore(),
            NullLogger<StatusPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            await using (var abandoned = new NamedPipeClientStream(".", pipeName,
                StatusPipeServer.ClientRights, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                TokenImpersonationLevel.Anonymous, HandleInheritability.None))
            {
                using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await abandoned.ConnectAsync(connectTimeout.Token);
            }

            var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromSeconds(2), true);
            // The abandoned connection may still be disconnecting when the next connect starts.
            SecurityServiceStatus? recovered = null;
            for (var attempt = 0; attempt < 5 && recovered is null; attempt++)
            {
                recovered = await client.GetStatusAsync(CancellationToken.None);
                if (recovered is null) await Task.Delay(50);
            }
            Assert.IsNotNull(recovered, $"Last diagnostic: {client.LastDiagnostic}; worker completed: {worker.ExecuteTask?.IsCompleted}; worker failure: {worker.ExecuteTask?.Exception}");
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    [TestMethod]
    public async Task Worker_preserves_complete_response_until_slow_client_reads_it()
    {
        var pipeName = NewPipeName();
        using var worker = new StatusPipeWorker(new ServiceStatusStore(),
            NullLogger<StatusPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await using (var slowClient = new NamedPipeClientStream(".", pipeName,
                StatusPipeServer.ClientRights, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                TokenImpersonationLevel.Anonymous, HandleInheritability.None))
            {
                await slowClient.ConnectAsync(timeout.Token);
                await PipeMessages.WriteAsync(slowClient, StatusProtocol.CreateRequest(), timeout.Token);
                await Task.Delay(150, timeout.Token);
                var response = await PipeMessages.ReadAsync(slowClient, timeout.Token);
                Assert.IsNotNull(response, "The server discarded unread response bytes when it disconnected.");
                Assert.IsTrue(StatusProtocol.TryReadResponse(response, out _));
            }

            var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromSeconds(2), true);
            Assert.IsNotNull(await client.GetStatusAsync(CancellationToken.None));
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    [TestMethod]
    public async Task Worker_logs_safe_exception_type_and_read_stage_on_timeout()
    {
        var pipeName = NewPipeName();
        var logger = new WarningLogger();
        using var worker = new StatusPipeWorker(new ServiceStatusStore(), logger, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            await using var idleClient = new NamedPipeClientStream(".", pipeName,
                StatusPipeServer.ClientRights, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                TokenImpersonationLevel.Anonymous, HandleInheritability.None);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await idleClient.ConnectAsync(timeout.Token);
            var warning = await logger.Warning.WaitAsync(timeout.Token);
            StringAssert.Contains(warning, "Status IPC Timeout at ReadRequest");
            StringAssert.Contains(warning, "exception=System.");
            StringAssert.Contains(warning, "HRESULT=");
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    [DataTestMethod]
    [DataRow("not json")]
    [DataRow("{\"ProtocolVersion\":2,\"Type\":\"get_status\"}")]
    [DataRow("{\"ProtocolVersion\":1,\"Type\":\"execute\"}")]
    [DataRow("{\"ProtocolVersion\":1,\"Command\":\"refresh_trusted_manifest_integrity\",\"RequestId\":\"0123456789abcdef0123456789abcdef\"}")]
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
    public async Task Client_reports_incomplete_response_frame_after_reaching_pipe()
    {
        var pipeName = NewPipeName();
        await using var server = StatusPipeServer.Create(pipeName);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serve = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync(timeout.Token);
            Assert.IsNotNull(await PipeMessages.ReadAsync(server, timeout.Token));
            await server.WriteAsync(StatusProtocol.CreateResponse(new ServiceStatusStore().Snapshot()), timeout.Token);
            await server.FlushAsync(timeout.Token);
            await Task.Delay(100, timeout.Token);
            server.Disconnect();
        });

        var client = new NamedPipeStatusClient(pipeName, TimeSpan.FromSeconds(2), true);
        Assert.IsNull(await client.GetStatusAsync(timeout.Token));
        await serve;
        Assert.IsNotNull(client.LastDiagnostic);
        Assert.AreEqual("IncompleteFrame", client.LastDiagnostic.Reason);
        Assert.AreEqual("ReadResponse", client.LastDiagnostic.Stage);
        Assert.AreEqual(pipeName, client.LastDiagnostic.PipeName);
        Assert.IsTrue(client.LastDiagnostic.BytesReceived > 0);
    }

    [TestMethod]
    public void Pipe_acl_limits_interactive_client_to_data_rights()
    {
        using var pipe = StatusPipeServer.Create(NewPipeName());
        var security = pipe.GetAccessControl();
        Assert.IsTrue(security.AreAccessRulesProtected);
        var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>().ToArray();
        var owner = WindowsIdentity.GetCurrent().User;
        Assert.IsNotNull(owner);
        Assert.AreEqual(owner, security.GetOwner(typeof(SecurityIdentifier)));
        Assert.IsTrue(rules.Any(x => x.IdentityReference == owner &&
            x.PipeAccessRights == PipeAccessRights.FullControl && x.AccessControlType == AccessControlType.Allow));
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        var rule = rules.Single(x => x.IdentityReference == interactive);
        Assert.AreEqual(StatusPipeServer.ClientRights, rule.PipeAccessRights);
        Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
        Assert.IsFalse(rules.Any(x => x.IdentityReference ==
            new SecurityIdentifier(WellKnownSidType.WorldSid, null)));
        Assert.IsFalse(rules.Any(x => x.IdentityReference ==
            new SecurityIdentifier(WellKnownSidType.AnonymousSid, null)));
        Assert.IsFalse(rules.Any(x => x.IdentityReference ==
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null)));
    }

    [TestMethod]
    public void Pipe_refuses_a_second_first_instance()
    {
        var pipeName = NewPipeName();
        using var first = StatusPipeServer.Create(pipeName);
        Assert.ThrowsException<IOException>(() => StatusPipeServer.Create(pipeName));
    }

    [TestMethod]
    public async Task Interactive_client_can_open_pipe_without_account_full_control()
    {
        var pipeName = NewPipeName();
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(WindowsIdentity.GetCurrent().User!);
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            StatusPipeServer.ClientRights, AccessControlType.Allow));

        await using var server = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
            4096, 4096, security);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var exchange = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync(timeout.Token);
            var request = await PipeMessages.ReadAsync(server, timeout.Token);
            Assert.IsNotNull(request);
            Assert.IsTrue(StatusProtocol.IsValidRequest(request));
            var status = new ServiceStatusStore().Snapshot();
            await PipeMessages.WriteAsync(server, StatusProtocol.CreateResponse(status), timeout.Token);
        });
        await using var client = new NamedPipeClientStream(".", pipeName, StatusPipeServer.ClientRights,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous, HandleInheritability.None);
        await client.ConnectAsync(timeout.Token);
        await PipeMessages.WriteAsync(client, StatusProtocol.CreateRequest(), timeout.Token);
        var response = await PipeMessages.ReadAsync(client, timeout.Token);
        Assert.IsNotNull(response);
        Assert.IsTrue(StatusProtocol.TryReadResponse(response, out _));
        await exchange;
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

    private sealed class WarningLogger : ILogger<StatusPipeWorker>
    {
        private readonly TaskCompletionSource<string> _warning =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<string> Warning => _warning.Task;
        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning) _warning.TrySetResult(formatter(state, exception));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
