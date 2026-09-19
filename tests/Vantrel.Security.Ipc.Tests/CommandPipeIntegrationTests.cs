using System.IO.Pipes;
using System.ComponentModel;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class CommandPipeIntegrationTests
{
    [TestMethod]
    public async Task Malformed_command_frame_does_no_work_and_next_local_client_is_accepted()
    {
        var pipeName = $"Vantrel.Security.Command.Test.{Guid.NewGuid():N}"; var store = new TrustedManifestIntegrityStore(); var calls = 0;
        using var stop = new CancellationTokenSource(); var audit = new CommandAuditStore();
        var coordinator = new TrustedManifestRefreshCoordinator(store, _ => { Interlocked.Increment(ref calls); return Task.FromResult(Sample()); }, audit, new Lifetime(stop.Token), NullLogger<TrustedManifestRefreshCoordinator>.Instance);
        using var worker = new CommandPipeWorker(new CommandRequestRegistry(), audit, coordinator, new CommandRejectionLogLimiter(), NullLogger<CommandPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            using (var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            { await client.ConnectAsync(); await PipeMessages.WriteAsync(client, "{bad"u8.ToArray(), CancellationToken.None); }
            await Task.Delay(25); Assert.AreEqual(0, calls);
            var valid = await new NamedPipeCommandClient(pipeName).RefreshTrustedManifestIntegrityAsync("0123456789abcdef0123456789abcdef", CancellationToken.None);
            Assert.IsNotNull(valid); Assert.AreEqual(CommandResult.Accepted, valid.Result);
        }
        finally { stop.Cancel(); await worker.StopAsync(CancellationToken.None); }
    }

    [DataTestMethod]
    [DataRow("{bad")]
    [DataRow("{\"ProtocolVersion\":1,\"Command\":\"unknown\",\"RequestId\":\"0123456789abcdef0123456789abcdef\"}")]
    [DataRow("{\"ProtocolVersion\":1,\"Command\":\"refresh_trusted_manifest_integrity\",\"Command\":\"refresh_trusted_manifest_integrity\",\"RequestId\":\"0123456789abcdef0123456789abcdef\"}")]
    [DataRow("{\"ProtocolVersion\":1,\"Command\":\"refresh_trusted_manifest_integrity\",\"RequestId\":\"0123456789abcdef0123456789abcdef\",\"Extra\":true}")]
    [DataRow("{\"ProtocolVersion\":1,\"Command\":\"refresh_trusted_manifest_integrity\",\"RequestId\":\"UPPERCASE\"}")]
    [DataRow("{\"ProtocolVersion\":1,\"Type\":\"get_status\"}")]
    public async Task Invalid_command_frames_are_rejected_without_work_and_worker_recovers(string invalid)
    {
        await using var fixture = await CommandFixture.StartAsync();
        Assert.IsNull(await fixture.SendRawAsync(System.Text.Encoding.UTF8.GetBytes(invalid)));
        Assert.AreEqual(0, fixture.Collections);
        Assert.IsTrue(fixture.WorkerIsAlive, "The rejected client faulted the command worker.");
        var response = await fixture.SendEventuallyAsync("0123456789abcdef0123456789abcdef");
        Assert.AreEqual(CommandResult.Accepted, response.Result);
    }

    [TestMethod]
    public async Task Oversized_and_disconnected_clients_are_isolated_and_next_client_recovers()
    {
        await using var fixture = await CommandFixture.StartAsync();
        Assert.IsNull(await fixture.SendOversizedAsync());
        await fixture.ConnectAndCloseAsync();
        var response = await fixture.SendAsync("1123456789abcdef0123456789abcdef");
        Assert.AreEqual(CommandResult.Accepted, response.Result);
    }

    [TestMethod]
    public async Task Duplicate_request_is_returned_without_second_collection_or_admission()
    {
        await using var fixture = await CommandFixture.StartAsync();
        const string id = "2123456789abcdef0123456789abcdef";
        Assert.AreEqual(CommandResult.Accepted, (await fixture.SendAsync(id)).Result);
        await fixture.WaitForIdleAsync();
        Assert.AreEqual(1, fixture.Collections);
        Assert.AreEqual(CommandResult.Duplicate, (await fixture.SendAsync(id)).Result);
        await Task.Delay(25);
        Assert.AreEqual(1, fixture.Collections);
    }

    [TestMethod]
    public async Task Active_collection_returns_already_in_progress_without_second_collection()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var fixture = await CommandFixture.StartAsync(async token => { started.TrySetResult(); await release.Task.WaitAsync(token); return Sample(); });
        Assert.AreEqual(CommandResult.Accepted, (await fixture.SendAsync("3123456789abcdef0123456789abcdef")).Result);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.AreEqual(CommandResult.AlreadyInProgress, (await fixture.SendEventuallyAsync("4123456789abcdef0123456789abcdef")).Result);
        Assert.AreEqual(1, fixture.Collections);
        release.TrySetResult(); await fixture.WaitForIdleAsync();
    }

    [TestMethod]
    public async Task Admission_limit_rejects_thirteenth_unique_request_without_collection()
    {
        await using var fixture = await CommandFixture.StartAsync();
        for (var value = 0; value < 12; value++)
        {
            var id = value.ToString("x32");
            Assert.AreEqual(CommandResult.Accepted, (await fixture.SendAsync(id)).Result);
            await fixture.WaitForIdleAsync();
        }
        var rejected = await fixture.SendEventuallyAsync("f123456789abcdef0123456789abcdef");
        Assert.AreEqual(CommandResult.Rejected, rejected.Result);
        Assert.AreEqual(CommandFailureReason.RateLimited, rejected.Reason);
        Assert.AreEqual(12, fixture.Collections);
    }

    [TestMethod]
    public async Task Command_response_contains_only_admission_state_and_no_integrity_data()
    {
        await using var fixture = await CommandFixture.StartAsync();
        var bytes = await fixture.SendRawAsync(CommandProtocol.CreateRefreshRequest("5123456789abcdef0123456789abcdef"));
        Assert.IsNotNull(bytes);
        using var document = JsonDocument.Parse(bytes);
        var names = document.RootElement.EnumerateObject().Select(property => property.Name).OrderBy(name => name).ToArray();
        CollectionAssert.AreEqual(new[] { "ProtocolVersion", "Reason", "RequestId", "Result", "TimestampUtc", "Type" }.OrderBy(name => name).ToArray(), names);
        Assert.IsTrue(CommandProtocol.TryReadResponse(bytes, out var response));
        Assert.AreEqual(CommandResult.Accepted, response!.Result);
    }

    [TestMethod]
    public void Command_pipe_preserves_the_protected_interactive_dacl_and_first_instance()
    {
        var pipeName = $"Vantrel.Security.Command.Test.{Guid.NewGuid():N}";
        using var pipe = CommandPipeServer.Create(pipeName);
        var security = pipe.GetAccessControl();
        Assert.IsTrue(security.AreAccessRulesProtected);
        var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToArray();
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        Assert.AreEqual(StatusPipeServer.ClientRights, rules.Single(rule => rule.IdentityReference == interactive).PipeAccessRights);
        Assert.IsFalse(rules.Any(rule => rule.IdentityReference == new SecurityIdentifier(WellKnownSidType.WorldSid, null)));
        Assert.IsFalse(rules.Any(rule => rule.IdentityReference == new SecurityIdentifier(WellKnownSidType.AnonymousSid, null)));
        Assert.IsFalse(rules.Any(rule => rule.IdentityReference == new SecurityIdentifier(WellKnownSidType.NetworkSid, null)));
        Assert.ThrowsException<Win32Exception>(() => CommandPipeServer.Create(pipeName));
    }
    private static TrustedManifestIntegritySnapshot Sample() => new(DateTimeOffset.UtcNow, StatusProtocol.TrustedManifestIntegrityPolicyRevision, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.AllMatch, null, null);
    private sealed class Lifetime(CancellationToken token) : IHostApplicationLifetime { public CancellationToken ApplicationStarted => CancellationToken.None; public CancellationToken ApplicationStopping => token; public CancellationToken ApplicationStopped => CancellationToken.None; public void StopApplication() { } }

    private sealed class CommandFixture : IAsyncDisposable
    {
        private readonly CancellationTokenSource stop = new();
        private readonly TrustedManifestRefreshCoordinator coordinator;
        private readonly CommandPipeWorker worker;
        private int collections;
        private CommandFixture(string pipeName, Func<CancellationToken, Task<TrustedManifestIntegritySnapshot>> collect)
        {
            var audit = new CommandAuditStore();
            coordinator = new TrustedManifestRefreshCoordinator(new TrustedManifestIntegrityStore(), async token => { Interlocked.Increment(ref collections); return await collect(token); }, audit, new Lifetime(stop.Token), NullLogger<TrustedManifestRefreshCoordinator>.Instance);
            worker = new CommandPipeWorker(new CommandRequestRegistry(), audit, coordinator, new CommandRejectionLogLimiter(), NullLogger<CommandPipeWorker>.Instance, pipeName);
            PipeName = pipeName;
        }
        public string PipeName { get; }
        public int Collections => Volatile.Read(ref collections);
        public bool WorkerIsAlive => worker.ExecuteTask is not { IsFaulted: true, IsCanceled: true };
        public static async Task<CommandFixture> StartAsync(Func<CancellationToken, Task<TrustedManifestIntegritySnapshot>>? collect = null)
        {
            var value = new CommandFixture($"Vantrel.Security.Command.Test.{Guid.NewGuid():N}", collect ?? (_ => Task.FromResult(Sample())));
            await value.worker.StartAsync(CancellationToken.None); return value;
        }
        public async Task<CommandResponse> SendAsync(string requestId)
        {
            var response = await new NamedPipeCommandClient(PipeName).RefreshTrustedManifestIntegrityAsync(requestId, CancellationToken.None);
            Assert.IsNotNull(response); return response;
        }
        public async Task<CommandResponse> SendEventuallyAsync(string requestId)
        {
            CommandResponse? response = null;
            for (var attempt = 0; attempt < 5 && response is null; attempt++)
            {
                response = await new NamedPipeCommandClient(PipeName).RefreshTrustedManifestIntegrityAsync(requestId, CancellationToken.None);
                if (response is null) await Task.Delay(50);
            }
            Assert.IsNotNull(response, "The command worker did not recover after the rejected client disconnected.");
            return response;
        }
        public async Task<byte[]?> SendRawAsync(byte[] request)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                System.Security.Principal.TokenImpersonationLevel.Impersonation, System.IO.HandleInheritability.None);
            await pipe.ConnectAsync(timeout.Token);
            try { await PipeMessages.WriteAsync(pipe, request, timeout.Token); return await PipeMessages.ReadAsync(pipe, timeout.Token); }
            catch (IOException) { return null; }
        }
        public async Task<byte[]?> SendOversizedAsync()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                System.Security.Principal.TokenImpersonationLevel.Impersonation, System.IO.HandleInheritability.None);
            await pipe.ConnectAsync(timeout.Token);
            try
            {
                await pipe.WriteAsync(new byte[CommandProtocol.MaximumMessageBytes + 1], timeout.Token);
                await pipe.WriteAsync(new byte[] { (byte)'\n' }, timeout.Token); await pipe.FlushAsync(timeout.Token);
                return await PipeMessages.ReadAsync(pipe, timeout.Token);
            }
            catch (IOException) { return null; }
        }
        public async Task ConnectAndCloseAsync()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                System.Security.Principal.TokenImpersonationLevel.Impersonation, System.IO.HandleInheritability.None);
            await pipe.ConnectAsync(timeout.Token);
        }
        public async Task WaitForIdleAsync()
        {
            for (var attempt = 0; coordinator.IsBusy && attempt < 100; attempt++) await Task.Delay(10);
            Assert.IsFalse(coordinator.IsBusy, "Refresh did not complete.");
        }
        public async ValueTask DisposeAsync()
        {
            stop.Cancel(); await worker.StopAsync(CancellationToken.None); worker.Dispose(); stop.Dispose();
        }
    }
}
