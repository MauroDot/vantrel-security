using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;
using Vantrel.Security.Service;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using System.Text;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class CommandBoundaryTests
{
    private static readonly string[] Ids = Enumerable.Range(0, 80).Select(i => i.ToString("x32")).ToArray();

    [TestMethod]
    public void Only_interactive_callers_are_authorized()
    {
        Assert.IsTrue(CommandCallerAuthorizer.Authorized(CommandCallerClassification.InteractiveUser));
        foreach (var caller in Enum.GetValues<CommandCallerClassification>().Where(value => value != CommandCallerClassification.InteractiveUser))
            Assert.IsFalse(CommandCallerAuthorizer.Authorized(caller));
    }

    [TestMethod]
    public void Token_classification_accepts_interactive_users_and_rejects_noninteractive_identities()
    {
        var interactive = new IdentityReferenceCollection(1) { new SecurityIdentifier(WellKnownSidType.InteractiveSid, null) };
        var standardUser = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        var administrator = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        Assert.AreEqual(CommandCallerClassification.InteractiveUser, CommandCallerAuthorizer.ClassifyIdentity(standardUser, interactive));
        Assert.AreEqual(CommandCallerClassification.InteractiveUser, CommandCallerAuthorizer.ClassifyIdentity(administrator, interactive));
        foreach (var sid in new[] { WellKnownSidType.AnonymousSid, WellKnownSidType.LocalSystemSid, WellKnownSidType.LocalServiceSid, WellKnownSidType.NetworkServiceSid })
            Assert.AreNotEqual(CommandCallerClassification.InteractiveUser, CommandCallerAuthorizer.ClassifyIdentity(new SecurityIdentifier(sid, null), interactive));
        Assert.AreEqual(CommandCallerClassification.NonInteractive, CommandCallerAuthorizer.ClassifyIdentity(standardUser, new IdentityReferenceCollection()));
    }

    [TestMethod]
    public void Command_pipe_uses_kernel_remote_client_rejection()
    {
        Assert.AreEqual(0x00000008u, CommandPipeServer.PipeRejectRemoteClients);
    }

    [TestMethod]
    public void Rejection_limiter_coalesces_then_expires_without_affecting_other_fixed_reasons()
    {
        var now = DateTimeOffset.UtcNow; var limiter = new CommandRejectionLogLimiter(() => now);
        Assert.IsTrue(limiter.ShouldLog("Malformed")); Assert.IsFalse(limiter.ShouldLog("Malformed"));
        Assert.IsTrue(limiter.ShouldLog("Unauthorized")); now = now.AddMinutes(1).AddTicks(1);
        Assert.IsTrue(limiter.ShouldLog("Malformed"));
    }

    [TestMethod]
    public void Registry_deduplicates_rate_limits_expires_and_bounds_state()
    {
        var now = DateTimeOffset.UtcNow; var registry = new CommandRequestRegistry(() => now);
        Assert.AreEqual(CommandResult.Accepted, registry.Admit(Ids[0], false));
        Assert.AreEqual(CommandResult.Duplicate, registry.Admit(Ids[0], false));
        for (var i = 1; i < 12; i++) Assert.AreEqual(CommandResult.Accepted, registry.Admit(Ids[i], false));
        Assert.AreEqual(CommandResult.Rejected, registry.Admit(Ids[12], false));
        now = now.AddMinutes(10).AddTicks(1);
        Assert.AreEqual(CommandResult.Accepted, registry.Admit(Ids[12], false));
    }

    [TestMethod]
    public void Busy_request_is_not_admitted_and_a_new_session_starts_empty()
    {
        var registry = new CommandRequestRegistry(() => DateTimeOffset.UtcNow);
        Assert.AreEqual(CommandResult.AlreadyInProgress, registry.Admit(Ids[0], true));
        Assert.AreEqual(CommandResult.Accepted, registry.Admit(Ids[0], false));
        Assert.AreEqual(CommandResult.Accepted, new CommandRequestRegistry(() => DateTimeOffset.UtcNow).Admit(Ids[0], false));
    }

    [TestMethod]
    public void Reservation_race_does_not_consume_an_admission_slot()
    {
        var registry = new CommandRequestRegistry(() => DateTimeOffset.UtcNow);
        Assert.AreEqual(CommandResult.AlreadyInProgress, registry.AdmitAndReserve(Ids[0], () => false));
        Assert.AreEqual(CommandResult.Accepted, registry.AdmitAndReserve(Ids[0], () => true));
    }

    [TestMethod]
    public void Audit_is_newest_first_and_bounded_to_32_safe_records()
    {
        var now = DateTimeOffset.UtcNow; var audit = new CommandAuditStore(() => now);
        for (var i = 0; i < 40; i++) { now = now.AddSeconds(1); audit.Add(Ids[i], CommandCallerClassification.InteractiveUser, CommandAuditOutcome.Accepted); }
        var values = audit.Snapshot();
        Assert.AreEqual(32, values.Length); Assert.AreEqual(Ids[39], values[0].RequestId); Assert.AreEqual(Ids[8], values[^1].RequestId);
        Assert.IsTrue(values.All(value => value.Caller == CommandCallerClassification.InteractiveUser && CommandProtocol.IsValidRequestId(value.RequestId)));
    }

    [TestMethod]
    public void Public_audit_projection_is_newest_first_limited_to_16_and_excludes_rejections()
    {
        var now = DateTimeOffset.UtcNow; var audit = new CommandAuditStore(() => now);
        audit.Add(Ids[0], CommandCallerClassification.Anonymous, CommandAuditOutcome.Rejected);
        for (var i = 1; i <= 20; i++) { now = now.AddSeconds(1); audit.Add(Ids[i], CommandCallerClassification.InteractiveUser, CommandAuditOutcome.Completed); }
        var snapshot = audit.PublicSnapshot(now.AddMinutes(-1), now);
        Assert.AreEqual(16, snapshot.Entries.Length);
        Assert.IsTrue(snapshot.Entries.All(entry => entry.Command == IntegrityRefreshAuditCommandKind.RefreshTrustedManifestIntegrity &&
            entry.Caller == CommandCallerClassification.InteractiveUser && entry.Outcome == IntegrityRefreshAuditOutcome.Completed));
        Assert.AreEqual(now, snapshot.Entries[0].OccurredAtUtc);
        Assert.AreEqual(now.AddSeconds(-15), snapshot.Entries[^1].OccurredAtUtc);
        Assert.AreEqual(21, audit.Snapshot().Length);
    }

    [TestMethod]
    public void Public_audit_projection_has_no_private_command_or_integrity_fields_and_new_session_is_empty()
    {
        var now = DateTimeOffset.UtcNow; var audit = new CommandAuditStore(() => now);
        audit.Add(Ids[0], CommandCallerClassification.InteractiveUser, CommandAuditOutcome.Completed);
        var bytes = StatusProtocol.CreateIntegrityRefreshAuditResponse(audit.PublicSnapshot(now.AddMinutes(-1), now));
        var text = Encoding.UTF8.GetString(bytes);
        foreach (var forbidden in new[] { "RequestId", "User", "Sid", "Token", "Process", "Path", "Manifest", "Hash", "Exception", "SignatureState", "Evaluation" })
            Assert.IsFalse(text.Contains(forbidden, StringComparison.Ordinal), forbidden);
        Assert.AreEqual(0, new CommandAuditStore(() => now).PublicSnapshot(now, now).Entries.Length);
    }

    [TestMethod]
    public async Task Public_audit_projection_is_immutable_and_safe_during_concurrent_writes()
    {
        var audit = new CommandAuditStore();
        var writes = Enumerable.Range(0, 64).Select(index => Task.Run(() =>
            audit.Add(Ids[index], CommandCallerClassification.InteractiveUser, CommandAuditOutcome.Completed)));
        var reads = Enumerable.Range(0, 64).Select(_ => Task.Run(() =>
        {
            var snapshot = audit.PublicSnapshot(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow);
            Assert.IsTrue(snapshot.Entries.Length <= 16);
            Assert.IsTrue(snapshot.Entries.All(entry => entry.Caller == CommandCallerClassification.InteractiveUser));
        }));
        await Task.WhenAll(writes.Concat(reads));
        var stable = audit.PublicSnapshot(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow);
        Assert.AreEqual(16, stable.Entries.Length);
    }

    [TestMethod]
    public void Trusted_manifest_history_is_newest_first_bounded_and_session_scoped()
    {
        var history = new TrustedManifestIntegrityHistoryStore();
        for (var i = 0; i < 16; i++) history.AppendPublished(new TrustedManifestIntegritySnapshot(
            DateTimeOffset.UtcNow.AddSeconds(i), StatusProtocol.TrustedManifestIntegrityPolicyRevision,
            TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.AllMatch, null, null));
        var entries = history.Snapshot();
        Assert.AreEqual(12, entries.Length);
        Assert.IsTrue(entries.Zip(entries.Skip(1)).All(pair => pair.First.SampledAtUtc >= pair.Second.SampledAtUtc));
        Assert.AreEqual(0, new TrustedManifestIntegrityHistoryStore().Snapshot().Length);
        Assert.IsTrue(typeof(TrustedManifestIntegrityHistoryRecord).GetProperties().Select(property => property.Name).OrderBy(name => name)
            .SequenceEqual(new[] { "Evaluation", "SampledAtUtc", "SignatureState" }));
    }

    [TestMethod]
    public async Task Coordinator_publishes_current_snapshot_before_appending_history_and_preserves_history_on_failure()
    {
        var current = new TrustedManifestIntegrityStore(); var history = new TrustedManifestIntegrityHistoryStore(); var sample = Sample();
        var coordinator = new TrustedManifestRefreshCoordinator(current, history, _ => Task.FromResult(sample), new CommandAuditStore(), new Lifetime(), NullLogger<TrustedManifestRefreshCoordinator>.Instance);
        await coordinator.RefreshScheduledAsync(CancellationToken.None);
        Assert.AreSame(sample, current.Snapshot()); Assert.AreEqual(1, history.Snapshot().Length);
        var failing = new TrustedManifestRefreshCoordinator(current, history, _ => Task.FromException<TrustedManifestIntegritySnapshot>(new IOException()), new CommandAuditStore(), new Lifetime(), NullLogger<TrustedManifestRefreshCoordinator>.Instance);
        await Assert.ThrowsExceptionAsync<IOException>(() => failing.RefreshScheduledAsync(CancellationToken.None));
        Assert.AreSame(sample, current.Snapshot()); Assert.AreEqual(1, history.Snapshot().Length);
    }

    [TestMethod]
    public async Task Manual_refresh_uses_the_same_publication_path_and_shutdown_cancellation_does_not_append_history()
    {
        var current = new TrustedManifestIntegrityStore(); var history = new TrustedManifestIntegrityHistoryStore(); var audit = new CommandAuditStore();
        var sample = Sample(); var stop = new CancellationTokenSource(); var lifetime = new TestLifetime(stop.Token);
        var coordinator = new TrustedManifestRefreshCoordinator(current, history, _ => Task.FromResult(sample), audit, lifetime, NullLogger<TrustedManifestRefreshCoordinator>.Instance);
        Assert.IsTrue(coordinator.TryRefreshCommand(Ids[0], CommandCallerClassification.InteractiveUser));
        for (var i = 0; coordinator.IsBusy && i < 100; i++) await Task.Delay(5);
        Assert.AreSame(sample, current.Snapshot()); Assert.AreEqual(1, history.Snapshot().Length);

        stop.Cancel();
        var cancelled = new TrustedManifestRefreshCoordinator(current, history,
            token => Task.FromCanceled<TrustedManifestIntegritySnapshot>(token), audit, lifetime, NullLogger<TrustedManifestRefreshCoordinator>.Instance);
        Assert.IsTrue(cancelled.TryRefreshCommand(Ids[1], CommandCallerClassification.InteractiveUser));
        for (var i = 0; cancelled.IsBusy && i < 100; i++) await Task.Delay(5);
        Assert.AreSame(sample, current.Snapshot()); Assert.AreEqual(1, history.Snapshot().Length);
    }

    [TestMethod]
    public async Task Trusted_manifest_history_snapshots_are_immutable_and_safe_during_concurrent_publication()
    {
        var history = new TrustedManifestIntegrityHistoryStore();
        var writes = Enumerable.Range(0, 64).Select(index => Task.Run(() => history.AppendPublished(new TrustedManifestIntegritySnapshot(
            DateTimeOffset.UtcNow.AddTicks(index), StatusProtocol.TrustedManifestIntegrityPolicyRevision,
            TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.AllMatch, null, null))));
        var reads = Enumerable.Range(0, 64).Select(_ => Task.Run(() =>
        {
            var snapshot = history.Snapshot();
            Assert.IsTrue(snapshot.Length <= 12);
            Assert.IsTrue(snapshot.Zip(snapshot.Skip(1)).All(pair => pair.First.SampledAtUtc >= pair.Second.SampledAtUtc));
        }));
        await Task.WhenAll(writes.Concat(reads));
        Assert.AreEqual(12, history.Snapshot().Length);
    }

    [TestMethod]
    public async Task Coordinator_reserves_one_slot_and_serializes_command_and_scheduled_refreshes()
    {
        var store = new TrustedManifestIntegrityStore(); var audit = new CommandAuditStore(); var started = new TaskCompletionSource(); var release = new TaskCompletionSource(); var count = 0;
        var coordinator = new TrustedManifestRefreshCoordinator(store, async token => { Interlocked.Increment(ref count); started.SetResult(); await release.Task.WaitAsync(token); return Sample(); }, audit, new Lifetime(), NullLogger<TrustedManifestRefreshCoordinator>.Instance);
        Assert.IsTrue(coordinator.TryRefreshCommand(Ids[0], CommandCallerClassification.InteractiveUser)); await started.Task;
        Assert.IsFalse(coordinator.TryRefreshCommand(Ids[1], CommandCallerClassification.InteractiveUser));
        await coordinator.RefreshScheduledAsync(CancellationToken.None); Assert.AreEqual(1, count);
        release.SetResult(); for (var i = 0; coordinator.IsBusy && i < 100; i++) await Task.Delay(5);
        Assert.AreEqual(1, count); Assert.IsNotNull(store.Snapshot());
    }

    [TestMethod]
    public async Task Failed_or_cancelled_command_refresh_preserves_prior_snapshot_and_releases_slot()
    {
        var prior = Sample(); var store = new TrustedManifestIntegrityStore(); store.Update(prior);
        var stop = new CancellationTokenSource(); var lifetime = new TestLifetime(stop.Token);
        var coordinator = new TrustedManifestRefreshCoordinator(store, _ => Task.FromException<TrustedManifestIntegritySnapshot>(new IOException()), new CommandAuditStore(), lifetime, NullLogger<TrustedManifestRefreshCoordinator>.Instance);
        Assert.IsTrue(coordinator.TryRefreshCommand(Ids[0], CommandCallerClassification.InteractiveUser));
        for (var i = 0; coordinator.IsBusy && i < 100; i++) await Task.Delay(5);
        Assert.AreSame(prior, store.Snapshot()); Assert.IsFalse(coordinator.IsBusy);
        var cancelled = new TrustedManifestRefreshCoordinator(store, token => Task.FromCanceled<TrustedManifestIntegritySnapshot>(token), new CommandAuditStore(), lifetime, NullLogger<TrustedManifestRefreshCoordinator>.Instance);
        stop.Cancel(); Assert.IsTrue(cancelled.TryRefreshCommand(Ids[1], CommandCallerClassification.InteractiveUser));
        for (var i = 0; cancelled.IsBusy && i < 100; i++) await Task.Delay(5);
        Assert.AreSame(prior, store.Snapshot()); Assert.IsFalse(cancelled.IsBusy);
    }

    [TestMethod]
    public async Task Command_pipe_accepts_the_one_fixed_local_interactive_command()
    {
        var pipe = $"Vantrel.Security.Command.Test.{Guid.NewGuid():N}";
        var stop = new CancellationTokenSource(); var store = new TrustedManifestIntegrityStore(); var audit = new CommandAuditStore();
        var coordinator = new TrustedManifestRefreshCoordinator(store, _ => Task.FromResult(Sample()), audit, new TestLifetime(stop.Token), NullLogger<TrustedManifestRefreshCoordinator>.Instance);
        using var worker = new CommandPipeWorker(new CommandRequestRegistry(), audit, coordinator, new CommandRejectionLogLimiter(), NullLogger<CommandPipeWorker>.Instance, pipe);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var client = new Vantrel.Security.Infrastructure.NamedPipeCommandClient(pipe);
            var value = await client.RefreshTrustedManifestIntegrityAsync(Ids[0], CancellationToken.None);
            Assert.IsNotNull(value); Assert.AreEqual(CommandResult.Accepted, value.Result, string.Join(',', audit.Snapshot().Select(entry => entry.Caller)));
        }
        finally { stop.Cancel(); await worker.StopAsync(CancellationToken.None); }
    }

    private static TrustedManifestIntegritySnapshot Sample() => new(DateTimeOffset.UtcNow, StatusProtocol.TrustedManifestIntegrityPolicyRevision, TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.AllMatch, null, null);
    private sealed class Lifetime : IHostApplicationLifetime { public CancellationToken ApplicationStarted => CancellationToken.None; public CancellationToken ApplicationStopping => CancellationToken.None; public CancellationToken ApplicationStopped => CancellationToken.None; public void StopApplication() { } }
    private sealed class TestLifetime(CancellationToken stopping) : IHostApplicationLifetime { public CancellationToken ApplicationStarted => CancellationToken.None; public CancellationToken ApplicationStopping => stopping; public CancellationToken ApplicationStopped => CancellationToken.None; public void StopApplication() { } }
}
