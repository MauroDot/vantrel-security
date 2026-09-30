using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class OfflineUpdateAdministratorTests
{
    [TestMethod]
    public async Task Concurrent_fixed_invocation_returns_already_in_progress_without_second_operation()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var gate = new SemaphoreSlim(1, 1);
        var first = new OfflineUpdateAdministrator(async token =>
        {
            Interlocked.Increment(ref calls); started.TrySetResult(); await release.Task.WaitAsync(token); return UpdateTransactionPhase.Completed;
        });
        var second = new OfflineUpdateAdministrator(_ => { Interlocked.Increment(ref calls); return Task.FromResult(UpdateTransactionPhase.Completed); });
        var running = first.ApplyFixedStagedCandidateAsync(CancellationToken.None);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.AreEqual(OfflineUpdateInvocationResult.AlreadyInProgress, await second.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        Assert.AreEqual(1, calls);
        release.TrySetResult();
        Assert.AreEqual(OfflineUpdateInvocationResult.Completed, await running);
        Assert.AreEqual(OfflineUpdateInvocationResult.Completed, await second.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        Assert.AreEqual(2, calls);
    }

    [TestMethod]
    public async Task Fixed_gate_releases_after_bounded_failure()
    {
        var gate = new SemaphoreSlim(1, 1);
        var failed = new OfflineUpdateAdministrator(_ => Task.FromException<UpdateTransactionPhase>(new IOException()), gate);
        Assert.AreEqual(OfflineUpdateInvocationResult.Failed, await failed.ApplyFixedStagedCandidateAsync(CancellationToken.None));
        var subsequent = new OfflineUpdateAdministrator(_ => Task.FromResult(UpdateTransactionPhase.Completed), gate);
        Assert.AreEqual(OfflineUpdateInvocationResult.Completed, await subsequent.ApplyFixedStagedCandidateAsync(CancellationToken.None));
    }

    [TestMethod]
    public void Fixed_compatibility_identities_remain_closed()
    {
        Assert.AreEqual("VantrelSecurityService", StatusProtocol.ServiceName);
        Assert.AreEqual("Vantrel.Security.Status.v1", StatusProtocol.PipeName);
        Assert.AreEqual("vantrel-security", ReleaseMetadataCodec.Product);
    }
}
