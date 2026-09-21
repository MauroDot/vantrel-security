using System.Security.AccessControl;
using System.Security.Principal;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed partial class ReleasePolicyStoreTests
{
    private const string HashA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string HashB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    [TestMethod]
    public async Task Controlled_sequence_one_bootstrap_writes_canonical_high_water_once()
    {
        await using var scope = new PolicyScope();
        var store = new ReleasePolicyStore(scope.Root, applyAcls: false);
        Assert.AreEqual(ReleasePolicyDecision.BootstrapAccepted, await store.BootstrapVerifiedSequenceOneAsync(Verified(1, HashA), CancellationToken.None));
        Assert.AreEqual(new ReleasePolicyRecord(1, HashA), store.Snapshot());
        var policyPath = Path.Combine(scope.Root, "ReleasePolicy", ReleasePolicyStore.PolicyFileName);
        Assert.IsTrue(ReleasePolicyCodec.TryParse(await File.ReadAllBytesAsync(policyPath), out var persisted, out _));
        Assert.AreEqual(store.Snapshot(), persisted);
        Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease, await store.BootstrapVerifiedSequenceOneAsync(Verified(1, HashA), CancellationToken.None));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict, await store.BootstrapVerifiedSequenceOneAsync(Verified(1, HashB), CancellationToken.None));
    }

    [TestMethod]
    public async Task Bootstrap_is_closed_to_non_sequence_one_and_post_bootstrap_missing_state()
    {
        await using var scope = new PolicyScope();
        var store = new ReleasePolicyStore(scope.Root, applyAcls: false);
        Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, await store.BootstrapVerifiedSequenceOneAsync(Verified(2, HashA), CancellationToken.None));
        Assert.IsNull(store.Snapshot());
        Assert.AreEqual(ReleasePolicyDecision.BootstrapAccepted, await store.BootstrapVerifiedSequenceOneAsync(Verified(1, HashA), CancellationToken.None));
        File.Delete(Path.Combine(scope.Root, "ReleasePolicy", ReleasePolicyStore.PolicyFileName));
        Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, await store.BootstrapVerifiedSequenceOneAsync(Verified(1, HashA), CancellationToken.None));
    }

    [TestMethod]
    public async Task Higher_equal_conflict_and_rollback_decisions_preserve_or_advance_policy_atomically()
    {
        await using var scope = new PolicyScope();
        var store = new ReleasePolicyStore(scope.Root, applyAcls: false);
        await store.BootstrapVerifiedSequenceOneAsync(Verified(1, HashA), CancellationToken.None);
        Assert.AreEqual(ReleasePolicyDecision.HigherRelease, await store.EvaluateVerifiedAsync(Verified(2, HashB), CancellationToken.None));
        Assert.AreEqual(new ReleasePolicyRecord(1, HashA), store.Snapshot());
        Assert.AreEqual(ReleasePolicyDecision.HigherRelease, await store.CommitVerifiedInstalledReleaseAsync(Verified(2, HashB), CancellationToken.None));
        Assert.AreEqual(new ReleasePolicyRecord(2, HashB), store.Snapshot());
        Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease, await store.CommitVerifiedInstalledReleaseAsync(Verified(2, HashB), CancellationToken.None));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict, await store.CommitVerifiedInstalledReleaseAsync(Verified(2, HashA), CancellationToken.None));
        Assert.AreEqual(ReleasePolicyDecision.RollbackBlocked, await store.CommitVerifiedInstalledReleaseAsync(Verified(1, HashA), CancellationToken.None));
        Assert.AreEqual(new ReleasePolicyRecord(2, HashB), store.Snapshot());
    }

    [TestMethod]
    public async Task Corrupt_state_and_cancellation_fail_closed_without_mutation_and_concurrent_bootstrap_serializes()
    {
        await using var scope = new PolicyScope();
        var store = new ReleasePolicyStore(scope.Root, applyAcls: false);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => store.BootstrapVerifiedSequenceOneAsync(Verified(1, HashA), cancelled.Token));
        Assert.IsNull(store.Snapshot());
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => store.BootstrapVerifiedSequenceOneAsync(Verified(1, HashA), CancellationToken.None)));
        Assert.AreEqual(1, results.Count(value => value == ReleasePolicyDecision.BootstrapAccepted));
        Assert.IsTrue(results.All(value => value is ReleasePolicyDecision.BootstrapAccepted or ReleasePolicyDecision.SameAcceptedRelease));
        var policyPath = Path.Combine(scope.Root, "ReleasePolicy", ReleasePolicyStore.PolicyFileName);
        await File.WriteAllTextAsync(policyPath, "not-json");
        var another = new ReleasePolicyStore(scope.Root, applyAcls: false);
        Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, await another.EvaluateVerifiedAsync(Verified(2, HashB), CancellationToken.None));
        Assert.AreEqual("not-json", await File.ReadAllTextAsync(policyPath));
    }

    [TestMethod]
    public void Store_exposes_no_raw_metadata_or_caller_selected_path_api()
    {
        var methods = typeof(ReleasePolicyStore).GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public);
        Assert.IsFalse(methods.SelectMany(method => method.GetParameters()).Any(parameter => parameter.ParameterType == typeof(ReleaseMetadata) || parameter.ParameterType == typeof(string)));
        Assert.IsTrue(typeof(VerifiedRelease).IsNotPublic);
    }

    private static VerifiedRelease Verified(ulong sequence, string hash) =>
        VerifiedRelease.AfterFullVerification(new ReleaseMetadata(sequence, hash, "test", DateTimeOffset.UnixEpoch, [], []));

    private sealed class PolicyScope : IAsyncDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-release-policy-" + Guid.NewGuid().ToString("N"));
        public ValueTask DisposeAsync()
        {
            if (Directory.Exists(Root))
            {
                var security = new DirectorySecurity();
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(Root).SetAccessControl(security);
                Directory.Delete(Root, recursive: true);
            }
            return ValueTask.CompletedTask;
        }
    }
}