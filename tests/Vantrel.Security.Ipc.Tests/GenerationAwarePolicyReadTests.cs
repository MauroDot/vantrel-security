using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class GenerationAwarePolicyReadTests
{
    [TestMethod]
    public async Task Reads_each_canonical_policy_generation_without_rewriting_durable_bytes()
    {
        using var scope = new Scope();
        var first = new ReleaseIdentity(ReleaseGeneration.V1, 7, new string('A', 64));
        var historical = ReleasePolicyCodec.Serialize(new(first.ReleaseSequence, first.ManifestSha256));
        File.WriteAllBytes(scope.Path, historical);
        var v1 = await scope.Store.ReadPolicyIdentityAsync(CancellationToken.None);
        Assert.AreEqual(ReleasePolicyParseFailure.None, v1.Failure);
        Assert.AreEqual(first, v1.Identity);
        CollectionAssert.AreEqual(historical, File.ReadAllBytes(scope.Path));

        var second = new ReleaseIdentity(ReleaseGeneration.V2, 9, new string('B', 64));
        var generation = GenerationAwareReleasePolicyCodec.Serialize(new(second));
        File.WriteAllBytes(scope.Path, generation);
        var v2 = await scope.Store.ReadPolicyIdentityAsync(CancellationToken.None);
        Assert.AreEqual(ReleasePolicyParseFailure.None, v2.Failure);
        Assert.AreEqual(second, v2.Identity);
        CollectionAssert.AreEqual(generation, File.ReadAllBytes(scope.Path));
    }

    [TestMethod]
    public async Task Missing_policy_is_unavailable_without_creating_policy_storage()
    {
        using var scope = new Scope(createPolicyDirectory: false);
        var result = await scope.Store.ReadPolicyIdentityAsync(CancellationToken.None);
        Assert.AreEqual(ReleasePolicyParseFailure.Unavailable, result.Failure);
        Assert.IsNull(result.Identity);
        Assert.IsFalse(Directory.Exists(System.IO.Path.GetDirectoryName(scope.Path)));
    }

    [TestMethod]
    public async Task Malformed_and_unknown_policy_cannot_supply_a_release_identity()
    {
        using var scope = new Scope();
        foreach (var bytes in new[]
        {
            Array.Empty<byte>(),
            Encoding.ASCII.GetBytes("partial-policy"),
            Encoding.ASCII.GetBytes("{\"schema\":\"vantrel-release-policy-v3\"}\n"),
            Encoding.ASCII.GetBytes("{\"schema\":\"vantrel-release-policy-v2\",\"schema\":\"vantrel-release-policy-v2\"}\n"),
            Encoding.ASCII.GetBytes("{\"schema\":\"vantrel-release-policy-v1\"}\n")
        })
        {
            File.WriteAllBytes(scope.Path, bytes);
            var result = await scope.Store.ReadPolicyIdentityAsync(CancellationToken.None);
            Assert.AreNotEqual(ReleasePolicyParseFailure.None, result.Failure);
            Assert.IsNull(result.Identity);
            CollectionAssert.AreEqual(bytes, File.ReadAllBytes(scope.Path));
        }
    }

    [TestMethod]
    public async Task Policy_leaf_symlink_cannot_supply_an_identity_from_its_canonical_target()
    {
        using var scope = new Scope();
        var target = System.IO.Path.Combine(scope.Root, "outside-policy.json");
        var bytes = GenerationAwareReleasePolicyCodec.Serialize(new(
            new ReleaseIdentity(ReleaseGeneration.V2, 9, new string('B', 64))));
        File.WriteAllBytes(target, bytes);
        try { File.CreateSymbolicLink(scope.Path, target); }
        catch (Exception exception) when (exception.HResult == unchecked((int)0x80070522))
        {
            Assert.Inconclusive("File symlink privilege is unavailable.");
            return;
        }

        Assert.IsTrue((File.GetAttributes(scope.Path) & FileAttributes.ReparsePoint) != 0);
        await Assert.ThrowsExceptionAsync<IOException>(
            () => scope.Store.ReadPolicyIdentityAsync(CancellationToken.None));
        CollectionAssert.AreEqual(bytes, File.ReadAllBytes(target));
    }

    [TestMethod]
    public async Task Malformed_v2_replacement_does_not_reuse_the_previous_v1_identity_or_fall_back()
    {
        using var scope = new Scope();
        var historical = ReleasePolicyCodec.Serialize(new(7, new string('A', 64)));
        File.WriteAllBytes(scope.Path, historical);
        var original = await scope.Store.ReadPolicyIdentityAsync(CancellationToken.None);
        Assert.AreEqual(ReleasePolicyParseFailure.None, original.Failure);
        Assert.IsNotNull(original.Identity);
        Assert.AreEqual(ReleaseGeneration.V1, original.Identity.Generation);

        var canonicalV2 = GenerationAwareReleasePolicyCodec.Serialize(new(
            new ReleaseIdentity(ReleaseGeneration.V2, 9, new string('B', 64))));
        var malformedV2 = canonicalV2[..^1]; // Missing the required final LF.
        var replacement = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(scope.Path)!, "replacement.tmp");
        File.WriteAllBytes(replacement, malformedV2);
        File.Move(replacement, scope.Path, overwrite: true);

        var result = await scope.Store.ReadPolicyIdentityAsync(CancellationToken.None);
        Assert.AreEqual(ReleasePolicyParseFailure.Malformed, result.Failure);
        Assert.IsNull(result.Identity);
        CollectionAssert.AreEqual(malformedV2, File.ReadAllBytes(scope.Path));
    }

    [TestMethod]
    public async Task Semantically_valid_v2_with_noncanonical_field_order_is_rejected_without_rewriting()
    {
        using var scope = new Scope();
        var canonical = GenerationAwareReleasePolicyCodec.Serialize(new(
            new ReleaseIdentity(ReleaseGeneration.V2, 9, new string('B', 64))));
        var text = Encoding.UTF8.GetString(canonical);
        var canonicalPrefix = $"{{\"schema\":\"{GenerationAwareReleasePolicyCodec.Schema}\",\"product\":\"{ReleasePolicyCodec.Product}\",\"architecture\":\"{ReleasePolicyCodec.Architecture}\",";
        Assert.IsTrue(text.StartsWith(canonicalPrefix, StringComparison.Ordinal));
        var noncanonical = Encoding.UTF8.GetBytes(text.Replace(canonicalPrefix,
            $"{{\"schema\":\"{GenerationAwareReleasePolicyCodec.Schema}\",\"architecture\":\"{ReleasePolicyCodec.Architecture}\",\"product\":\"{ReleasePolicyCodec.Product}\",", StringComparison.Ordinal));
        File.WriteAllBytes(scope.Path, noncanonical);

        var result = await scope.Store.ReadPolicyIdentityAsync(CancellationToken.None);
        Assert.AreEqual(ReleasePolicyParseFailure.Malformed, result.Failure);
        Assert.IsNull(result.Identity);
        CollectionAssert.AreEqual(noncanonical, File.ReadAllBytes(scope.Path));
    }

    private sealed class Scope : IDisposable
    {
        private readonly string _root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "vantrel-policy-read-" + Guid.NewGuid().ToString("N"));
        internal Scope(bool createPolicyDirectory = true)
        {
            Directory.CreateDirectory(_root);
            if (createPolicyDirectory) Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            Store = new ReleasePolicyStore(_root, applyAcls: false);
        }
        internal string Path => System.IO.Path.Combine(_root, "ReleasePolicy", ReleasePolicyStore.PolicyFileName);
        internal string Root => _root;
        internal ReleasePolicyStore Store { get; }
        public void Dispose() => Directory.Delete(_root, recursive: true);
    }
}
