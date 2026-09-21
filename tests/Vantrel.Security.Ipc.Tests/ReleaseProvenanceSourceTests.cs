using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class ReleaseProvenanceSourceTests
{
    [TestMethod]
    public async Task Non_scm_provenance_evaluation_does_not_open_metadata_or_mutate_policy()
    {
        var operations = new CountingOperations();
        var root = Path.Combine(Path.GetTempPath(), "vantrel-provenance-" + Guid.NewGuid().ToString("N"));
        try
        {
            var policy = new ReleasePolicyStore(root, applyAcls: false);
            var manifest = new TrustedManifestIntegritySource(operations, () => false,
                () => new ComponentInspectionTargetIdentity(Path.Combine(root, "Vantrel.Security.TrustedManifest"), root));
            var source = new ReleaseProvenanceSource(operations, () => false,
                () => new ComponentInspectionTargetIdentity(Path.Combine(root, "Vantrel.Security.ReleaseMetadata"), root), null, manifest, policy);
            var snapshot = await source.CollectAsync(CancellationToken.None);
            Assert.AreEqual(ReleaseMetadataSignatureState.MetadataUnavailable, snapshot.MetadataSignatureState);
            Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, snapshot.PolicyDecision);
            Assert.AreEqual(0, operations.OpenCount);
            Assert.IsNull(policy.Snapshot());
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [TestMethod]
    public void Verified_release_capability_has_no_public_constructor_or_raw_store_input()
    {
        Assert.AreEqual(0, typeof(VerifiedRelease).GetConstructors(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public).Length);
        Assert.IsFalse(typeof(ReleasePolicyStore).GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public)
            .SelectMany(method => method.GetParameters()).Any(parameter => parameter.ParameterType == typeof(ReleaseMetadata)));
    }
}