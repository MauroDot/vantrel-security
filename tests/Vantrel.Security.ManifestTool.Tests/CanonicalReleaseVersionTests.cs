using System.Text;
using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.ManifestTool;

namespace Vantrel.Security.ManifestTool.Tests;

[TestClass]
public sealed class CanonicalReleaseVersionTests
{
    [TestMethod]
    public void Manifest_tool_uses_the_approved_separate_public_roots()
    {
        Assert.AreEqual("21E21285DD1BE7655F34DB1E75F826B89DD615D69C606BA090B9F0AF560DDBBD",
            Convert.ToHexString(SHA256.HashData(OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo)));
        Assert.AreEqual("1BA6C704BEA16085A39BCECE9600A845223943A0846F961273FCDAAC60FD2782",
            Convert.ToHexString(SHA256.HashData(OfflineReleasePublicKeys.ReleaseMetadataSubjectPublicKeyInfo)));
        CollectionAssert.AreNotEqual(OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo,
            OfflineReleasePublicKeys.ReleaseMetadataSubjectPublicKeyInfo);
    }

    [TestMethod]
    public void Authoritative_component_mapping_is_ordered_and_supplies_the_exact_manifest_hash_set()
    {
        var expected = new[]
        {
            new ServicePayloadComponent(TrustedManifestComponent.ServiceExe, "Vantrel.Security.Service.exe"),
            new ServicePayloadComponent(TrustedManifestComponent.ServiceAssembly, "Vantrel.Security.Service.dll"),
            new ServicePayloadComponent(TrustedManifestComponent.InfrastructureAssembly, "Vantrel.Security.Infrastructure.dll"),
            new ServicePayloadComponent(TrustedManifestComponent.CoreAssembly, "Vantrel.Security.Core.dll"),
            new ServicePayloadComponent(TrustedManifestComponent.Deps, "Vantrel.Security.Service.deps.json"),
            new ServicePayloadComponent(TrustedManifestComponent.RuntimeConfig, "Vantrel.Security.Service.runtimeconfig.json"),
            new ServicePayloadComponent(TrustedManifestComponent.EventLogResource, "System.Diagnostics.EventLog.Messages.dll")
        };
        CollectionAssert.AreEqual(expected, ReleasePayloadVerifier.ServiceComponents.ToArray());
        CollectionAssert.AreEqual(expected.Select(component => component.FileName).ToArray(), ReleasePayloadVerifier.ServiceComponentFileNames.ToArray());
        Assert.IsFalse(ReleasePayloadVerifier.ServiceComponentFileNames is string[]);
        Assert.IsFalse(ReleasePayloadVerifier.ExactFileNames is string[]);

        var hash = new string('A', 64);
        var hashes = ReleasePayloadVerifier.ServiceComponents.ToDictionary(component => component.Component, _ => hash);
        var canonical = Encoding.ASCII.GetString(TrustedManifestCodec.CreateCanonicalPayload(CanonicalReleaseVersion.Default, hashes));
        var expectedCanonical = $"schema=vantrel-trusted-manifest-v1\nrelease=0.1.0\nServiceExe={hash}\nServiceAssembly={hash}\nInfrastructureAssembly={hash}\nCoreAssembly={hash}\nDeps={hash}\nRuntimeConfig={hash}\nEventLogResource={hash}\n";
        Assert.AreEqual(expectedCanonical, canonical);
    }

    [TestMethod]
    public void Exact_release_set_derives_components_then_the_two_signed_artifacts()
    {
        var expected = ReleasePayloadVerifier.ServiceComponents.Select(component => component.FileName)
            .Append("Vantrel.Security.TrustedManifest").Append("Vantrel.Security.ReleaseMetadata").ToArray();
        CollectionAssert.AreEqual(expected, ReleasePayloadVerifier.ExactFileNames.ToArray());
    }
    [DataTestMethod]
    [DataRow("0.1.0")]
    [DataRow("1.2.3-beta.1")]
    [DataRow("12.34.56-rc.2")]
    public void Canonical_versions_are_accepted(string version)
    {
        Assert.IsTrue(CanonicalReleaseVersion.IsValid(version));
        Assert.AreEqual(version, CanonicalReleaseVersion.Resolve(version));
    }

    [TestMethod]
    public void Missing_optional_version_preserves_the_legacy_default()
    {
        Assert.AreEqual("0.1.0", CanonicalReleaseVersion.Default);
        Assert.AreEqual("0.1.0", CanonicalReleaseVersion.Resolve(null));
    }

    [DataTestMethod]
    [DataRow("")]
    [DataRow(" 1.2.3")]
    [DataRow("1.2.3 ")]
    [DataRow("01.2.3")]
    [DataRow("1.02.3")]
    [DataRow("1.2")]
    [DataRow("1.2.3+build")]
    [DataRow("1.2.3-")]
    [DataRow("1.2.3-beta..1")]
    [DataRow("１.2.3")]
    public void Descriptor_incompatible_versions_are_rejected_before_signing(string version)
    {
        Assert.IsFalse(CanonicalReleaseVersion.IsValid(version));
        Assert.ThrowsException<ArgumentException>(() => CanonicalReleaseVersion.Resolve(version));
    }
}
