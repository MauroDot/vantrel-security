using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class InstalledManifestDispatchTests
{
    [TestMethod]
    public async Task V2_framing_with_bad_signature_invokes_only_v2_verifier_once()
    {
        using var scope = new Scope();
        scope.WriteV2SignedByUntrustedKey();
        var v1Calls = 0;
        var v2Calls = 0;
        var result = await scope.CreateSource(
            (manifest, key) => { v1Calls++; return TrustedManifestCodec.Verify(manifest, key); },
            (manifest, key) => { v2Calls++; return TrustedManifestV2Codec.Verify(manifest, key); })
            .CollectWithEvidenceAsync(CancellationToken.None);

        Assert.AreEqual(TrustedManifestSignatureState.SignatureInvalid, result.Snapshot.SignatureState);
        Assert.AreEqual(TrustedManifestInstallationEvaluation.ManifestInvalid, result.Snapshot.Evaluation);
        Assert.AreEqual(StatusProtocol.TrustedManifestIntegrityPolicyRevisionV2, result.Snapshot.PolicyRevision);
        Assert.AreEqual(0, v1Calls);
        Assert.AreEqual(1, v2Calls);
    }

    [TestMethod]
    public async Task V1_framing_with_bad_signature_invokes_only_v1_verifier_once()
    {
        using var scope = new Scope();
        scope.WriteV1SignedByUntrustedKey();
        var v1Calls = 0;
        var v2Calls = 0;
        var result = await scope.CreateSource(
            (manifest, key) => { v1Calls++; return TrustedManifestCodec.Verify(manifest, key); },
            (manifest, key) => { v2Calls++; return TrustedManifestV2Codec.Verify(manifest, key); })
            .CollectWithEvidenceAsync(CancellationToken.None);

        Assert.AreEqual(TrustedManifestSignatureState.SignatureInvalid, result.Snapshot.SignatureState);
        Assert.AreEqual(TrustedManifestInstallationEvaluation.ManifestInvalid, result.Snapshot.Evaluation);
        Assert.AreEqual(StatusProtocol.TrustedManifestIntegrityPolicyRevision, result.Snapshot.PolicyRevision);
        Assert.AreEqual(1, v1Calls);
        Assert.AreEqual(0, v2Calls);
    }

    [TestMethod]
    public async Task Unknown_schema_invokes_neither_verifier()
    {
        using var scope = new Scope();
        File.WriteAllText(scope.ManifestPath, "schema=vantrel-trusted-manifest-v3\n");
        var v1Calls = 0;
        var v2Calls = 0;
        var result = await scope.CreateSource(
            (manifest, key) => { v1Calls++; return TrustedManifestCodec.Verify(manifest, key); },
            (manifest, key) => { v2Calls++; return TrustedManifestV2Codec.Verify(manifest, key); })
            .CollectWithEvidenceAsync(CancellationToken.None);

        Assert.AreEqual(TrustedManifestSignatureState.UnsupportedSchema, result.Snapshot.SignatureState);
        Assert.AreEqual(TrustedManifestInstallationEvaluation.ManifestInvalid, result.Snapshot.Evaluation);
        Assert.AreEqual(0, v1Calls);
        Assert.AreEqual(0, v2Calls);
    }

    private sealed class Scope : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), $"vantrel-manifest-dispatch-{Guid.NewGuid():N}");
        private readonly ECDsa _trustedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        internal Scope() => Directory.CreateDirectory(_root);
        internal string ManifestPath => Path.Combine(_root, "Vantrel.Security.TrustedManifest");

        internal TrustedManifestIntegritySource CreateSource(
            Func<TrustedManifest, byte[], bool> verifyV1, Func<TrustedManifestV2, byte[], bool> verifyV2) =>
            new(new NativeComponentInspectionHandleOperations(), () => true,
                () => new ComponentInspectionTargetIdentity(ManifestPath, _root),
                manifestPublicKey: () => _trustedKey.ExportSubjectPublicKeyInfo())
            {
                VerifyV1Signature = verifyV1,
                VerifyV2Signature = verifyV2
            };

        internal void WriteV1SignedByUntrustedKey()
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var hashes = new Dictionary<TrustedManifestComponent, string>
            {
                [TrustedManifestComponent.ServiceExe] = new('A', 64),
                [TrustedManifestComponent.ServiceAssembly] = new('A', 64),
                [TrustedManifestComponent.InfrastructureAssembly] = new('A', 64),
                [TrustedManifestComponent.CoreAssembly] = new('A', 64),
                [TrustedManifestComponent.Deps] = new('A', 64),
                [TrustedManifestComponent.RuntimeConfig] = new('A', 64),
                [TrustedManifestComponent.EventLogResource] = new('A', 64)
            };
            File.WriteAllBytes(ManifestPath, TrustedManifestCodec.CreateFile("0.1.0-beta.1", hashes, signer));
        }

        internal void WriteV2SignedByUntrustedKey()
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            File.WriteAllBytes(ManifestPath, TrustedManifestV2Codec.CreateFile("0.1.0-beta.2", 1,
                [new TrustedManifestV2File("Vantrel.Security.Service.dll", new string('A', 64))], signer));
        }

        public void Dispose()
        {
            _trustedKey.Dispose();
            Directory.Delete(_root, recursive: true);
        }
    }
}
