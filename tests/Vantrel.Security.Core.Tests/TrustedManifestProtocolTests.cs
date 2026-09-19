using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class TrustedManifestProtocolTests
{
    private static readonly IReadOnlyDictionary<TrustedManifestComponent, string> Hashes = Enum.GetValues<TrustedManifestComponent>()
        .ToDictionary(component => component, component => new string('A', 63) + ((int)component).ToString());

    [TestMethod]
    public void Canonical_bytes_are_exact_utf8_lf_and_final_newline()
    {
        var bytes = TrustedManifestCodec.CreateCanonicalPayload("0.1.0", Hashes);
        var expected = "schema=vantrel-trusted-manifest-v1\nrelease=0.1.0\nServiceExe=" + Hashes[TrustedManifestComponent.ServiceExe] + "\nServiceAssembly=" + Hashes[TrustedManifestComponent.ServiceAssembly] + "\nInfrastructureAssembly=" + Hashes[TrustedManifestComponent.InfrastructureAssembly] + "\nCoreAssembly=" + Hashes[TrustedManifestComponent.CoreAssembly] + "\nDeps=" + Hashes[TrustedManifestComponent.Deps] + "\nRuntimeConfig=" + Hashes[TrustedManifestComponent.RuntimeConfig] + "\nEventLogResource=" + Hashes[TrustedManifestComponent.EventLogResource] + "\n";
        CollectionAssert.AreEqual(Encoding.UTF8.GetBytes(expected), bytes);
    }

    [TestMethod]
    public void Strict_parser_rejects_bom_crlf_missing_final_newline_reordering_and_lowercase()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var valid = TrustedManifestCodec.CreateFile("0.1.0", Hashes, key);
        Assert.IsTrue(TrustedManifestCodec.TryParse(valid, out _, out _));
        var cases = new[]
        {
            new byte[] { 0xEF, 0xBB, 0xBF }.Concat(valid).ToArray(),
            Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(valid).Replace("\n", "\r\n", StringComparison.Ordinal)),
            valid[..^1],
            Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(valid).Replace("ServiceExe=", "ServiceAssembly=", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(valid).Replace(Hashes[TrustedManifestComponent.CoreAssembly], Hashes[TrustedManifestComponent.CoreAssembly].ToLowerInvariant(), StringComparison.Ordinal))
        };
        foreach (var value in cases) Assert.IsFalse(TrustedManifestCodec.TryParse(value, out _, out _));
    }

    [TestMethod]
    public void Explicit_der_signature_verifies_and_wrong_format_key_or_modified_payload_fails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var file = TrustedManifestCodec.CreateFile("0.1.0", Hashes, key);
        Assert.IsTrue(TrustedManifestCodec.TryParse(file, out var manifest, out _));
        Assert.IsTrue(TrustedManifestCodec.Verify(manifest!, key.ExportSubjectPublicKeyInfo()));
        Assert.IsFalse(key.VerifyData(manifest!.CanonicalPayload, manifest.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        var modified = manifest.CanonicalPayload.ToArray(); modified[0] ^= 1;
        Assert.IsFalse(key.VerifyData(modified, manifest.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        using var wrong = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.IsFalse(TrustedManifestCodec.Verify(manifest, wrong.ExportSubjectPublicKeyInfo()));
    }

    [TestMethod]
    public void Parser_rejects_mutated_base64_duplicate_or_trailing_fields_and_oversize()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var text = Encoding.UTF8.GetString(TrustedManifestCodec.CreateFile("0.1.0", Hashes, key));
        var signature = text["signature=".Length..^1];
        var cases = new[]
        {
            text[..^2] + "!\n",
            text + "signature=" + signature + "\n",
            text + "extra=x\n",
            new string('A', TrustedManifestCodec.MaximumBytes + 1)
        };
        foreach (var value in cases) Assert.IsFalse(TrustedManifestCodec.TryParse(Encoding.UTF8.GetBytes(value), out _, out _));
    }

    [TestMethod]
    public void Seventh_request_and_response_are_strictly_typed_and_parameter_free()
    {
        Assert.AreEqual(StatusProtocol.RequestKind.TrustedManifestIntegrity, StatusProtocol.ReadRequestKind(StatusProtocol.CreateTrustedManifestIntegrityRequest()));
        Assert.AreEqual(StatusProtocol.RequestKind.Invalid, StatusProtocol.ReadRequestKind(Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"get_trusted_manifest_integrity\",\"path\":\"x\"}")));
        var value = new TrustedManifestIntegritySnapshot(DateTimeOffset.UtcNow, StatusProtocol.TrustedManifestIntegrityPolicyRevision,
            TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.AllMatch, null, null);
        Assert.IsTrue(StatusProtocol.TryReadTrustedManifestIntegrityResponse(StatusProtocol.CreateTrustedManifestIntegrityResponse(value), out var read, out _));
        Assert.AreEqual(TrustedManifestInstallationEvaluation.AllMatch, read!.Evaluation);
        var invalid = Encoding.UTF8.GetBytes("{\"ProtocolVersion\":1,\"Type\":\"trusted_manifest_integrity\",\"Integrity\":{\"SampledAtUtc\":\"2026-09-18T00:00:00+00:00\",\"PolicyRevision\":\"trusted-manifest-integrity-v1\",\"SignatureState\":999,\"Evaluation\":0,\"ObservationReason\":null,\"MismatchedComponent\":null}}");
        Assert.IsFalse(StatusProtocol.TryReadTrustedManifestIntegrityResponse(invalid, out _, out var failure));
        Assert.AreEqual(StatusResponseFailure.InvalidTrustedManifestIntegrity, failure);
    }

    [TestMethod]
    public void Presentation_distinguishes_current_recovered_stale_unavailable_and_disconnected()
    {
        var current = new TrustedManifestIntegritySnapshot(DateTimeOffset.UtcNow, StatusProtocol.TrustedManifestIntegrityPolicyRevision,
            TrustedManifestSignatureState.Valid, TrustedManifestInstallationEvaluation.AllMatch, null, null);
        Assert.AreEqual(TrustedManifestIntegrityDisplayState.Current, TrustedManifestIntegrityPresentation.State(current, true, DateTimeOffset.UtcNow));
        Assert.AreEqual(TrustedManifestIntegrityDisplayState.Recovered, TrustedManifestIntegrityPresentation.State(current, true, DateTimeOffset.UtcNow, true));
        Assert.AreEqual(TrustedManifestIntegrityDisplayState.Stale, TrustedManifestIntegrityPresentation.State(current, true, DateTimeOffset.UtcNow.AddMinutes(31)));
        Assert.AreEqual(TrustedManifestIntegrityDisplayState.Unavailable, TrustedManifestIntegrityPresentation.State(null, true, DateTimeOffset.UtcNow));
        Assert.AreEqual(TrustedManifestIntegrityDisplayState.Disconnected, TrustedManifestIntegrityPresentation.State(current, false, DateTimeOffset.UtcNow));
    }
}
