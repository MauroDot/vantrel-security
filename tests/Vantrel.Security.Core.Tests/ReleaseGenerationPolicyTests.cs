using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class ReleaseGenerationPolicyTests
{
    private static readonly string A = new('A', 64);
    private static readonly string B = new('B', 64);

    [TestMethod]
    public void Historical_v1_policy_strictly_parses_and_projects_to_v1_for_in_memory_decisions()
    {
        var bytes = ReleasePolicyCodec.Serialize(new(7, A));
        Assert.IsTrue(ReleasePolicyCodec.TryParse(bytes, out var historical, out var failure));
        Assert.AreEqual(ReleasePolicyParseFailure.None, failure);
        Assert.IsFalse(GenerationAwareReleasePolicyCodec.TryParse(bytes, out _, out _));

        var projected = new GenerationAwareReleasePolicyRecord(new(ReleaseGeneration.V1,
            historical!.HighestAcceptedReleaseSequence, historical.AcceptedManifestSha256));
        Assert.AreEqual(ReleaseGeneration.V1, projected.Identity.Generation);
        Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease,
            GenerationAwareReleasePolicyCodec.Evaluate(projected, new(ReleaseGeneration.V1, 7, A)));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict,
            GenerationAwareReleasePolicyCodec.Evaluate(projected, new(ReleaseGeneration.V1, 7, B)));
        Assert.AreEqual(ReleasePolicyDecision.TransitionRequiresCoordination,
            GenerationAwareReleasePolicyCodec.Evaluate(projected, new(ReleaseGeneration.V2, 8, B)));
    }

    [TestMethod]
    public void V2_policy_round_trips_canonically_without_reinterpreting_legacy_v1()
    {
        var policy = new GenerationAwareReleasePolicyRecord(new(ReleaseGeneration.V2, ulong.MaxValue, A));
        var bytes = GenerationAwareReleasePolicyCodec.Serialize(policy);
        Assert.IsTrue(GenerationAwareReleasePolicyCodec.TryParse(bytes, out var parsed, out var failure));
        Assert.AreEqual(ReleasePolicyParseFailure.None, failure);
        Assert.AreEqual(policy, parsed);
        Assert.IsFalse(ReleasePolicyCodec.TryParse(bytes, out _, out var oldFailure));
        Assert.AreEqual(ReleasePolicyParseFailure.Malformed, oldFailure);
        Assert.IsFalse(GenerationAwareReleasePolicyCodec.TryParse(
            ReleasePolicyCodec.Serialize(new(1, A)), out _, out _));
    }

    [TestMethod]
    public void V2_policy_rejects_unknown_generation_duplicates_and_noncanonical_values()
    {
        var valid = Encoding.UTF8.GetString(GenerationAwareReleasePolicyCodec.Serialize(new(new(ReleaseGeneration.V2, 1, A))));
        foreach (var text in new[]
        {
            valid.Replace("\"generation\":\"v2\"", "\"generation\":\"v3\""),
            valid.Replace("\"generation\":\"v2\"", "\"generation\":\"V2\""),
            valid.Replace("\"generation\":\"v2\"", "\"generation\":\"v2\",\"generation\":\"v2\""),
            valid.Replace("\"generation\":\"v2\"", "\"generation\":\"v2\",\"extra\":1"),
            valid.Replace("\"highestAcceptedReleaseSequence\":1", "\"highestAcceptedReleaseSequence\":0"),
            valid.Replace("\"highestAcceptedReleaseSequence\":1", "\"highestAcceptedReleaseSequence\":01"),
            valid.Replace(A, A.ToLowerInvariant()),
            valid.Replace("\n", "\r\n"),
            "\uFEFF" + valid,
            valid.TrimEnd('\n'),
            valid.Replace("\"schema\":\"vantrel-release-policy-v2\"", "\"schema\":\"unexpected\"")
        }) Assert.IsFalse(GenerationAwareReleasePolicyCodec.TryParse(Encoding.UTF8.GetBytes(text), out _, out _), text);
    }

    [TestMethod]
    public void Generation_participates_in_sequence_conflict_and_transition_decisions()
    {
        var v1 = new GenerationAwareReleasePolicyRecord(new(ReleaseGeneration.V1, 10, A));
        var v2 = new GenerationAwareReleasePolicyRecord(new(ReleaseGeneration.V2, 10, A));
        Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease, GenerationAwareReleasePolicyCodec.Evaluate(v1, new(ReleaseGeneration.V1, 10, A)));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict, GenerationAwareReleasePolicyCodec.Evaluate(v1, new(ReleaseGeneration.V1, 10, B)));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict, GenerationAwareReleasePolicyCodec.Evaluate(v1, new(ReleaseGeneration.V2, 10, A)));
        Assert.AreEqual(ReleasePolicyDecision.RollbackBlocked, GenerationAwareReleasePolicyCodec.Evaluate(v1, new(ReleaseGeneration.V2, 9, A)));
        Assert.AreEqual(ReleasePolicyDecision.HigherRelease, GenerationAwareReleasePolicyCodec.Evaluate(v1, new(ReleaseGeneration.V1, 11, B)));
        Assert.AreEqual(ReleasePolicyDecision.TransitionRequiresCoordination, GenerationAwareReleasePolicyCodec.Evaluate(v1, new(ReleaseGeneration.V2, 11, B)));
        Assert.AreEqual(ReleasePolicyDecision.GenerationDowngradeBlocked, GenerationAwareReleasePolicyCodec.Evaluate(v2, new(ReleaseGeneration.V1, 11, A)));
        Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, GenerationAwareReleasePolicyCodec.Evaluate(v2, new((ReleaseGeneration)99, 11, A)));
    }

    [TestMethod]
    public void V2_integrity_status_uses_explicit_revision_and_runtime_inventory_mismatch()
    {
        var mismatch = new TrustedManifestIntegritySnapshot(DateTimeOffset.UtcNow,
            StatusProtocol.TrustedManifestIntegrityPolicyRevisionV2, TrustedManifestSignatureState.Valid,
            TrustedManifestInstallationEvaluation.ComponentMismatch, null, TrustedManifestComponent.RuntimeInventory);
        Assert.IsTrue(StatusProtocol.TryReadTrustedManifestIntegrityResponse(
            StatusProtocol.CreateTrustedManifestIntegrityResponse(mismatch), out var parsed, out _));
        Assert.AreEqual(mismatch, parsed);
        var v1Mislabel = mismatch with { PolicyRevision = StatusProtocol.TrustedManifestIntegrityPolicyRevision };
        Assert.IsFalse(StatusProtocol.TryReadTrustedManifestIntegrityResponse(
            StatusProtocol.CreateTrustedManifestIntegrityResponse(v1Mislabel), out _, out _));
        var v2MetadataFailure = mismatch with { Evaluation = TrustedManifestInstallationEvaluation.ManifestInvalid, MismatchedComponent = null };
        Assert.IsTrue(StatusProtocol.TryReadTrustedManifestIntegrityResponse(
            StatusProtocol.CreateTrustedManifestIntegrityResponse(v2MetadataFailure), out _, out _));
    }
}
