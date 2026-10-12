using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class Task078GenerationPolicyMatrixTests
{
    private static readonly string HashA = new('A', 64);
    private static readonly string HashB = new('B', 64);

    [TestMethod]
    public void Historical_v1_policy_projects_to_v1_without_changing_its_format()
    {
        var historicalBytes = ReleasePolicyCodec.Serialize(new ReleasePolicyRecord(10, HashA));
        var originalBytes = historicalBytes.ToArray();

        Assert.IsTrue(ReleasePolicyCodec.TryParse(historicalBytes, out var historical, out var failure));
        Assert.AreEqual(ReleasePolicyParseFailure.None, failure);
        Assert.IsFalse(GenerationAwareReleasePolicyCodec.TryParse(historicalBytes, out _, out _));
        var projected = new GenerationAwareReleasePolicyRecord(new ReleaseIdentity(ReleaseGeneration.V1,
            historical!.HighestAcceptedReleaseSequence, historical.AcceptedManifestSha256));

        Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease,
            GenerationAwareReleasePolicyCodec.Evaluate(projected, Candidate(ReleaseGeneration.V1, 10, HashA)));
        Assert.AreEqual(ReleasePolicyDecision.HigherRelease,
            GenerationAwareReleasePolicyCodec.Evaluate(projected, Candidate(ReleaseGeneration.V1, 11, HashB)));
        Assert.AreEqual(ReleasePolicyDecision.TransitionRequiresCoordination,
            GenerationAwareReleasePolicyCodec.Evaluate(projected, Candidate(ReleaseGeneration.V2, 11, HashB)));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict,
            GenerationAwareReleasePolicyCodec.Evaluate(projected, Candidate(ReleaseGeneration.V2, 10, HashA)));
        CollectionAssert.AreEqual(originalBytes, historicalBytes);
        CollectionAssert.AreEqual(originalBytes, ReleasePolicyCodec.Serialize(historical));
    }

    [TestMethod]
    public void Policy_v2_round_trips_each_explicit_generation_and_compares_full_identity()
    {
        foreach (var generation in new[] { ReleaseGeneration.V1, ReleaseGeneration.V2 })
        {
            var accepted = new GenerationAwareReleasePolicyRecord(Candidate(generation, 10, HashA));
            var bytes = GenerationAwareReleasePolicyCodec.Serialize(accepted);
            var text = Encoding.UTF8.GetString(bytes);
            StringAssert.Contains(text, $"\"generation\":\"{(generation == ReleaseGeneration.V1 ? "v1" : "v2")}\"");
            Assert.IsFalse(ReleasePolicyCodec.TryParse(bytes, out _, out _));
            Assert.IsTrue(GenerationAwareReleasePolicyCodec.TryParse(bytes, out var parsed, out var failure));
            Assert.AreEqual(ReleasePolicyParseFailure.None, failure);
            Assert.AreEqual(accepted, parsed);
            CollectionAssert.AreEqual(bytes, GenerationAwareReleasePolicyCodec.Serialize(parsed!));

            Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease,
                GenerationAwareReleasePolicyCodec.Evaluate(parsed, Candidate(generation, 10, HashA)));
            Assert.AreEqual(ReleasePolicyDecision.SequenceConflict,
                GenerationAwareReleasePolicyCodec.Evaluate(parsed, Candidate(generation, 10, HashB)));
            Assert.AreEqual(ReleasePolicyDecision.RollbackBlocked,
                GenerationAwareReleasePolicyCodec.Evaluate(parsed, Candidate(generation, 9, HashA)));
            Assert.AreEqual(ReleasePolicyDecision.HigherRelease,
                GenerationAwareReleasePolicyCodec.Evaluate(parsed, Candidate(generation, 11, HashB)));
        }
    }

    [TestMethod]
    public void Cross_generation_policy_decisions_never_authorize_ordinary_advancement()
    {
        var v1Policy = ParseV2Policy(ReleaseGeneration.V1);
        var v2Policy = ParseV2Policy(ReleaseGeneration.V2);

        Assert.AreEqual(ReleasePolicyDecision.TransitionRequiresCoordination,
            GenerationAwareReleasePolicyCodec.Evaluate(v1Policy, Candidate(ReleaseGeneration.V2, 11, HashB)));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict,
            GenerationAwareReleasePolicyCodec.Evaluate(v1Policy, Candidate(ReleaseGeneration.V2, 10, HashA)));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict,
            GenerationAwareReleasePolicyCodec.Evaluate(v1Policy, Candidate(ReleaseGeneration.V2, 10, HashB)));
        Assert.AreEqual(ReleasePolicyDecision.RollbackBlocked,
            GenerationAwareReleasePolicyCodec.Evaluate(v1Policy, Candidate(ReleaseGeneration.V2, 9, HashA)));

        Assert.AreEqual(ReleasePolicyDecision.GenerationDowngradeBlocked,
            GenerationAwareReleasePolicyCodec.Evaluate(v2Policy, Candidate(ReleaseGeneration.V1, 11, HashB)));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict,
            GenerationAwareReleasePolicyCodec.Evaluate(v2Policy, Candidate(ReleaseGeneration.V1, 10, HashA)));
        Assert.AreEqual(ReleasePolicyDecision.RollbackBlocked,
            GenerationAwareReleasePolicyCodec.Evaluate(v2Policy, Candidate(ReleaseGeneration.V1, 9, HashA)));
    }

    [TestMethod]
    public void Malformed_or_unknown_policy_v2_fails_closed_with_no_record()
    {
        var canonical = Encoding.UTF8.GetString(GenerationAwareReleasePolicyCodec.Serialize(
            new GenerationAwareReleasePolicyRecord(Candidate(ReleaseGeneration.V2, 10, HashA))));
        var cases = new (string Name, byte[] Bytes, ReleasePolicyParseFailure Failure)[]
        {
            ("empty", [], ReleasePolicyParseFailure.Unavailable),
            ("unknown schema", Encoding.UTF8.GetBytes(canonical.Replace(GenerationAwareReleasePolicyCodec.Schema, "unknown-schema", StringComparison.Ordinal)), ReleasePolicyParseFailure.UnsupportedSchema),
            ("unknown generation", Encoding.UTF8.GetBytes(canonical.Replace("\"generation\":\"v2\"", "\"generation\":\"v3\"", StringComparison.Ordinal)), ReleasePolicyParseFailure.InvalidIdentity),
            ("uppercase generation", Encoding.UTF8.GetBytes(canonical.Replace("\"generation\":\"v2\"", "\"generation\":\"V2\"", StringComparison.Ordinal)), ReleasePolicyParseFailure.InvalidIdentity),
            ("wrong product", Encoding.UTF8.GetBytes(canonical.Replace(ReleasePolicyCodec.Product, "other-product", StringComparison.Ordinal)), ReleasePolicyParseFailure.InvalidIdentity),
            ("wrong architecture", Encoding.UTF8.GetBytes(canonical.Replace(ReleasePolicyCodec.Architecture, "other-arch", StringComparison.Ordinal)), ReleasePolicyParseFailure.InvalidIdentity),
            ("zero sequence", Encoding.UTF8.GetBytes(canonical.Replace("\"highestAcceptedReleaseSequence\":10", "\"highestAcceptedReleaseSequence\":0", StringComparison.Ordinal)), ReleasePolicyParseFailure.InvalidIdentity),
            ("lowercase hash", Encoding.UTF8.GetBytes(canonical.Replace(HashA, HashA.ToLowerInvariant(), StringComparison.Ordinal)), ReleasePolicyParseFailure.InvalidIdentity),
            ("duplicate generation", Encoding.UTF8.GetBytes(canonical.Replace("\"generation\":\"v2\"", "\"generation\":\"v2\",\"generation\":\"v2\"", StringComparison.Ordinal)), ReleasePolicyParseFailure.Malformed),
            ("extra field", Encoding.UTF8.GetBytes(canonical.Replace("}\n", ",\"extra\":true}\n", StringComparison.Ordinal)), ReleasePolicyParseFailure.Malformed),
            ("missing generation", Encoding.UTF8.GetBytes(canonical.Replace("\"generation\":\"v2\",", "", StringComparison.Ordinal)), ReleasePolicyParseFailure.Malformed),
            ("noncanonical sequence", Encoding.UTF8.GetBytes(canonical.Replace("\"highestAcceptedReleaseSequence\":10", "\"highestAcceptedReleaseSequence\":1e1", StringComparison.Ordinal)), ReleasePolicyParseFailure.Malformed),
            ("trailing whitespace", Encoding.UTF8.GetBytes(canonical + " "), ReleasePolicyParseFailure.Malformed),
            ("CRLF", Encoding.UTF8.GetBytes(canonical.Replace("\n", "\r\n", StringComparison.Ordinal)), ReleasePolicyParseFailure.Malformed),
            ("BOM", [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes(canonical)], ReleasePolicyParseFailure.Malformed),
            ("invalid UTF-8", [0xFF], ReleasePolicyParseFailure.Malformed),
            ("oversize", new byte[GenerationAwareReleasePolicyCodec.MaximumBytes + 1], ReleasePolicyParseFailure.Malformed)
        };

        foreach (var (name, bytes, expectedFailure) in cases)
        {
            Assert.IsFalse(GenerationAwareReleasePolicyCodec.TryParse(bytes, out var record, out var failure), name);
            Assert.IsNull(record, name);
            Assert.AreEqual(expectedFailure, failure, name);
        }
    }

    [TestMethod]
    public void Invalid_identity_or_missing_policy_cannot_produce_an_advancement_decision()
    {
        var policy = ParseV2Policy(ReleaseGeneration.V2);
        Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable,
            GenerationAwareReleasePolicyCodec.Evaluate(null, Candidate(ReleaseGeneration.V2, 11, HashB)));
        foreach (var identity in new[]
        {
            Candidate((ReleaseGeneration)0, 11, HashB),
            Candidate(ReleaseGeneration.V2, 0, HashB),
            Candidate(ReleaseGeneration.V2, 11, HashB.ToLowerInvariant()),
            Candidate(ReleaseGeneration.V2, 11, "short")
        })
        {
            Assert.IsFalse(identity.IsValid);
            Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable,
                GenerationAwareReleasePolicyCodec.Evaluate(policy, identity));
        }
    }

    private static ReleaseIdentity Candidate(ReleaseGeneration generation, ulong sequence, string hash) =>
        new(generation, sequence, hash);

    private static GenerationAwareReleasePolicyRecord ParseV2Policy(ReleaseGeneration generation)
    {
        var canonical = GenerationAwareReleasePolicyCodec.Serialize(
            new GenerationAwareReleasePolicyRecord(Candidate(generation, 10, HashA)));
        Assert.IsTrue(GenerationAwareReleasePolicyCodec.TryParse(canonical, out var parsed, out var failure));
        Assert.AreEqual(ReleasePolicyParseFailure.None, failure);
        return parsed!;
    }
}
