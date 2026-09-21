using System.Text;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class ReleasePolicyProtocolTests
{
    private const string HashA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string HashB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    [TestMethod]
    public void Canonical_policy_round_trips_and_has_deterministic_bytes()
    {
        var policy = new ReleasePolicyRecord(ulong.MaxValue, HashA);
        var bytes = ReleasePolicyCodec.Serialize(policy);
        CollectionAssert.AreEqual(Encoding.UTF8.GetBytes("{\"schema\":\"vantrel-release-policy-v1\",\"product\":\"vantrel-security\",\"architecture\":\"win-x64\",\"highestAcceptedReleaseSequence\":18446744073709551615,\"acceptedManifestSha256\":\"" + HashA + "\"}\n"), bytes);
        Assert.IsTrue(ReleasePolicyCodec.TryParse(bytes, out var parsed, out var failure));
        Assert.AreEqual(ReleasePolicyParseFailure.None, failure);
        Assert.AreEqual(policy, parsed);
    }

    [TestMethod]
    public void Parser_rejects_noncanonical_policy_shapes_and_values()
    {
        var valid = Encoding.UTF8.GetString(ReleasePolicyCodec.Serialize(new ReleasePolicyRecord(1, HashA)));
        var cases = new[]
        {
            "\uFEFF" + valid,
            valid.Replace("\n", "\r\n", StringComparison.Ordinal),
            valid.Replace("\"highestAcceptedReleaseSequence\":1", "\"highestAcceptedReleaseSequence\":01", StringComparison.Ordinal),
            valid.Replace("\"acceptedManifestSha256\":\"" + HashA + "\"", "\"acceptedManifestSha256\":\"" + HashA.ToLowerInvariant() + "\"", StringComparison.Ordinal),
            valid.Replace("\"product\":\"vantrel-security\"", "\"product\":\"other\"", StringComparison.Ordinal),
            valid.Replace("\"architecture\":\"win-x64\"", "\"architecture\":\"x86\"", StringComparison.Ordinal),
            valid.Replace("\"schema\":\"vantrel-release-policy-v1\",", string.Empty, StringComparison.Ordinal),
            valid.Replace("}", ",\"extra\":true}", StringComparison.Ordinal),
            valid[..^1] + ",\"schema\":\"vantrel-release-policy-v1\"}\n",
            new string('A', ReleasePolicyCodec.MaximumBytes + 1)
        };
        foreach (var value in cases) Assert.IsFalse(ReleasePolicyCodec.TryParse(Encoding.UTF8.GetBytes(value), out _, out _));
    }

    [TestMethod]
    public void Policy_decisions_are_closed_and_never_lower_high_water()
    {
        var policy = new ReleasePolicyRecord(10, HashA);
        Assert.AreEqual(ReleasePolicyDecision.HigherRelease, ReleasePolicyCodec.Evaluate(policy, 11, HashB));
        Assert.AreEqual(ReleasePolicyDecision.SameAcceptedRelease, ReleasePolicyCodec.Evaluate(policy, 10, HashA));
        Assert.AreEqual(ReleasePolicyDecision.SequenceConflict, ReleasePolicyCodec.Evaluate(policy, 10, HashB));
        Assert.AreEqual(ReleasePolicyDecision.RollbackBlocked, ReleasePolicyCodec.Evaluate(policy, 9, HashB));
        Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, ReleasePolicyCodec.Evaluate(null, 1, HashA));
        Assert.AreEqual(ReleasePolicyDecision.PolicyUnavailable, ReleasePolicyCodec.Evaluate(policy, 0, HashA));
    }
}