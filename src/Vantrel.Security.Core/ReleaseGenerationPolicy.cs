using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Vantrel.Security.Core;

public enum ReleaseGeneration { V1 = 1, V2 = 2 }

/// <summary>The hash covers the complete signed manifest file, including its signature.</summary>
public sealed record ReleaseIdentity(ReleaseGeneration Generation, ulong ReleaseSequence, string ManifestSha256)
{
    public bool IsValid => Generation is ReleaseGeneration.V1 or ReleaseGeneration.V2 &&
        ReleaseSequence != 0 && ManifestSha256 is { Length: 64 } &&
        ManifestSha256.All(static c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
}

public sealed record GenerationAwareReleasePolicyRecord(ReleaseIdentity Identity);

/// <summary>Strict, canonical successor to the historical v1 policy format.</summary>
public static class GenerationAwareReleasePolicyCodec
{
    public const string Schema = "vantrel-release-policy-v2";
    public const int MaximumBytes = ReleasePolicyCodec.MaximumBytes;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static byte[] Serialize(GenerationAwareReleasePolicyRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!record.Identity.IsValid) throw new ArgumentException("Invalid release identity.", nameof(record));
        var generation = record.Identity.Generation == ReleaseGeneration.V1 ? "v1" : "v2";
        return Utf8.GetBytes($"{{\"schema\":\"{Schema}\",\"product\":\"{ReleasePolicyCodec.Product}\",\"architecture\":\"{ReleasePolicyCodec.Architecture}\",\"generation\":\"{generation}\",\"highestAcceptedReleaseSequence\":{record.Identity.ReleaseSequence.ToString(CultureInfo.InvariantCulture)},\"acceptedManifestSha256\":\"{record.Identity.ManifestSha256}\"}}\n");
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out GenerationAwareReleasePolicyRecord? record,
        out ReleasePolicyParseFailure failure)
    {
        record = null;
        if (bytes.IsEmpty) { failure = ReleasePolicyParseFailure.Unavailable; return false; }
        if (bytes.Length > MaximumBytes || bytes.IndexOf((byte)'\r') >= 0 ||
            bytes.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }))
        { failure = ReleasePolicyParseFailure.Malformed; return false; }
        try
        {
            using var document = JsonDocument.Parse(bytes.ToArray());
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) { failure = ReleasePolicyParseFailure.Malformed; return false; }
            var fields = new[] { "schema", "product", "architecture", "generation", "highestAcceptedReleaseSequence", "acceptedManifestSha256" };
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!seen.Add(property.Name) || !fields.Contains(property.Name, StringComparer.Ordinal))
                { failure = ReleasePolicyParseFailure.Malformed; return false; }
            if (seen.Count != fields.Length) { failure = ReleasePolicyParseFailure.Malformed; return false; }
            if (root.GetProperty("schema").GetString() != Schema)
            { failure = ReleasePolicyParseFailure.UnsupportedSchema; return false; }
            if (root.GetProperty("product").GetString() != ReleasePolicyCodec.Product ||
                root.GetProperty("architecture").GetString() != ReleasePolicyCodec.Architecture)
            { failure = ReleasePolicyParseFailure.InvalidIdentity; return false; }
            var generation = root.GetProperty("generation").GetString() switch
            {
                "v1" => ReleaseGeneration.V1,
                "v2" => ReleaseGeneration.V2,
                _ => (ReleaseGeneration)0
            };
            var number = root.GetProperty("highestAcceptedReleaseSequence");
            if (number.ValueKind != JsonValueKind.Number ||
                !ulong.TryParse(number.GetRawText(), NumberStyles.None, CultureInfo.InvariantCulture, out var sequence))
            { failure = ReleasePolicyParseFailure.Malformed; return false; }
            var identity = new ReleaseIdentity(generation, sequence, root.GetProperty("acceptedManifestSha256").GetString() ?? "");
            if (!identity.IsValid) { failure = ReleasePolicyParseFailure.InvalidIdentity; return false; }
            var parsed = new GenerationAwareReleasePolicyRecord(identity);
            if (!bytes.SequenceEqual(Serialize(parsed))) { failure = ReleasePolicyParseFailure.Malformed; return false; }
            record = parsed; failure = ReleasePolicyParseFailure.None; return true;
        }
        catch (JsonException) { failure = ReleasePolicyParseFailure.Malformed; return false; }
        catch (InvalidOperationException) { failure = ReleasePolicyParseFailure.Malformed; return false; }
    }

    public static ReleasePolicyDecision Evaluate(GenerationAwareReleasePolicyRecord? policy, ReleaseIdentity candidate)
    {
        if (policy?.Identity.IsValid != true || candidate is null || !candidate.IsValid)
            return ReleasePolicyDecision.PolicyUnavailable;
        var accepted = policy.Identity;
        if (candidate.ReleaseSequence < accepted.ReleaseSequence) return ReleasePolicyDecision.RollbackBlocked;
        if (candidate.ReleaseSequence == accepted.ReleaseSequence)
            return candidate.Generation == accepted.Generation && candidate.ManifestSha256 == accepted.ManifestSha256
                ? ReleasePolicyDecision.SameAcceptedRelease : ReleasePolicyDecision.SequenceConflict;
        if (accepted.Generation == ReleaseGeneration.V2 && candidate.Generation == ReleaseGeneration.V1)
            return ReleasePolicyDecision.GenerationDowngradeBlocked;
        if (accepted.Generation == ReleaseGeneration.V1 && candidate.Generation == ReleaseGeneration.V2)
            return ReleasePolicyDecision.TransitionRequiresCoordination;
        return ReleasePolicyDecision.HigherRelease;
    }
}
