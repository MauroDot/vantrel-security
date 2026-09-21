using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Vantrel.Security.Core;

public enum ReleasePolicyDecision { BootstrapAccepted, SameAcceptedRelease, HigherRelease, SequenceConflict, RollbackBlocked, PolicyUnavailable }
public enum ReleasePolicyParseFailure { None, Unavailable, Malformed, UnsupportedSchema, InvalidIdentity }

/// <summary>Minimal durable high-water state. It contains no signing material or arbitrary metadata.</summary>
public sealed record ReleasePolicyRecord(ulong HighestAcceptedReleaseSequence, string AcceptedManifestSha256);

public static class ReleasePolicyCodec
{
    public const int MaximumBytes = 1024;
    public const string Schema = "vantrel-release-policy-v1";
    public const string Product = ReleaseMetadataCodec.Product;
    public const string Architecture = ReleaseMetadataCodec.Architecture;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static byte[] Serialize(ReleasePolicyRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.HighestAcceptedReleaseSequence == 0) throw new ArgumentOutOfRangeException(nameof(record));
        if (!IsUpperHash(record.AcceptedManifestSha256)) throw new ArgumentException("A 64-character uppercase SHA-256 is required.", nameof(record));
        return Utf8.GetBytes($"{{\"schema\":\"{Schema}\",\"product\":\"{Product}\",\"architecture\":\"{Architecture}\",\"highestAcceptedReleaseSequence\":{record.HighestAcceptedReleaseSequence.ToString(CultureInfo.InvariantCulture)},\"acceptedManifestSha256\":\"{record.AcceptedManifestSha256}\"}}\n");
    }

    public static bool TryParse(ReadOnlySpan<byte> bytes, out ReleasePolicyRecord? record, out ReleasePolicyParseFailure failure)
    {
        record = null;
        if (bytes.Length == 0) { failure = ReleasePolicyParseFailure.Unavailable; return false; }
        if (bytes.Length > MaximumBytes || HasBom(bytes) || bytes.IndexOf((byte)'\r') >= 0) { failure = ReleasePolicyParseFailure.Malformed; return false; }
        try
        {
            var text = Utf8.GetString(bytes);
            using var document = JsonDocument.Parse(bytes.ToArray());
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !HasExactFields(root)) { failure = ReleasePolicyParseFailure.Malformed; return false; }
            if (root.GetProperty("schema").GetString() != Schema) { failure = ReleasePolicyParseFailure.UnsupportedSchema; return false; }
            if (root.GetProperty("product").GetString() != Product || root.GetProperty("architecture").GetString() != Architecture)
            { failure = ReleasePolicyParseFailure.InvalidIdentity; return false; }
            var sequenceElement = root.GetProperty("highestAcceptedReleaseSequence");
            if (sequenceElement.ValueKind != JsonValueKind.Number || !ulong.TryParse(sequenceElement.GetRawText(), NumberStyles.None, CultureInfo.InvariantCulture, out var sequence) || sequence == 0)
            { failure = ReleasePolicyParseFailure.Malformed; return false; }
            var hash = root.GetProperty("acceptedManifestSha256").GetString();
            if (!IsUpperHash(hash)) { failure = ReleasePolicyParseFailure.Malformed; return false; }
            var parsed = new ReleasePolicyRecord(sequence, hash!);
            if (!bytes.SequenceEqual(Serialize(parsed))) { failure = ReleasePolicyParseFailure.Malformed; return false; }
            record = parsed; failure = ReleasePolicyParseFailure.None; return true;
        }
        catch (JsonException) { failure = ReleasePolicyParseFailure.Malformed; return false; }
        catch (DecoderFallbackException) { failure = ReleasePolicyParseFailure.Malformed; return false; }
    }

    public static ReleasePolicyDecision Evaluate(ReleasePolicyRecord? highWater, ulong candidateSequence, string candidateManifestSha256)
    {
        if (candidateSequence == 0 || !IsUpperHash(candidateManifestSha256)) return ReleasePolicyDecision.PolicyUnavailable;
        if (highWater is null) return ReleasePolicyDecision.PolicyUnavailable;
        if (candidateSequence > highWater.HighestAcceptedReleaseSequence) return ReleasePolicyDecision.HigherRelease;
        if (candidateSequence < highWater.HighestAcceptedReleaseSequence) return ReleasePolicyDecision.RollbackBlocked;
        return string.Equals(candidateManifestSha256, highWater.AcceptedManifestSha256, StringComparison.Ordinal)
            ? ReleasePolicyDecision.SameAcceptedRelease : ReleasePolicyDecision.SequenceConflict;
    }

    private static bool HasExactFields(JsonElement root)
    {
        var expected = new[] { "schema", "product", "architecture", "highestAcceptedReleaseSequence", "acceptedManifestSha256" };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject()) if (!seen.Add(property.Name) || !expected.Contains(property.Name, StringComparer.Ordinal)) return false;
        return seen.Count == expected.Length;
    }
    private static bool IsUpperHash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool HasBom(ReadOnlySpan<byte> bytes) => bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
}