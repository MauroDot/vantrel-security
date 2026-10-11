using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
public sealed class BetaReleaseRecordV2CodecTests
{
    private const string Commit = "0123456789abcdef0123456789abcdef01234567";
    private static readonly DateTimeOffset Publication = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void Canonical_round_trip_preserves_release_identity_manifest_hashes_and_ordered_evidence()
    {
        var original = ValidRecord();
        var bytes = BetaReleaseRecordV2Codec.CreateCanonical(original);

        Assert.IsTrue(BetaReleaseRecordV2Codec.TryParse(bytes, out var parsed));
        Assert.IsNotNull(parsed);
        Assert.AreEqual(BetaReleaseRecordV2Codec.Schema,
            Encoding.ASCII.GetString(bytes).Split('\n')[0]["schema=".Length..]);
        Assert.AreEqual(original.Descriptor, parsed.Descriptor);
        Assert.AreEqual(original.SourceLockSha256, parsed.SourceLockSha256);
        Assert.AreEqual(original.SignedManifestSha256, parsed.SignedManifestSha256);
        Assert.AreEqual(original.ManifestPayloadSha256, parsed.ManifestPayloadSha256);
        Assert.AreEqual(original.SignedMetadataSha256, parsed.SignedMetadataSha256);
        CollectionAssert.AreEqual(original.ServiceFiles.ToArray(), parsed.ServiceFiles.ToArray());
        CollectionAssert.AreEqual(original.DiagnosticSymbols.ToArray(), parsed.DiagnosticSymbols.ToArray());
        CollectionAssert.AreEqual(original.AuthenticodeEvidence.ToArray(), parsed.AuthenticodeEvidence.ToArray());
        CollectionAssert.AreEqual(bytes, BetaReleaseRecordV2Codec.CreateCanonical(parsed));
        Assert.IsFalse(BetaReleaseRecordCodec.TryParse(bytes, out _));
    }

    [TestMethod]
    public void Unknown_schema_extra_field_duplicate_field_crlf_bom_and_reordered_lines_decline()
    {
        var text = Encoding.ASCII.GetString(BetaReleaseRecordV2Codec.CreateCanonical(ValidRecord()));
        var lines = text.Split('\n');
        (lines[1], lines[2]) = (lines[2], lines[1]);
        foreach (var changed in new[]
        {
            text.Replace("schema=vantrel-beta-release-record-v2", "schema=vantrel-beta-release-record-v3", StringComparison.Ordinal),
            text.Replace("configuration=Release\n", "configuration=Release\nunknown-field=x\n", StringComparison.Ordinal),
            text.Replace("configuration=Release\n", "configuration=Release\nconfiguration=Release\n", StringComparison.Ordinal),
            text.Replace("\n", "\r\n", StringComparison.Ordinal),
            string.Join('\n', lines),
            text[..^1],
            text + "\n"
        })
            Assert.IsFalse(BetaReleaseRecordV2Codec.TryParse(Encoding.ASCII.GetBytes(changed), out _));
        Assert.IsFalse(BetaReleaseRecordV2Codec.TryParse(
            [0xEF, 0xBB, 0xBF, .. Encoding.ASCII.GetBytes(text)], out _));
    }

    [TestMethod]
    public void Wrong_deployment_sdk_configuration_and_noncanonical_sequence_decline()
    {
        var text = Encoding.ASCII.GetString(BetaReleaseRecordV2Codec.CreateCanonical(ValidRecord()));
        foreach (var (from, to) in new[]
        {
            ("deployment=framework-dependent", "deployment=self-contained"),
            ("target-framework=net10.0-windows", "target-framework=net10.0"),
            ("sdk-version=10.0.401", "sdk-version=10.0.402"),
            ("configuration=Release", "configuration=Debug"),
            ("runtime=win-x64", "runtime=win-arm64"),
            ("release-sequence=7", "release-sequence=07"),
            ("release-sequence=7", "release-sequence=0")
        })
            Assert.IsFalse(BetaReleaseRecordV2Codec.TryParse(
                Encoding.ASCII.GetBytes(text.Replace(from, to, StringComparison.Ordinal)), out _));
    }

    [TestMethod]
    public void Manifest_identity_and_required_service_pe_binding_decline_on_mismatch()
    {
        var text = Encoding.ASCII.GetString(BetaReleaseRecordV2Codec.CreateCanonical(ValidRecord()));
        foreach (var (from, to) in new[]
        {
            ("source-commit=" + Commit, "source-commit=bad"),
            ("release-version=0.1.0-beta.1", "release-version=0.01.0-beta.1"),
            ("published-at-utc=2026-10-10T12:00:00Z", "published-at-utc=2026-99-10T12:00:00Z"),
            ("manifest-metadata-binding=valid", "manifest-metadata-binding=unknown"),
            ("trusted-manifest-v2-file-sha256=" + Hash('B'), "trusted-manifest-v2-file-sha256=invalid"),
            ("trusted-manifest-v2-payload-sha256=" + Hash('C'), "trusted-manifest-v2-payload-sha256=invalid"),
            ("service-file-count=4", "service-file-count=04"),
            ("service-file-count=4", "service-file-count=3"),
            ("diagnostic-symbol-count=3", "diagnostic-symbol-count=2")
        })
            Assert.IsFalse(BetaReleaseRecordV2Codec.TryParse(
                Encoding.ASCII.GetBytes(text.Replace(from, to, StringComparison.Ordinal)), out _));

        var withoutOwnedPe = ValidRecord(files: [
            new("Vantrel.Security.Core.dll", Hash('A')),
            new("Vantrel.Security.Infrastructure.dll", Hash('A')),
            new("Vantrel.Security.Service.dll", Hash('A')),
            new("Vantrel.Security.Service.runtimeconfig.json", Hash('A'))
        ]);
        Assert.ThrowsException<ArgumentException>(() => BetaReleaseRecordV2Codec.CreateCanonical(withoutOwnedPe));
    }

    [TestMethod]
    public void Pdb_and_lock_residue_are_never_record_eligible()
    {
        foreach (var path in new[] { "Vantrel.Security.Service.pdb", "nested/symbols.pdb",
            "packages.lock.json", "nested/packages.lock.json" })
        {
            var original = ValidRecord();
            var files = original.ServiceFiles.Append(new TrustedManifestV2File(path, Hash('A')))
                .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
            var changed = ValidRecord(files: files);
            Assert.ThrowsException<ArgumentException>(() => BetaReleaseRecordV2Codec.CreateCanonical(changed));
        }
    }

    [TestMethod]
    public void Nonvalid_authenticode_categories_wrong_policy_missing_or_reordered_evidence_decline()
    {
        var original = ValidRecord();
        var text = Encoding.ASCII.GetString(BetaReleaseRecordV2Codec.CreateCanonical(original));
        foreach (var (from, to) in new[]
        {
            ("|Valid|", "|Unsigned|"),
            ("|ExactlyOne|", "|ExtraOrDuplicate|"),
            ("|ValidRfc3161\n", "|Missing\n"),
            ("|" + BetaReleaseRecordV2Codec.SigningPolicyId + "|",
                "|wrong-policy|"),
            ("authenticode-artifact-count=4", "authenticode-artifact-count=03")
        })
            Assert.IsFalse(BetaReleaseRecordV2Codec.TryParse(
                Encoding.ASCII.GetBytes(text.Replace(from, to, StringComparison.Ordinal)), out _));

        var reordered = original.AuthenticodeEvidence.Reverse().ToArray();
        Assert.ThrowsException<ArgumentException>(() => BetaReleaseRecordV2Codec.CreateCanonical(
            ValidRecord(evidence: reordered)));
        Assert.ThrowsException<ArgumentException>(() => BetaReleaseRecordV2Codec.CreateCanonical(
            ValidRecord(evidence: original.AuthenticodeEvidence.Skip(1).ToArray())));
    }

    private static BetaReleaseRecordV2 ValidRecord(
        IReadOnlyList<TrustedManifestV2File>? files = null,
        IReadOnlyList<AuthenticodeReleaseEvidence>? evidence = null)
    {
        files ??= ReleaseSigningContract.VantrelOwnedPeArtifacts.Take(4)
            .Select(artifact => new TrustedManifestV2File(artifact.RelativePath["service/".Length..], Hash('A')))
            .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
        evidence ??= ReleaseSigningContract.VantrelOwnedPeArtifacts.Take(4)
            .Select(artifact => new AuthenticodeReleaseEvidence(artifact.RelativePath,
                AuthenticodeVerificationCategory.Valid, BetaReleaseRecordV2Codec.SigningPolicyId,
                PrimarySignatureCountPolicyCategory.ExactlyOne, TimestampPolicyCategory.ValidRfc3161)).ToArray();
        var descriptor = new BetaReleaseDescriptor(Commit, "0.1.0-beta.1", 7, Publication,
            "Release", "win-x64", "10.0.401", Hash('F'));
        TrustedManifestV2File[] diagnostics =
        [
            new("Vantrel.Security.Core.pdb", Hash('E')),
            new("Vantrel.Security.Infrastructure.pdb", Hash('E')),
            new("Vantrel.Security.Service.pdb", Hash('E'))
        ];
        return new BetaReleaseRecordV2(descriptor, Hash('A'), Hash('B'), Hash('C'), Hash('D'),
            files, evidence, diagnostics);
    }

    private static string Hash(char digit) => new(digit, 64);
}
