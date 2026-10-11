using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
public sealed class ProductReleaseRecordV2CodecTests
{
    private const string Hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    [TestMethod]
    public void Canonical_record_round_trips_with_exact_service_and_product_authorities()
    {
        var record = Valid();
        var bytes = ProductReleaseRecordV2Codec.CreateCanonical(record);
        Assert.IsTrue(ProductReleaseRecordV2Codec.TryParse(bytes, out var parsed));
        CollectionAssert.AreEqual(bytes, ProductReleaseRecordV2Codec.CreateCanonical(parsed!));
        Assert.AreEqual(9, parsed!.AuthenticodeEvidence.Count);
        Assert.AreEqual(10, parsed.DiagnosticSymbols.Count);
        Assert.AreEqual(4, parsed.ExcludedBuildArtifacts.Count);
        Assert.IsTrue(parsed.ToolFiles.Any(file => file.Path == "Vantrel.Security.Service.dll"));
        Assert.IsFalse(parsed.ServiceFiles.Any(file => file.Path == "Vantrel.Security.OfflineUpdateTool.dll"));
        Assert.IsFalse(BetaReleaseRecordV2Codec.TryParse(bytes, out _));
    }

    [TestMethod]
    public void Noncanonical_fields_paths_identity_and_schema_fail_closed()
    {
        var text = Encoding.ASCII.GetString(ProductReleaseRecordV2Codec.CreateCanonical(Valid()));
        foreach (var (oldText, newText) in new[]
        {
            ("schema=vantrel-product-release-record-v2", "schema=vantrel-beta-release-record-v2"),
            ("source-commit=" + new string('a', 40), "source-commit=invalid"),
            ("release-version=0.1.0-beta.1", "release-version=0.01.0-beta.1"),
            ("release-sequence=1", "release-sequence=01"),
            ("configuration=Release", "configuration=Debug"),
            ("deployment=framework-dependent", "deployment=self-contained"),
            ("sdk-version=10.0.401", "sdk-version=10.0.402"),
            ("service-record-sha256=" + Hash, "service-record-sha256=bad"),
            ("desktop-file=Vantrel.Security.Desktop.exe", "desktop-file=../escape.exe"),
            ("desktop-file=Vantrel.Security.Desktop.exe", "desktop-file=C:/escape.exe"),
            ("desktop-file-count=4", "desktop-file-count=04"),
            ("|Valid|", "|Unsigned|"),
            ("|ValidRfc3161\n", "|Missing\n"),
            ("source-residue=publish/offline-update-tool/packages.lock.json", "source-residue=publish/offline-update-tool/extra.json")
        })
            Assert.IsFalse(ProductReleaseRecordV2Codec.TryParse(
                Encoding.ASCII.GetBytes(text.Replace(oldText, newText, StringComparison.Ordinal)), out _));
        foreach (var changed in new[] { text.Replace("\n", "\r\n", StringComparison.Ordinal),
            text + "unknown=x\n", text[..^1], "\uFEFF" + text })
            Assert.IsFalse(ProductReleaseRecordV2Codec.TryParse(Encoding.UTF8.GetBytes(changed), out _));
    }

    [TestMethod]
    public void Missing_owned_pe_duplicate_case_collision_and_residue_leakage_fail_closed()
    {
        var original = Valid();
        Assert.ThrowsException<ArgumentException>(() => ProductReleaseRecordV2Codec.CreateCanonical(
            Change(original, desktop: original.DesktopFiles.Where(file => file.Path != "Vantrel.Security.Desktop.exe").ToArray())));
        Assert.ThrowsException<ArgumentException>(() => ProductReleaseRecordV2Codec.CreateCanonical(
            Change(original, desktop: original.DesktopFiles.Append(new("vantrel.security.desktop.exe", Hash))
                .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray())));
        Assert.ThrowsException<ArgumentException>(() => ProductReleaseRecordV2Codec.CreateCanonical(
            Change(original, desktop: original.DesktopFiles.Append(new("packages.lock.json", Hash))
                .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray())));
        Assert.ThrowsException<ArgumentException>(() => ProductReleaseRecordV2Codec.CreateCanonical(
            Change(original, tool: original.ToolFiles.Append(new("Vantrel.Security.Service.pdb", Hash))
                .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray())));
        Assert.ThrowsException<ArgumentException>(() => ProductReleaseRecordV2Codec.CreateCanonical(
            Change(original, evidence: original.AuthenticodeEvidence.Reverse().ToArray())));
    }

    [TestMethod]
    public void Optional_desktop_lock_residue_requires_the_independently_bound_source_lock_hash()
    {
        var original = Valid();
        var residue = original.ExcludedBuildArtifacts.Prepend(
            new TrustedManifestV2File("publish/desktop/packages.lock.json", Hash)).ToArray();
        var withApprovedLock = new ProductReleaseRecordV2(original.Descriptor,
            original.ServiceRecordSha256, original.ServiceManifestSha256,
            original.ServiceMetadataSha256, original.DesktopSourceLockSha256,
            original.ToolSourceLockSha256, original.ServiceFiles, original.DesktopFiles,
            original.ToolFiles, original.DiagnosticSymbols, residue, original.AuthenticodeEvidence);
        Assert.IsTrue(ProductReleaseRecordV2Codec.TryParse(
            ProductReleaseRecordV2Codec.CreateCanonical(withApprovedLock), out _));
        var changed = residue.ToArray();
        changed[0] = changed[0] with { Sha256 = new string('B', 64) };
        var wrongLock = new ProductReleaseRecordV2(original.Descriptor,
            original.ServiceRecordSha256, original.ServiceManifestSha256,
            original.ServiceMetadataSha256, original.DesktopSourceLockSha256,
            original.ToolSourceLockSha256, original.ServiceFiles, original.DesktopFiles,
            original.ToolFiles, original.DiagnosticSymbols, changed, original.AuthenticodeEvidence);
        Assert.ThrowsException<ArgumentException>(() => ProductReleaseRecordV2Codec.CreateCanonical(wrongLock));
    }

    private static ProductReleaseRecordV2 Change(ProductReleaseRecordV2 original,
        IReadOnlyList<TrustedManifestV2File>? desktop = null,
        IReadOnlyList<TrustedManifestV2File>? tool = null,
        IReadOnlyList<AuthenticodeReleaseEvidence>? evidence = null) =>
        new(original.Descriptor, original.ServiceRecordSha256, original.ServiceManifestSha256,
            original.ServiceMetadataSha256, original.DesktopSourceLockSha256,
            original.ToolSourceLockSha256, original.ServiceFiles, desktop ?? original.DesktopFiles,
            tool ?? original.ToolFiles, original.DiagnosticSymbols, original.ExcludedBuildArtifacts,
            evidence ?? original.AuthenticodeEvidence);

    private static ProductReleaseRecordV2 Valid()
    {
        var descriptor = new BetaReleaseDescriptor(new string('a', 40), "0.1.0-beta.1", 1,
            new DateTimeOffset(2026, 10, 10, 12, 0, 0, TimeSpan.Zero), "Release", "win-x64",
            "10.0.401", Hash);
        var service = ReleaseSigningContract.VantrelOwnedPeArtifacts.Take(4)
            .Select(item => new TrustedManifestV2File(item.RelativePath["service/".Length..], Hash))
            .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
        var desktop = ReleaseSigningContract.VantrelOwnedPeArtifacts.Skip(4).Take(4)
            .Select(item => new TrustedManifestV2File(item.RelativePath["desktop/".Length..], Hash))
            .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
        var tool = ReleaseSigningContract.VantrelOwnedPeArtifacts.Skip(8)
            .Select(item => new TrustedManifestV2File(item.RelativePath["offline-update-tool/".Length..], Hash))
            .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
        var diagnostics = new[]
        {
            "Vantrel.Security.Core.pdb", "Vantrel.Security.Infrastructure.pdb",
            "Vantrel.Security.Service.pdb", "desktop/Vantrel.Security.Core.pdb",
            "desktop/Vantrel.Security.Desktop.pdb", "desktop/Vantrel.Security.Infrastructure.pdb",
            "offline-update-tool/Vantrel.Security.Core.pdb",
            "offline-update-tool/Vantrel.Security.Infrastructure.pdb",
            "offline-update-tool/Vantrel.Security.OfflineUpdateTool.pdb",
            "offline-update-tool/Vantrel.Security.Service.pdb"
        }.Select(path => new TrustedManifestV2File("diagnostic-symbols/" + path, Hash))
            .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
        var residue = new[]
        {
            "publish/offline-update-tool/Vantrel.Security.Service.deps.json",
            "publish/offline-update-tool/Vantrel.Security.Service.exe",
            "publish/offline-update-tool/Vantrel.Security.Service.runtimeconfig.json",
            "publish/offline-update-tool/packages.lock.json"
        }.Select(path => new TrustedManifestV2File(path, Hash)).ToArray();
        var evidence = ReleaseSigningContract.VantrelOwnedPeArtifacts.Skip(4)
            .Select(item => new AuthenticodeReleaseEvidence(item.RelativePath,
                AuthenticodeVerificationCategory.Valid, BetaReleaseRecordV2Codec.SigningPolicyId,
                PrimarySignatureCountPolicyCategory.ExactlyOne, TimestampPolicyCategory.ValidRfc3161))
            .ToArray();
        return new(descriptor, Hash, Hash, Hash, Hash, Hash, service, desktop, tool,
            diagnostics, residue, evidence);
    }
}
