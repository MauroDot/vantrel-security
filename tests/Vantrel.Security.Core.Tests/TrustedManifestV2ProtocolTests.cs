using System.Collections;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vantrel.Security.Core;

namespace Vantrel.Security.Core.Tests;

[TestClass]
public sealed class TrustedManifestV2ProtocolTests
{
    private const string Release = "0.1.0-beta.2";
    private const ulong Sequence = 7;
    private static readonly DateTimeOffset PublishedAt = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);
    private static readonly string HashA = new('A', 64);
    private static readonly string HashB = new('B', 64);
    private static readonly string HashC = new('C', 64);
    private static readonly string HashD = new('D', 64);
    private static readonly string HashE = new('E', 64);
    private static readonly string HashF = new('F', 64);

    private static readonly TrustedManifestV2File[] Files =
    [
        new("System.Diagnostics.EventLog.Messages.dll", HashA),
        new("Vantrel.Security.Service.deps.json", HashB),
        new("Vantrel.Security.Service.dll", HashC),
        new("Vantrel.Security.Service.exe", HashD),
        new("Vantrel.Security.Service.runtimeconfig.json", HashE),
        new("runtimes/win-x64/native/native.dll", HashF)
    ];

    [TestMethod]
    public void Canonical_v2_manifest_round_trips_with_exact_ascii_lf_bytes_and_all_inventory_entries()
    {
        var payload = TrustedManifestV2Codec.CreateCanonicalPayload(Release, Sequence, Files);
        var expected =
            "schema=vantrel-trusted-manifest-v2\n" +
            "release=0.1.0-beta.2\n" +
            "release-sequence=7\n" +
            "architecture=win-x64\n" +
            "deployment=framework-dependent\n" +
            "file-count=6\n" +
            $"file=System.Diagnostics.EventLog.Messages.dll|{HashA}\n" +
            $"file=Vantrel.Security.Service.deps.json|{HashB}\n" +
            $"file=Vantrel.Security.Service.dll|{HashC}\n" +
            $"file=Vantrel.Security.Service.exe|{HashD}\n" +
            $"file=Vantrel.Security.Service.runtimeconfig.json|{HashE}\n" +
            $"file=runtimes/win-x64/native/native.dll|{HashF}\n";
        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes(expected), payload);

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var file = TrustedManifestV2Codec.CreateFile(Release, Sequence, Files, key);
        Assert.IsTrue(TrustedManifestV2Codec.TryParse(file, out var manifest, out var failure));
        Assert.AreEqual(TrustedManifestParseFailure.None, failure);
        Assert.IsNotNull(manifest);
        Assert.AreEqual(Release, manifest.Release);
        Assert.AreEqual(Sequence, manifest.ReleaseSequence);
        Assert.AreEqual("win-x64", manifest.Architecture);
        Assert.AreEqual("framework-dependent", manifest.Deployment);
        CollectionAssert.AreEqual(Files.Select(entry => entry.Path).ToArray(), manifest.Files.Select(entry => entry.Path).ToArray());
        CollectionAssert.AreEqual(Files.Select(entry => entry.Sha256).ToArray(), manifest.Files.Select(entry => entry.Sha256).ToArray());
        Assert.IsFalse(manifest.Files is TrustedManifestV2File[]);
        Assert.IsTrue(manifest.Files is IList<TrustedManifestV2File>);
        var mutableView = (IList<TrustedManifestV2File>)manifest.Files;
        Assert.IsTrue(mutableView.IsReadOnly);
        Assert.ThrowsException<NotSupportedException>(() => mutableView.Add(new TrustedManifestV2File("extra.dll", HashA)));
        Assert.IsTrue(TrustedManifestV2Codec.Verify(manifest, key.ExportSubjectPublicKeyInfo()));
        Assert.IsTrue(TrustedManifestV2Codec.MatchesInventory(manifest, Inventory()));
    }

    [TestMethod]
    public void Creator_rejects_case_colliding_directories_and_file_directory_conflicts()
    {
        var caseCollision = new TrustedManifestV2File[]
        {
            new("runtimes/Win/native.dll", HashA),
            new("runtimes/win/other.dll", HashB)
        };
        var fileAsDirectory = new TrustedManifestV2File[]
        {
            new("assets", HashA),
            new("assets/child.dll", HashB)
        };
        Assert.ThrowsException<ArgumentException>(() => TrustedManifestV2Codec.CreateCanonicalPayload(Release, Sequence, caseCollision));
        Assert.ThrowsException<ArgumentException>(() => TrustedManifestV2Codec.CreateCanonicalPayload(Release, Sequence, fileAsDirectory));
    }

    [TestMethod]
    public void Creator_enforces_file_segment_and_release_identity_bounds()
    {
        var tooMany = Enumerable.Range(0, TrustedManifestV2Codec.MaximumFiles + 1)
            .Select(index => new TrustedManifestV2File($"file{index:D4}.dll", HashA)).ToArray();
        Assert.ThrowsException<ArgumentException>(() => TrustedManifestV2Codec.CreateCanonicalPayload(Release, Sequence, tooMany));
        Assert.ThrowsException<ArgumentException>(() => TrustedManifestV2Codec.CreateCanonicalPayload(Release, Sequence,
            [new TrustedManifestV2File(new string('a', TrustedManifestV2Codec.MaximumSegmentLength + 1), HashA)]));
        Assert.ThrowsException<ArgumentException>(() => TrustedManifestV2Codec.CreateCanonicalPayload("01.0.0", Sequence, Files));
        Assert.ThrowsException<ArgumentException>(() => TrustedManifestV2Codec.CreateCanonicalPayload("0.1.0-beta..2", Sequence, Files));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => TrustedManifestV2Codec.CreateCanonicalPayload(Release, 0, Files));
    }

    [TestMethod]
    public void Creator_snapshots_each_producer_entry_once_before_validation_and_serialization()
    {
        var source = new ChangingInventory(Files);
        var canonical = TrustedManifestV2Codec.CreateCanonicalPayload(Release, Sequence, source);

        CollectionAssert.AreEqual(TrustedManifestV2Codec.CreateCanonicalPayload(Release, Sequence, Files), canonical);
        CollectionAssert.AreEqual(Enumerable.Repeat(1, Files.Length).ToArray(), source.ReadCounts);
    }

    [TestMethod]
    public void Parsed_v2_signature_rejects_wrong_key_and_changed_authorized_hash()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var original = TrustedManifestV2Codec.CreateFile(Release, Sequence, Files, key);
        Assert.IsTrue(TrustedManifestV2Codec.TryParse(original, out var manifest, out _));
        Assert.IsFalse(TrustedManifestV2Codec.Verify(manifest!, wrongKey.ExportSubjectPublicKeyInfo()));
        Assert.IsFalse(TrustedManifestV2Codec.Verify(manifest!, OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo));

        var changed = ReplaceAscii(original, $"file=Vantrel.Security.Service.dll|{HashC}",
            $"file=Vantrel.Security.Service.dll|{HashD}");
        Assert.IsTrue(TrustedManifestV2Codec.TryParse(changed, out var changedManifest, out _));
        Assert.IsFalse(TrustedManifestV2Codec.Verify(changedManifest!, key.ExportSubjectPublicKeyInfo()));
        Assert.IsFalse(TrustedManifestV2Codec.MatchesInventory(changedManifest!, Inventory()));
    }

    [TestMethod]
    public void Verification_rejects_malformed_der_and_wrong_curve_keys()
    {
        using var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var valid = TrustedManifestV2Codec.CreateFile(Release, Sequence, Files, p256);
        Assert.IsTrue(TrustedManifestV2Codec.TryParse(valid, out var parsed, out _));
        Assert.IsNotNull(parsed);
        Assert.IsFalse(TrustedManifestV2Codec.Verify(parsed, p384.ExportSubjectPublicKeyInfo()));
        Assert.ThrowsException<ArgumentException>(() => TrustedManifestV2Codec.CreateFile(Release, Sequence, Files, p384));

        var canonical = TrustedManifestV2Codec.CreateCanonicalPayload(Release, Sequence, Files);
        foreach (var malformedDer in new[]
        {
            new byte[] { 0x01, 0x01, 0x00 }, // Not an ASN.1 sequence.
            new byte[] { 0x30, 0x03, 0x02, 0x01 } // Truncated DER sequence.
        })
        {
            var malformedFile = Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(canonical) +
                "signature=" + Convert.ToBase64String(malformedDer) + "\n");
            Assert.IsTrue(TrustedManifestV2Codec.TryParse(malformedFile, out var malformed, out _));
            Assert.IsNotNull(malformed);
            Assert.IsFalse(TrustedManifestV2Codec.Verify(malformed, p256.ExportSubjectPublicKeyInfo()));
        }
    }

    [TestMethod]
    public void Exact_inventory_rejects_missing_extra_changed_case_variant_and_duplicate_observations()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var file = TrustedManifestV2Codec.CreateFile(Release, Sequence, Files, key);
        Assert.IsTrue(TrustedManifestV2Codec.TryParse(file, out var manifest, out _));
        Assert.IsNotNull(manifest);

        var missing = Inventory();
        missing.RemoveAt(2);
        Assert.IsFalse(TrustedManifestV2Codec.MatchesInventory(manifest, missing));

        var extra = Inventory();
        extra.Add(new TrustedManifestV2File("unlisted.dll", HashA));
        Assert.IsFalse(TrustedManifestV2Codec.MatchesInventory(manifest, extra));

        var changed = Inventory();
        changed[2] = new TrustedManifestV2File("Vantrel.Security.Service.dll", HashD);
        Assert.IsFalse(TrustedManifestV2Codec.MatchesInventory(manifest, changed));

        var differentCase = Inventory();
        differentCase[2] = new TrustedManifestV2File("vantrel.security.service.dll", HashC);
        Assert.IsFalse(TrustedManifestV2Codec.MatchesInventory(manifest, differentCase));

        var caseDuplicate = Inventory();
        caseDuplicate.Add(new TrustedManifestV2File("vantrel.security.service.dll", HashC));
        Assert.IsFalse(TrustedManifestV2Codec.MatchesInventory(manifest, caseDuplicate));
    }

    [TestMethod]
    public void Parser_rejects_duplicate_case_collision_count_mismatch_and_noncanonical_order()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var valid = Encoding.ASCII.GetString(TrustedManifestV2Codec.CreateFile(Release, Sequence, Files, key));
        var last = $"file=runtimes/win-x64/native/native.dll|{HashF}\n";
        var duplicate = valid.Replace("file-count=6\n", "file-count=7\n", StringComparison.Ordinal)
            .Replace("signature=", last + "signature=", StringComparison.Ordinal);
        var caseCollision = valid.Replace("file-count=6\n", "file-count=7\n", StringComparison.Ordinal)
            .Replace(last, $"file=runtimes/win-x64/native/NATIVE.dll|{HashF}\n" + last, StringComparison.Ordinal);
        var countMismatch = valid.Replace("file-count=6\n", "file-count=5\n", StringComparison.Ordinal);
        var first = $"file=System.Diagnostics.EventLog.Messages.dll|{HashA}\n";
        var second = $"file=Vantrel.Security.Service.deps.json|{HashB}\n";
        var outOfOrder = valid.Replace(first + second, second + first, StringComparison.Ordinal);

        foreach (var text in new[] { duplicate, caseCollision, countMismatch, outOfOrder })
            Assert.IsFalse(TrustedManifestV2Codec.TryParse(Encoding.ASCII.GetBytes(text), out _, out _));
    }

    [TestMethod]
    public void Parser_rejects_unsafe_windows_paths_and_ambiguous_representations()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string originalPath = "placeholder.dll";
        var valid = TrustedManifestV2Codec.CreateFile(Release, Sequence,
            [new TrustedManifestV2File(originalPath, HashA)], key);
        var unsafePaths = new[]
        {
            "/absolute.exe", "C:/absolute.exe", "C:relative.exe", "//server/share/file.exe",
            "../escape.exe", "a/../escape.exe", "a/./file.exe", "a//file.exe", "./file.exe",
            "a\\file.exe", "file.exe:stream", "CON", "AUX.txt", "NUL", "COM1.txt",
            "LPT9.log", "file.", "file ", "a/<file>.exe", "a/?file.exe", "a/|file.exe",
            "Vantrel.Security.TrustedManifest", "Vantrel.Security.ReleaseMetadata",
            "vantrel.security.trustedmanifest/child.dll", "vantrel.security.releasemetadata/child.dll"
        };
        foreach (var unsafePath in unsafePaths)
        {
            var changed = ReplaceAscii(valid, originalPath, unsafePath);
            Assert.IsFalse(TrustedManifestV2Codec.TryParse(changed, out _, out _), unsafePath);
        }
    }

    [TestMethod]
    public void Parser_rejects_invalid_encoding_schema_profile_sequence_and_bounds()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var valid = TrustedManifestV2Codec.CreateFile(Release, Sequence, Files, key);
        var text = Encoding.ASCII.GetString(valid);
        var unknownSchema = ReplaceAscii(valid, TrustedManifestV2Codec.Schema, "vantrel-trusted-manifest-v3");
        Assert.IsFalse(TrustedManifestV2Codec.TryParse(unknownSchema, out _, out var failure));
        Assert.AreEqual(TrustedManifestParseFailure.UnsupportedSchema, failure);

        var malformed = new[]
        {
            new byte[] { 0xEF, 0xBB, 0xBF }.Concat(valid).ToArray(),
            Encoding.ASCII.GetBytes(text.Replace("\n", "\r\n", StringComparison.Ordinal)),
            valid[..^1],
            valid.Concat(new byte[] { 0xFF }).ToArray(),
            Encoding.UTF8.GetBytes(text.Replace("Service.exe", "Sérvice.exe", StringComparison.Ordinal)),
            ReplaceAscii(valid, "architecture=win-x64", "architecture=win-arm64"),
            ReplaceAscii(valid, "deployment=framework-dependent", "deployment=self-contained"),
            ReplaceAscii(valid, "release-sequence=7", "release-sequence=0"),
            ReplaceAscii(valid, "release-sequence=7", "release-sequence=07"),
            ReplaceAscii(valid, "release-sequence=7", "release-sequence=18446744073709551616"),
            ReplaceAscii(valid, "file-count=6", "file-count=06"),
            ReplaceAscii(valid, $"file=Vantrel.Security.Service.exe|{HashD}", $"file=Vantrel.Security.Service.exe|{HashD.ToLowerInvariant()}"),
            Encoding.ASCII.GetBytes(text + "extra=x\n"),
            Enumerable.Repeat((byte)'A', TrustedManifestV2Codec.MaximumBytes + 1).ToArray(),
            Encoding.ASCII.GetBytes("schema=" + TrustedManifestV2Codec.Schema + "\n" +
                string.Concat(Enumerable.Repeat("x\n", TrustedManifestV2Codec.MaximumFiles + 8))),
            ReplaceAscii(valid, "Vantrel.Security.Service.exe", new string('x', TrustedManifestV2Codec.MaximumPathLength + 1)),
            ReplaceAscii(valid, "Vantrel.Security.Service.exe", string.Join('/', Enumerable.Repeat("x", TrustedManifestV2Codec.MaximumDepth + 1)))
        };
        foreach (var bytes in malformed)
            Assert.IsFalse(TrustedManifestV2Codec.TryParse(bytes, out _, out _));
    }

    [TestMethod]
    public void V1_and_v2_parsers_do_not_reinterpret_the_other_schema()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var v1Hashes = Enum.GetValues<TrustedManifestComponent>()
            .ToDictionary(component => component, _ => HashA);
        var v1 = TrustedManifestCodec.CreateFile(Release, v1Hashes, key);
        var v2 = TrustedManifestV2Codec.CreateFile(Release, Sequence, Files, key);

        Assert.IsTrue(TrustedManifestCodec.TryParse(v1, out var parsedV1, out _));
        Assert.IsTrue(TrustedManifestCodec.Verify(parsedV1!, key.ExportSubjectPublicKeyInfo()));
        Assert.IsTrue(TrustedManifestSchemaCodec.TryParse(v1, out var dispatchedV1, out var absentV2, out _));
        Assert.IsNotNull(dispatchedV1);
        Assert.IsNull(absentV2);
        Assert.IsTrue(TrustedManifestSchemaCodec.TryParse(v2, out var absentV1, out var dispatchedV2, out _));
        Assert.IsNull(absentV1);
        Assert.IsNotNull(dispatchedV2);
        Assert.IsFalse(TrustedManifestV2Codec.TryParse(v1, out _, out var v2Failure));
        Assert.AreEqual(TrustedManifestParseFailure.UnsupportedSchema, v2Failure);
        Assert.IsFalse(TrustedManifestCodec.TryParse(v2, out _, out _));
        var unsupported = ReplaceAscii(v2, TrustedManifestV2Codec.Schema, "vantrel-trusted-manifest-v3");
        Assert.IsFalse(TrustedManifestSchemaCodec.TryParse(unsupported, out _, out _, out var unsupportedFailure));
        Assert.AreEqual(TrustedManifestParseFailure.UnsupportedSchema, unsupportedFailure);
    }

    [TestMethod]
    public void Metadata_binds_full_signed_v2_manifest_bytes_and_matching_release_identity()
    {
        using var manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifestBytes = TrustedManifestV2Codec.CreateFile(Release, Sequence, Files, manifestKey);
        var fullFileHash = Convert.ToHexString(SHA256.HashData(manifestBytes));
        var payloadHash = Convert.ToHexString(SHA256.HashData(TrustedManifestV2Codec.CreateCanonicalPayload(Release, Sequence, Files)));
        Assert.AreNotEqual(payloadHash, fullFileHash);

        var metadataBytes = ReleaseMetadataCodec.CreateFile(Sequence, fullFileHash, Release, PublishedAt, metadataKey);
        Assert.IsTrue(TrustedManifestV2Codec.VerifyBoundMetadata(manifestBytes, metadataBytes,
            manifestKey.ExportSubjectPublicKeyInfo(), metadataKey.ExportSubjectPublicKeyInfo()));
        Assert.IsFalse(TrustedManifestV2Codec.VerifyProductionBoundMetadata(manifestBytes, metadataBytes));
        Assert.IsFalse(TrustedManifestV2Codec.VerifyBoundMetadata(manifestBytes, metadataBytes,
            OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo, metadataKey.ExportSubjectPublicKeyInfo()));

        var payloadBoundMetadata = ReleaseMetadataCodec.CreateFile(Sequence, payloadHash, Release, PublishedAt, metadataKey);
        Assert.IsFalse(TrustedManifestV2Codec.VerifyBoundMetadata(manifestBytes, payloadBoundMetadata,
            manifestKey.ExportSubjectPublicKeyInfo(), metadataKey.ExportSubjectPublicKeyInfo()));
        var changedManifest = ReplaceAscii(manifestBytes, $"file=Vantrel.Security.Service.dll|{HashC}",
            $"file=Vantrel.Security.Service.dll|{HashD}");
        Assert.IsFalse(TrustedManifestV2Codec.VerifyBoundMetadata(changedManifest, metadataBytes,
            manifestKey.ExportSubjectPublicKeyInfo(), metadataKey.ExportSubjectPublicKeyInfo()));

        var wrongSequence = ReleaseMetadataCodec.CreateFile(Sequence + 1, fullFileHash, Release, PublishedAt, metadataKey);
        Assert.IsFalse(TrustedManifestV2Codec.VerifyBoundMetadata(manifestBytes, wrongSequence,
            manifestKey.ExportSubjectPublicKeyInfo(), metadataKey.ExportSubjectPublicKeyInfo()));
        var wrongRelease = ReleaseMetadataCodec.CreateFile(Sequence, fullFileHash, "0.1.0-beta.3", PublishedAt, metadataKey);
        Assert.IsFalse(TrustedManifestV2Codec.VerifyBoundMetadata(manifestBytes, wrongRelease,
            manifestKey.ExportSubjectPublicKeyInfo(), metadataKey.ExportSubjectPublicKeyInfo()));
    }

    private static List<TrustedManifestV2File> Inventory() => Files.ToList();

    private static byte[] ReplaceAscii(byte[] source, string oldValue, string newValue)
    {
        var text = Encoding.ASCII.GetString(source);
        Assert.IsTrue(text.Contains(oldValue, StringComparison.Ordinal));
        return Encoding.ASCII.GetBytes(text.Replace(oldValue, newValue, StringComparison.Ordinal));
    }

    private sealed class ChangingInventory(IReadOnlyList<TrustedManifestV2File> source) : IReadOnlyList<TrustedManifestV2File>
    {
        public int[] ReadCounts { get; } = new int[source.Count];
        public int Count => source.Count;

        public TrustedManifestV2File this[int index]
        {
            get
            {
                ReadCounts[index]++;
                return ReadCounts[index] == 1 ? source[index] : new(source[index].Path, "invalid hash");
            }
        }

        public IEnumerator<TrustedManifestV2File> GetEnumerator()
        {
            for (var i = 0; i < Count; i++) yield return this[i];
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
