using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vantrel.Security.InstallerPreflight;

namespace Vantrel.Security.InstallerPreflight.Tests;

[TestClass]
public sealed class MsiCompoundStorageTests
{
    [TestMethod]
    public void Only_two_root_signature_streams_and_root_timestamp_change_are_accepted()
    {
        var before = Read(MsiCompoundFixture.Create());
        var after = Read(MsiCompoundFixture.Create(signatures: true, rootModified: 7));
        MsiCompoundStorageComparer.RequireOnlySignatureChanges(before, after);
        Assert.HasCount(before.Entries.Count + 2, after.Entries.ToArray());
        Assert.IsTrue(after.Entries.ContainsKey(MsiCompoundStorageComparer.Signature));
        Assert.IsTrue(after.Entries.ContainsKey(MsiCompoundStorageComparer.SignatureEx));
    }

    [TestMethod]
    public void Version_four_header_sector_is_bound_and_nonzero_padding_is_rejected()
    {
        var unsigned = MsiCompoundFixture.Create(version4: true);
        var signed = MsiCompoundFixture.Create(signatures: true, rootModified: 7, version4: true);
        var before = Read(unsigned);
        var after = Read(signed);
        Assert.AreEqual(4096, before.SectorSize);
        Assert.AreEqual(Convert.ToHexString(SHA256.HashData(unsigned.AsSpan(0, 4096))), before.HeaderSha256);
        MsiCompoundStorageComparer.RequireOnlySignatureChanges(before, after);

        signed[512] = 1;
        Assert.ThrowsExactly<InvalidDataException>(() => Read(signed));
    }

    [TestMethod]
    public void Every_original_logical_stream_and_unexpected_nested_stream_is_rejected_when_changed()
    {
        var before = Read(MsiCompoundFixture.Create());
        foreach (var changed in new[] { "Table", "Summary", "Cab", "Property" })
        {
            var after = Read(MsiCompoundFixture.Create(signatures: true, changed: changed));
            Assert.ThrowsExactly<InvalidDataException>(
                () => MsiCompoundStorageComparer.RequireOnlySignatureChanges(before, after), changed);
        }
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            before, Read(MsiCompoundFixture.Create(signatures: true, extraNested: true))));
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            Read(MsiCompoundFixture.Create(signatures: true)), Read(MsiCompoundFixture.Create(signatures: true))));
    }

    [TestMethod]
    public void Malformed_allocation_cycle_overlap_and_ambiguous_name_fail_before_comparison()
    {
        var cycle = MsiCompoundFixture.Create(signatures: true);
        // Table occupies mini sectors zero and one. Send sector one back to zero.
        var miniFatStart = BinaryPrimitives.ReadUInt32LittleEndian(cycle.AsSpan(0x3C, 4));
        BinaryPrimitives.WriteUInt32LittleEndian(cycle.AsSpan(checked((int)(miniFatStart + 1) * 512 + 4), 4), 0);
        Assert.ThrowsExactly<InvalidDataException>(() => Read(cycle));

        var overlap = MsiCompoundFixture.Create(signatures: true);
        // Summary's directory start points into Table's mini-sector chain.
        BinaryPrimitives.WriteUInt32LittleEndian(overlap.AsSpan(1024 + 2 * 128 + 0x74, 4), 0);
        Assert.ThrowsExactly<InvalidDataException>(() => Read(overlap));

        var duplicate = MsiCompoundFixture.Create(signatures: true);
        // Directory sector one, entry two: case-collide with Table.
        var entry = 1024 + 2 * 128;
        System.Text.Encoding.Unicode.GetBytes("table\0").CopyTo(duplicate, entry);
        BinaryPrimitives.WriteUInt16LittleEndian(duplicate.AsSpan(entry + 0x40, 2), 12);
        Assert.ThrowsExactly<InvalidDataException>(() => Read(duplicate));
    }

    [TestMethod]
    public void Physical_padding_of_existing_stream_is_bound_even_when_logical_hash_is_unchanged()
    {
        var before = Read(MsiCompoundFixture.Create());
        var signed = MsiCompoundFixture.Create(signatures: true);
        // Table has 65 logical bytes in two mini sectors. Alter the unused tail.
        // The first mini-stream physical sector follows FAT, directory and mini-FAT sectors.
        var miniStart = BinaryPrimitives.ReadUInt32LittleEndian(signed.AsSpan(0x3C, 4));
        var offset = checked((int)(miniStart + 1) * 512 + 65);
        signed[offset] ^= 0x7F;
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            before, Read(signed)));
    }

    [TestMethod]
    public void New_signature_mini_stream_padding_must_preserve_prior_bytes()
    {
        var signed = MsiCompoundFixture.Create(signatures: true);
        var rootSector = BinaryPrimitives.ReadUInt32LittleEndian(signed.AsSpan(1024 + 0x74, 4));
        var signatureMini = BinaryPrimitives.ReadUInt32LittleEndian(signed.AsSpan(1024 + 6 * 128 + 0x74, 4));
        signed[checked((int)(rootSector + 1) * 512 + (int)signatureMini * 64 + 32)] = 0xA5;
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            Read(MsiCompoundFixture.Create()), Read(signed)));
    }

    [TestMethod]
    public void Preexisting_nested_signature_name_and_changed_root_metadata_are_rejected()
    {
        var nested = MsiCompoundFixture.Create(extraNested: true);
        var nestedAfter = MsiCompoundFixture.Create(signatures: true, extraNested: true);
        var entry = 1024 + 6 * 128;
        var name = System.Text.Encoding.Unicode.GetBytes("\u0005digitalsignature\0");
        name.CopyTo(nested, entry);
        BinaryPrimitives.WriteUInt16LittleEndian(nested.AsSpan(entry + 0x40, 2), (ushort)name.Length);
        var afterEntry = 1024 + 6 * 128;
        name.CopyTo(nestedAfter, afterEntry);
        BinaryPrimitives.WriteUInt16LittleEndian(nestedAfter.AsSpan(afterEntry + 0x40, 2), (ushort)name.Length);
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            Read(nested), Read(nestedAfter)));

        var metadata = MsiCompoundFixture.Create(signatures: true);
        BinaryPrimitives.WriteUInt32LittleEndian(metadata.AsSpan(1024 + 0x60, 4), 1);
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            Read(MsiCompoundFixture.Create()), Read(metadata)));
    }

    [TestMethod]
    public void Invalid_directory_color_and_valid_unrelated_recolor_are_rejected()
    {
        var invalid = MsiCompoundFixture.Create(signatures: true);
        invalid[1024 + 3 * 128 + 0x43] = 2;
        Assert.ThrowsExactly<InvalidDataException>(() => Read(invalid));

        var unrelated = MsiCompoundFixture.Create(signatures: true);
        unrelated[1024 + 3 * 128 + 0x43] = 0; // Cab remains a valid red leaf.
        var parsed = Read(unrelated);
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            Read(MsiCompoundFixture.Create()), parsed));
    }

    [TestMethod]
    public void Valid_but_unrelated_sibling_rotation_is_rejected()
    {
        var changed = MsiCompoundFixture.Create(signatures: true);
        // Rotate the sorted Table/summary subtree without changing its logical entries.
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(1024 + 1 * 128 + 0x48, 4), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(1024 + 4 * 128 + 0x48, 4), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(1024 + 2 * 128 + 0x44, 4), 7);
        changed[1024 + 2 * 128 + 0x43] = 1;
        var parsed = Read(changed);
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            Read(MsiCompoundFixture.Create()), parsed));
    }

    [TestMethod]
    public void Unnecessary_directory_allocation_and_unused_entry_bytes_are_rejected()
    {
        var before = Read(MsiCompoundFixture.Create());
        var expanded = MsiCompoundFixture.Create(signatures: true);
        var newSector = (uint)(expanded.Length / 512 - 1);
        Array.Resize(ref expanded, expanded.Length + 512);
        BinaryPrimitives.WriteUInt32LittleEndian(expanded.AsSpan(512 + 3 * 4, 4), newSector);
        BinaryPrimitives.WriteUInt32LittleEndian(expanded.AsSpan(512 + (int)newSector * 4, 4), 0xFFFFFFFE);
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            before, Read(expanded)));

        var hidden = MsiCompoundFixture.Create(signatures: true);
        hidden[1024 + 10 * 128 + 0x50] = 0x7F; // Inactive entry inside an otherwise permitted directory sector.
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            before, Read(hidden)));

        var withFreeTail = MsiCompoundFixture.Create();
        Array.Resize(ref withFreeTail, withFreeTail.Length + 20 * 512);
        Assert.ThrowsExactly<InvalidDataException>(() => MsiCompoundStorageComparer.RequireOnlySignatureChanges(
            Read(withFreeTail), Read(MsiCompoundFixture.Create(signatures: true))));
    }

    private static MsiCompoundStorage Read(byte[] bytes)
    {
        var path = Path.Combine(Path.GetTempPath(), "vantrel-cfb-" + Guid.NewGuid().ToString("N"));
        try
        {
            File.WriteAllBytes(path, bytes);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return MsiCompoundStorage.ReadFromHandle(stream.SafeFileHandle);
        }
        finally { File.Delete(path); }
    }
}
