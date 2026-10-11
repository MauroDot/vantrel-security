using System.Buffers.Binary;
using System.Text;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class InstalledV2NativeStreamTests
{
    [TestMethod]
    public void Complete_file_identity_does_not_fold_high_and_low_index_words()
    {
        // The former IndexLow XOR (IndexHigh << 16) gave both pairs the same value.
        var first = new ComponentInspectionNative.Metadata(false, false, 10,
            ComponentInspectionNative.ComposeFileIndex(1, 0), 1, 7);
        var second = new ComponentInspectionNative.Metadata(false, false, 10,
            ComponentInspectionNative.ComposeFileIndex(0, 0x10000), 1, 7);
        Assert.AreNotEqual(first, second);
        Assert.AreNotEqual(first.Identity, second.Identity);
        Assert.AreNotEqual(first, first with { VolumeSerial = 8 });
    }

    [TestMethod]
    public void Bounded_stream_parser_accepts_only_one_unnamed_file_stream()
    {
        Assert.IsTrue(ComponentInspectionNative.ParseOnlyDefaultDataStream(Entries("::$DATA"), directory: false));
        Assert.IsFalse(ComponentInspectionNative.ParseOnlyDefaultDataStream(Entries("::$DATA"), directory: true));
        Assert.IsFalse(ComponentInspectionNative.ParseOnlyDefaultDataStream(Entries(":hidden:$DATA"), directory: false));
        Assert.IsFalse(ComponentInspectionNative.ParseOnlyDefaultDataStream(Entries("::$DATA", ":hidden:$DATA"), directory: false));
        Assert.IsFalse(ComponentInspectionNative.ParseOnlyDefaultDataStream(Entries(":hidden:$DATA"), directory: true));
    }

    [TestMethod]
    public void Stream_parser_rejects_truncation_bad_offsets_and_oversized_names()
    {
        var valid = Entries("::$DATA");
        Assert.ThrowsException<IOException>(() => ComponentInspectionNative.ParseOnlyDefaultDataStream(valid.AsSpan(0, 23), false));
        var badName = valid.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(badName.AsSpan(4), 1026);
        Assert.ThrowsException<IOException>(() => ComponentInspectionNative.ParseOnlyDefaultDataStream(badName, false));
        var badOffset = Entries("::$DATA", ":hidden:$DATA");
        BinaryPrimitives.WriteUInt32LittleEndian(badOffset, 8);
        Assert.ThrowsException<IOException>(() => ComponentInspectionNative.ParseOnlyDefaultDataStream(badOffset, false));
        var misaligned = Entries("::$DATA", ":hidden:$DATA");
        BinaryPrimitives.WriteUInt32LittleEndian(misaligned, 41);
        Assert.ThrowsException<IOException>(() => ComponentInspectionNative.ParseOnlyDefaultDataStream(misaligned, false));
        var negativeSize = valid.ToArray();
        BinaryPrimitives.WriteInt64LittleEndian(negativeSize.AsSpan(8), -1);
        Assert.ThrowsException<IOException>(() => ComponentInspectionNative.ParseOnlyDefaultDataStream(negativeSize, false));
        var excessiveEntries = Entries(Enumerable.Repeat("::$DATA", 17).ToArray());
        Assert.ThrowsException<IOException>(() => ComponentInspectionNative.ParseOnlyDefaultDataStream(excessiveEntries, false));
    }

    [TestMethod]
    public void Native_stream_enumeration_is_bound_to_the_open_file_and_directory_handles()
    {
        if (!OperatingSystem.IsWindows()) Assert.Inconclusive("Windows stream API is required.");
        var root = Path.Combine(Path.GetTempPath(), "vantrel-stream-bound-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "runtime.dll");
            File.WriteAllText(path, "runtime");
            using var file = ComponentInspectionNative.OpenProtected(path);
            using var directory = ComponentInspectionNative.OpenProtected(root, directory: true);
            Assert.IsTrue(ComponentInspectionNative.HasOnlyDefaultDataStream(file));
            Assert.IsTrue(ComponentInspectionNative.HasOnlyDefaultDataStream(directory, directory: true));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static byte[] Entries(params string[] names)
    {
        var lengths = names.Select(name => (24 + Encoding.Unicode.GetByteCount(name) + 7) & ~7).ToArray();
        var bytes = new byte[lengths.Sum()];
        var offset = 0;
        for (var i = 0; i < names.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset),
                i + 1 == names.Length ? 0u : checked((uint)lengths[i]));
            var name = Encoding.Unicode.GetBytes(names[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 4), checked((uint)name.Length));
            name.CopyTo(bytes.AsSpan(offset + 24));
            offset += lengths[i];
        }
        return bytes;
    }
}
