using System.Buffers.Binary;
using System.Text;

namespace Vantrel.Security.InstallerPreflight.Tests;

// Structurally valid, disposable CFB input for injected orchestration tests; it is not an MSI database.
internal static class MsiCompoundFixture
{
    private const uint Free = 0xFFFFFFFF, End = 0xFFFFFFFE, FatSector = 0xFFFFFFFD;
    internal static byte[] Create(bool signatures = false, string? changed = null, bool extraNested = false,
        ulong rootModified = 0, bool version4 = false)
    {
        var sectorSize = version4 ? 4096 : 512;
        int Offset(int sector) => (sector + 1) * sectorSize;
        var nodes = new List<Node>
        {
            new("Root Entry", 5, null),
            new("Table", 2, Fill(65, (byte)(changed == "Table" ? 0xD1 : 0x11))),
            new("\u0005SummaryInformation", 2, Fill(90, (byte)(changed == "Summary" ? 0xD2 : 0x22))),
            new("Cab", 2, Fill(4096, (byte)(changed == "Cab" ? 0xD3 : 0x33))),
            new("Nested", 1, null),
            new("Property", 2, Fill(73, (byte)(changed == "Property" ? 0xD4 : 0x44)))
        };
        if (extraNested) nodes.Add(new("Extra", 2, Fill(45, 0xEE)));
        var signatureIndex = nodes.Count;
        if (signatures)
        {
            nodes.Add(new("\u0005MsiDigitalSignatureEx", 2, Fill(32, 0xA2)));
            nodes.Add(new("\u0005DigitalSignature", 2, Fill(5000, 0xA1)));
        }

        // A sorted sibling tree before and after Ex-then-Primary insertion.
        nodes[0].Child = 1;
        nodes[1].Color = 1; nodes[1].Left = 3; nodes[1].Right = signatures ? 2u : 4u;
        nodes[3].Color = 1;
        nodes[4].Color = 1; nodes[4].Right = signatures ? (uint)(signatureIndex + 1) : 2u;
        nodes[2].Color = 0;
        if (signatures) { nodes[2].Left = 4; nodes[2].Right = (uint)signatureIndex; }
        nodes[4].Child = 5;
        nodes[5].Color = 1;
        if (extraNested) { nodes[5].Left = 6; nodes[6].Color = 0; }
        if (signatures) { nodes[signatureIndex].Color = 1; nodes[signatureIndex + 1].Color = 0; }

        var miniData = new List<byte>();
        var miniFat = new List<uint>();
        foreach (var node in nodes.Where(node => node.Kind == 2 && node.Content!.Length < 4096))
        {
            node.Start = (uint)miniFat.Count;
            var blocks = (node.Content!.Length + 63) / 64;
            for (var i = 0; i < blocks; i++)
            {
                miniFat.Add(i == blocks - 1 ? End : (uint)miniFat.Count + 1);
                var piece = new byte[64];
                Array.Copy(node.Content, i * 64, piece, 0, Math.Min(64, node.Content.Length - i * 64));
                miniData.AddRange(piece);
            }
        }

        var directorySectors = 3;
        var miniFatSectors = (miniFat.Count * 4 + sectorSize - 1) / sectorSize;
        var rootMiniSectors = (miniData.Count + sectorSize - 1) / sectorSize;
        var next = 1; // FAT occupies physical sector zero.
        var directoryStart = next; next += directorySectors;
        var miniFatStart = miniFatSectors == 0 ? End : (uint)next; next += miniFatSectors;
        var rootMiniStart = rootMiniSectors == 0 ? End : (uint)next; next += rootMiniSectors;
        foreach (var node in nodes.Where(node => node.Kind == 2 && node.Content!.Length >= 4096))
        {
            node.Start = (uint)next;
            next += (node.Content!.Length + sectorSize - 1) / sectorSize;
        }
        if (next > sectorSize / 4) throw new InvalidOperationException();
        var bytes = new byte[(next + 1) * sectorSize];
        var fat = Enumerable.Repeat(Free, sectorSize / 4).ToArray();
        fat[0] = FatSector;
        Chain(fat, directoryStart, directorySectors);
        if (miniFatSectors != 0) Chain(fat, (int)miniFatStart, miniFatSectors);
        if (rootMiniSectors != 0) Chain(fat, (int)rootMiniStart, rootMiniSectors);
        foreach (var node in nodes.Where(node => node.Kind == 2 && node.Content!.Length >= 4096))
            Chain(fat, (int)node.Start, (node.Content!.Length + sectorSize - 1) / sectorSize);
        for (var i = 0; i < fat.Length; i++) Write32(bytes, sectorSize + i * 4, fat[i]);

        if (miniFatSectors != 0)
        {
            for (var i = 0; i < miniFatSectors * sectorSize / 4; i++)
                Write32(bytes, Offset((int)miniFatStart) + i * 4, i < miniFat.Count ? miniFat[i] : Free);
        }
        miniData.CopyTo(bytes, Offset((int)rootMiniStart));
        foreach (var node in nodes.Where(node => node.Kind == 2 && node.Content!.Length >= 4096))
            node.Content!.CopyTo(bytes, Offset((int)node.Start));

        nodes[0].Start = rootMiniStart;
        for (var i = 0; i < nodes.Count; i++)
        {
            var node = nodes[i];
            var offset = Offset(directoryStart) + i * 128;
            var name = Encoding.Unicode.GetBytes(node.Name + "\0");
            name.CopyTo(bytes, offset);
            Write16(bytes, offset + 0x40, (ushort)name.Length);
            bytes[offset + 0x42] = node.Kind;
            bytes[offset + 0x43] = node.Color;
            Write32(bytes, offset + 0x44, node.Left);
            Write32(bytes, offset + 0x48, node.Right);
            Write32(bytes, offset + 0x4C, node.Child);
            Write64(bytes, offset + 0x6C, i == 0 ? rootModified : 0);
            Write32(bytes, offset + 0x74, node.Start);
            Write64(bytes, offset + 0x78, i == 0 ? (ulong)miniData.Count : (ulong)(node.Content?.Length ?? 0));
        }

        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(bytes, 0);
        Write16(bytes, 0x18, 0x003E); Write16(bytes, 0x1A, (ushort)(version4 ? 4 : 3)); Write16(bytes, 0x1C, 0xFFFE);
        Write16(bytes, 0x1E, (ushort)(version4 ? 12 : 9)); Write16(bytes, 0x20, 6);
        Write32(bytes, 0x28, version4 ? (uint)directorySectors : 0);
        Write32(bytes, 0x2C, 1); Write32(bytes, 0x30, (uint)directoryStart);
        Write32(bytes, 0x38, 4096); Write32(bytes, 0x3C, miniFatStart);
        Write32(bytes, 0x40, (uint)miniFatSectors); Write32(bytes, 0x44, End);
        for (var i = 0; i < 109; i++) Write32(bytes, 0x4C + i * 4, i == 0 ? 0u : Free);
        return bytes;
    }

    private static byte[] Fill(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static void Chain(uint[] fat, int start, int count)
    {
        for (var i = 0; i < count; i++) fat[start + i] = i == count - 1 ? End : (uint)(start + i + 1);
    }
    private static void Write16(byte[] bytes, int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset, 2), value);
    private static void Write32(byte[] bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset, 4), value);
    private static void Write64(byte[] bytes, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset, 8), value);

    private sealed class Node(string name, byte kind, byte[]? content)
    {
        internal string Name = name;
        internal byte Kind = kind;
        internal byte Color;
        internal byte[]? Content = content;
        internal uint Left = Free, Right = Free, Child = Free, Start = End;
    }
}
