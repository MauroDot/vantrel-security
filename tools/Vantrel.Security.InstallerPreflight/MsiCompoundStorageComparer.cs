using System.Buffers.Binary;
using System.Text;

namespace Vantrel.Security.InstallerPreflight;

/// <summary>
/// A deliberately narrow CFB transition: insert two root signature streams using
/// red-black insertion into existing directory slots. Capacity changes that need
/// a new directory, FAT, MiniFAT or DIFAT sector fail closed.
/// Native Authenticode verification remains independently mandatory.
/// </summary>
internal static class MsiCompoundStorageComparer
{
    internal const string Signature = "@root/\\u0005DigitalSignature";
    internal const string SignatureEx = "@root/\\u0005MsiDigitalSignatureEx";
    private const uint Free = 0xFFFFFFFF, End = 0xFFFFFFFE;
    private const string RootMini = "@root-mini-stream", Directory = "@directory";
    private const string MiniFat = "@mini-fat", Fat = "@fat", Difat = "@difat";

    internal static void RequireOnlySignatureChanges(MsiCompoundStorage before, MsiCompoundStorage after)
    {
        if (before.Entries.Keys.Any(name => name.EndsWith("/\\u0005DigitalSignature", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith("/\\u0005MsiDigitalSignatureEx", StringComparison.OrdinalIgnoreCase)) ||
            before.Entries.Count + 2 != after.Entries.Count ||
            before.HeaderSha256 != after.HeaderSha256 ||
            before.SectorSize != after.SectorSize ||
            after.SectorCount < before.SectorCount ||
            before.DirectoryCapacity != after.DirectoryCapacity ||
            before.FatCapacity != after.FatCapacity ||
            before.MiniFatCapacity != after.MiniFatCapacity)
            throw new InvalidDataException();

        foreach (var (name, original) in before.Entries)
        {
            if (!after.Entries.TryGetValue(name, out var current)) throw new InvalidDataException();
            if (name == "@root")
            {
                if (original.Kind != "Root" || current.Kind != "Root" ||
                    original.RawName != current.RawName || original.ClassId != current.ClassId ||
                    original.State != current.State || original.Created != current.Created ||
                    original.Start != current.Start || original.DirectoryId != current.DirectoryId ||
                    current.Size < original.Size) throw new InvalidDataException();
            }
            else if (original != current) throw new InvalidDataException();
        }
        foreach (var name in after.Entries.Keys)
            if (!before.Entries.ContainsKey(name) && name is not (Signature or SignatureEx))
                throw new InvalidDataException();

        var primary = RequireNewSignatureStream(after, Signature);
        var extended = RequireNewSignatureStream(after, SignatureEx);
        var addedMiniBytes = MiniAllocation(primary) + MiniAllocation(extended);
        if (after.Entries["@root"].Size - before.Entries["@root"].Size != addedMiniBytes ||
            before.RootMiniSize % 64 != 0 || after.RootMiniSize % 64 != 0 ||
            (ulong)before.RootMiniSize + addedMiniBytes != (ulong)after.RootMiniSize)
            throw new InvalidDataException();

        RequireDirectoryInsertion(before, after, primary, extended);
        RequireContainerAllocation(before, after);
    }

    private static MsiStorageEntry RequireNewSignatureStream(MsiCompoundStorage after, string name)
    {
        if (!after.Entries.TryGetValue(name, out var stream) || stream.Kind != "Stream" || stream.Size == 0 ||
            stream.ClassId != "00000000000000000000000000000000" || stream.State != 0 ||
            stream.Created != 0 || stream.Modified != 0 || stream.Sha256.Length != 64)
            throw new InvalidDataException();
        return stream;
    }

    private static ulong MiniAllocation(MsiStorageEntry stream) => stream.Size < 4096
        ? checked((stream.Size + 63) / 64 * 64) : 0;

    private static void RequireDirectoryInsertion(MsiCompoundStorage before, MsiCompoundStorage after,
        MsiStorageEntry primary, MsiStorageEntry extended)
    {
        // The two first unused slots are the only new entries. SignTool's observed
        // insertion order is Extended, then Primary. Other layouts fail closed.
        var empty = Enumerable.Range(1, before.DirectoryCapacity)
            .Where(id => before.DirectoryNode(id).Kind == 0).Take(2).ToArray();
        if (empty.Length != 2 || extended.DirectoryId != empty[0] || primary.DirectoryId != empty[1])
            throw new InvalidDataException();
        var states = new Dictionary<uint, TreeNode>();
        for (var id = 1; id < before.DirectoryCapacity; id++)
        {
            var old = before.DirectoryNode(id);
            if (old.Kind is 1 or 2) states.Add((uint)id, new((uint)id, old.Name, old.Color, old.Left, old.Right, old.Child));
        }
        var rootChild = before.DirectoryNode(0).Child;
        AttachParents(states, rootChild, Free);
        Insert(states, ref rootChild, (uint)extended.DirectoryId, "\u0005MsiDigitalSignatureEx");
        Insert(states, ref rootChild, (uint)primary.DirectoryId, "\u0005DigitalSignature");
        if (after.DirectoryNode(0).Child != rootChild) throw new InvalidDataException();

        for (var id = 0; id < before.DirectoryCapacity; id++)
        {
            var old = before.DirectoryNode(id);
            var next = after.DirectoryNode(id);
            var original = before.DirectoryEntryBytes(id);
            var current = after.DirectoryEntryBytes(id);
            if (id == 0)
            {
                if (old.Color != next.Color || old.Left != next.Left || old.Right != next.Right ||
                    old.Child != next.Child) throw new InvalidDataException();
                RequireSameExcept(original, current,
                    new HashSet<int>(Enumerable.Range(0x6C, 8).Concat(Enumerable.Range(0x78, 8))));
            }
            else if (id == extended.DirectoryId || id == primary.DirectoryId)
            {
                var stream = id == extended.DirectoryId ? extended : primary;
                RequireCanonicalNewEntry(current, states[(uint)id], stream);
            }
            else if (old.Kind == 0)
            {
                if (!original.SequenceEqual(current)) throw new InvalidDataException();
            }
            else
            {
                if (!states.TryGetValue((uint)id, out var expected) ||
                    next.Name != old.Name || next.Kind != old.Kind ||
                    next.Color != expected.Color || next.Left != expected.Left ||
                    next.Right != expected.Right || next.Child != expected.Child)
                    throw new InvalidDataException();
                RequireSameExcept(original, current, new HashSet<int>(Enumerable.Range(0x43, 9)));
            }
        }
    }

    private static void RequireSameExcept(ReadOnlySpan<byte> original, ReadOnlySpan<byte> current,
        IReadOnlySet<int> allowed)
    {
        for (var index = 0; index < 128; index++)
            if (!allowed.Contains(index) && original[index] != current[index])
                throw new InvalidDataException();
    }

    private static void RequireCanonicalNewEntry(ReadOnlySpan<byte> raw, TreeNode expected, MsiStorageEntry stream)
    {
        var name = Encoding.Unicode.GetBytes(expected.Name + "\0");
        if (name.Length > 64 || stream.Start == Free || stream.Size == 0) throw new InvalidDataException();
        Span<byte> canonical = stackalloc byte[128];
        name.CopyTo(canonical);
        BinaryPrimitives.WriteUInt16LittleEndian(canonical.Slice(0x40, 2), (ushort)name.Length);
        canonical[0x42] = 2;
        canonical[0x43] = expected.Color;
        BinaryPrimitives.WriteUInt32LittleEndian(canonical.Slice(0x44, 4), expected.Left);
        BinaryPrimitives.WriteUInt32LittleEndian(canonical.Slice(0x48, 4), expected.Right);
        BinaryPrimitives.WriteUInt32LittleEndian(canonical.Slice(0x4C, 4), Free);
        BinaryPrimitives.WriteUInt32LittleEndian(canonical.Slice(0x74, 4), stream.Start);
        BinaryPrimitives.WriteUInt64LittleEndian(canonical.Slice(0x78, 8), stream.Size);
        if (!raw.SequenceEqual(canonical)) throw new InvalidDataException();
    }

    private static void RequireContainerAllocation(MsiCompoundStorage before, MsiCompoundStorage after)
    {
        foreach (var owner in new[] { Directory, MiniFat })
            if (!before.SectorChain(owner).SequenceEqual(after.SectorChain(owner)))
                throw new InvalidDataException();
        foreach (var owner in new[] { Fat, Difat })
            if (!before.SectorOwners.Where(item => item.Value == owner).Select(item => item.Key).Order()
                .SequenceEqual(after.SectorOwners.Where(item => item.Value == owner).Select(item => item.Key).Order()))
                throw new InvalidDataException();

        var oldRoot = before.SectorChain(RootMini);
        var newRoot = after.SectorChain(RootMini);
        if (newRoot.Count != (after.RootMiniSize + after.SectorSize - 1) / after.SectorSize ||
            oldRoot.Count > newRoot.Count || !oldRoot.SequenceEqual(newRoot.Take(oldRoot.Count)))
            throw new InvalidDataException();
        var oldRootLast = oldRoot.Count == 0 ? Free : oldRoot[^1];
        var firstNewRoot = oldRoot.Count == newRoot.Count ? Free : newRoot[oldRoot.Count];

        for (var index = 0; index < before.FatCapacity; index++)
        {
            var old = before.FatEntry(index);
            var next = after.FatEntry(index);
            if (old == next) continue;
            if ((uint)index == oldRootLast && old == End && next == firstNewRoot) continue;
            if (old != Free || !after.SectorOwners.TryGetValue((uint)index, out var owner) ||
                owner is not (Signature or SignatureEx or RootMini) ||
                before.SectorOwners.ContainsKey((uint)index)) throw new InvalidDataException();
        }
        var oldMiniSlots = before.RootMiniSize / 64;
        var newMiniSlots = after.RootMiniSize / 64;
        for (var index = 0; index < before.MiniFatCapacity; index++)
        {
            var old = before.MiniFatEntry(index);
            var next = after.MiniFatEntry(index);
            if (old == next) continue;
            if (index < oldMiniSlots || index >= newMiniSlots || old != Free ||
                !after.MiniOwners.TryGetValue((uint)index, out var owner) ||
                owner is not (Signature or SignatureEx)) throw new InvalidDataException();
        }
        for (var index = oldMiniSlots; index < newMiniSlots; index++)
            if (!after.MiniOwners.TryGetValue((uint)index, out var owner) ||
                owner is not (Signature or SignatureEx)) throw new InvalidDataException();

        foreach (var (id, owner) in before.SectorOwners)
        {
            if (!after.SectorOwners.TryGetValue(id, out var current) || current != owner)
                throw new InvalidDataException();
            if (owner is not (Fat or Directory or MiniFat or RootMini) &&
                before.OwnedSectorHashes[id] != after.OwnedSectorHashes[id])
                throw new InvalidDataException();
        }
        foreach (var (id, owner) in after.SectorOwners)
            if (!before.SectorOwners.ContainsKey(id) && owner is not (Signature or SignatureEx or RootMini))
                throw new InvalidDataException();
        for (var id = before.SectorCount; id < after.SectorCount; id++)
            if (!after.SectorOwners.ContainsKey((uint)id)) throw new InvalidDataException();
        foreach (var (id, hash) in before.FreeSectorHashes)
            if (after.FreeSectorHashes.TryGetValue(id, out var current) && current != hash)
                throw new InvalidDataException();
        foreach (var (id, owner) in before.MiniOwners)
            if (!after.MiniOwners.TryGetValue(id, out var current) || current != owner ||
                before.OwnedMiniHashes[id] != after.OwnedMiniHashes[id])
                throw new InvalidDataException();
        foreach (var (id, hash) in before.FreeMiniHashes)
            if (!after.FreeMiniHashes.TryGetValue(id, out var current) && current != hash)
                throw new InvalidDataException();

        // The old mini-stream's full physical allocation is immutable except for
        // precisely the appended mini sectors used by the signature streams.
        for (var position = 0; position < newRoot.Count * after.SectorSize; position++)
        {
            if (position >= before.RootMiniSize && position < after.RootMiniSize) continue;
            var newByte = after.PhysicalSector(newRoot[position / after.SectorSize])[position % after.SectorSize];
            if (position < oldRoot.Count * before.SectorSize)
            {
                var oldByte = before.PhysicalSector(oldRoot[position / before.SectorSize])[position % before.SectorSize];
                if (oldByte != newByte) throw new InvalidDataException();
            }
            else if (newByte != 0) throw new InvalidDataException();
        }
        foreach (var signature in new[] { Signature, SignatureEx })
        {
            var entry = after.Entries[signature];
            if (entry.Size < 4096)
            {
                var chain = after.MiniChain(signature);
                for (var position = checked((int)entry.Size); position < chain.Count * 64; position++)
                {
                    var absolute = checked((int)chain[position / 64] * 64 + position % 64);
                    var actual = after.RootMiniBytes[absolute];
                    if (absolute < oldRoot.Count * before.SectorSize)
                    {
                        var prior = before.PhysicalSector(oldRoot[absolute / before.SectorSize])[absolute % before.SectorSize];
                        if (actual != prior) throw new InvalidDataException();
                    }
                    else if (actual != 0) throw new InvalidDataException();
                }
            }
            else
            {
                var chain = after.SectorChain(signature);
                for (var position = checked((int)entry.Size); position < chain.Count * after.SectorSize; position++)
                    if (after.PhysicalSector(chain[position / after.SectorSize])[position % after.SectorSize] != 0)
                        throw new InvalidDataException();
            }
        }
    }

    private static void AttachParents(Dictionary<uint, TreeNode> states, uint id, uint parent)
    {
        if (id == Free) return;
        var node = states[id];
        node.Parent = parent;
        AttachParents(states, node.Left, id);
        AttachParents(states, node.Right, id);
    }

    private static void Insert(Dictionary<uint, TreeNode> states, ref uint root, uint id, string name)
    {
        var node = new TreeNode(id, name, 0, Free, Free, Free);
        var parent = Free;
        var current = root;
        while (current != Free)
        {
            parent = current;
            var comparison = MsiCompoundStorage.CompareNames(name, states[current].Name);
            if (comparison == 0) throw new InvalidDataException();
            current = comparison < 0 ? states[current].Left : states[current].Right;
        }
        node.Parent = parent;
        states.Add(id, node);
        if (parent == Free) root = id;
        else if (MsiCompoundStorage.CompareNames(name, states[parent].Name) < 0) states[parent].Left = id;
        else states[parent].Right = id;

        var z = id;
        while (states[z].Parent != Free && states[states[z].Parent].Color == 0)
        {
            var p = states[z].Parent;
            var g = states[p].Parent;
            if (g == Free) throw new InvalidDataException();
            if (p == states[g].Left)
            {
                var uncle = states[g].Right;
                if (uncle != Free && states[uncle].Color == 0)
                {
                    states[p].Color = 1; states[uncle].Color = 1; states[g].Color = 0; z = g;
                }
                else
                {
                    if (z == states[p].Right) { z = p; RotateLeft(states, ref root, z); p = states[z].Parent; g = states[p].Parent; }
                    states[p].Color = 1; states[g].Color = 0; RotateRight(states, ref root, g);
                }
            }
            else
            {
                var uncle = states[g].Left;
                if (uncle != Free && states[uncle].Color == 0)
                {
                    states[p].Color = 1; states[uncle].Color = 1; states[g].Color = 0; z = g;
                }
                else
                {
                    if (z == states[p].Left) { z = p; RotateRight(states, ref root, z); p = states[z].Parent; g = states[p].Parent; }
                    states[p].Color = 1; states[g].Color = 0; RotateLeft(states, ref root, g);
                }
            }
        }
        states[root].Color = 1;
    }

    private static void RotateLeft(Dictionary<uint, TreeNode> nodes, ref uint root, uint id)
    {
        var x = nodes[id]; var y = nodes[x.Right];
        x.Right = y.Left;
        if (y.Left != Free) nodes[y.Left].Parent = id;
        y.Parent = x.Parent;
        if (x.Parent == Free) root = y.Id;
        else if (id == nodes[x.Parent].Left) nodes[x.Parent].Left = y.Id;
        else nodes[x.Parent].Right = y.Id;
        y.Left = id; x.Parent = y.Id;
    }
    private static void RotateRight(Dictionary<uint, TreeNode> nodes, ref uint root, uint id)
    {
        var x = nodes[id]; var y = nodes[x.Left];
        x.Left = y.Right;
        if (y.Right != Free) nodes[y.Right].Parent = id;
        y.Parent = x.Parent;
        if (x.Parent == Free) root = y.Id;
        else if (id == nodes[x.Parent].Left) nodes[x.Parent].Left = y.Id;
        else nodes[x.Parent].Right = y.Id;
        y.Right = id; x.Parent = y.Id;
    }

    private sealed class TreeNode(uint id, string name, byte color, uint left, uint right, uint child)
    {
        internal uint Id = id, Left = left, Right = right, Child = child, Parent = Free;
        internal string Name = name;
        internal byte Color = color;
    }
}
