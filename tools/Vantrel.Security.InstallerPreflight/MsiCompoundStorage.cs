using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Vantrel.Security.InstallerPreflight.Tests")]

namespace Vantrel.Security.InstallerPreflight;

// Strict CFB inventory for the injected MSI signing gate. Native MSI signature
// verification remains a separate requirement; inventory alone is not approval.
internal sealed record MsiStorageEntry(string Name, string RawName, string Kind, ulong Size, string Sha256,
    string ClassId, uint State, ulong Created, ulong Modified, int DirectoryId, uint Start)
{
    internal string Report() => $"name={Name};kind={Kind};size={Size};sha256={Sha256};" +
        $"clsid={ClassId};state={State:X8};created={Created:X16};modified={Modified:X16};" +
        $"id={DirectoryId};start={Start:X8}";
}

internal sealed record MsiDirectoryNode(int Id, string Name, byte Kind, byte Color,
    uint Left, uint Right, uint Child);

internal sealed class MsiCompoundStorage
{
    private const uint Free = 0xFFFFFFFF, End = 0xFFFFFFFE, FatSector = 0xFFFFFFFD, DifSector = 0xFFFFFFFC;
    private const int MaximumBytes = 512 * 1024 * 1024;
    private readonly byte[] _bytes;
    private readonly int _sectorSize;
    private readonly uint[] _fat;
    private readonly uint[] _miniFat;
    private readonly byte[] _miniStream;
    private readonly byte[] _directoryBytes;
    private readonly List<DirectoryEntry> _directory;
    private readonly Dictionary<string, List<uint>> _sectorChains = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<uint>> _miniChains = new(StringComparer.Ordinal);
    private readonly SortedDictionary<string, MsiStorageEntry> _items = new(StringComparer.Ordinal);
    private readonly HashSet<int> _visited = [];
    private readonly Dictionary<uint, string> _sectorOwners = [];
    private readonly Dictionary<uint, string> _miniOwners = [];
    private readonly Dictionary<uint, string> _freeSectorHashes = [];
    private readonly Dictionary<uint, string> _freeMiniHashes = [];
    private readonly Dictionary<uint, string> _ownedSectorHashes = [];
    private readonly Dictionary<uint, string> _ownedMiniHashes = [];

    internal IReadOnlyDictionary<string, MsiStorageEntry> Entries => _items;
    internal IReadOnlyDictionary<uint, string> SectorOwners => _sectorOwners;
    internal IReadOnlyDictionary<uint, string> MiniOwners => _miniOwners;
    internal IReadOnlyDictionary<uint, string> FreeSectorHashes => _freeSectorHashes;
    internal IReadOnlyDictionary<uint, string> FreeMiniHashes => _freeMiniHashes;
    internal IReadOnlyDictionary<uint, string> OwnedSectorHashes => _ownedSectorHashes;
    internal IReadOnlyDictionary<uint, string> OwnedMiniHashes => _ownedMiniHashes;
    internal string HeaderSha256 => Convert.ToHexString(SHA256.HashData(_bytes.AsSpan(0, _sectorSize)));
    internal string WholeFileSha256 => Convert.ToHexString(SHA256.HashData(_bytes));
    internal int SectorSize => _sectorSize;
    internal int SectorCount => (_bytes.Length - _sectorSize) / _sectorSize;
    internal int DirectoryCapacity => _directory.Count;
    internal int FatCapacity => _fat.Length;
    internal int MiniFatCapacity => _miniFat.Length;
    internal int RootMiniSize => _miniStream.Length;
    internal ReadOnlySpan<byte> RootMiniBytes => _miniStream;
    internal uint FatEntry(int id) => _fat[id];
    internal uint MiniFatEntry(int id) => _miniFat[id];
    internal ReadOnlySpan<byte> DirectoryEntryBytes(int id) => _directoryBytes.AsSpan(id * 128, 128);
    internal MsiDirectoryNode DirectoryNode(int id)
    {
        var node = _directory[id];
        return new(id, node.Name, node.Kind, node.Color, node.Left, node.Right, node.Child);
    }
    internal IReadOnlyList<uint> SectorChain(string owner) => _sectorChains.TryGetValue(owner, out var chain)
        ? chain.AsReadOnly() : Array.Empty<uint>();
    internal IReadOnlyList<uint> MiniChain(string owner) => _miniChains.TryGetValue(owner, out var chain)
        ? chain.AsReadOnly() : Array.Empty<uint>();
    internal ReadOnlySpan<byte> PhysicalSector(uint id) => Sector(id);

    internal static MsiCompoundStorage ReadFromHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle)
    {
        var size = RandomAccess.GetLength(handle);
        if (size is < 512 or > MaximumBytes) throw new InvalidDataException();
        var bytes = new byte[checked((int)size)];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var count = RandomAccess.Read(handle, bytes.AsSpan(offset), offset);
            if (count <= 0) throw new InvalidDataException();
            offset += count;
        }
        if (RandomAccess.GetLength(handle) != size) throw new InvalidDataException();
        return new MsiCompoundStorage(bytes);
    }

    private MsiCompoundStorage(byte[] bytes)
    {
        _bytes = bytes;
        if (!bytes.AsSpan(0, 8).SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }) ||
            U16(0x1C) != 0xFFFE || U16(0x20) != 6 || U16(0x1A) is not (3 or 4)) throw new InvalidDataException();
        _sectorSize = 1 << U16(0x1E);
        if (_sectorSize != (U16(0x1A) == 3 ? 512 : 4096) || bytes.Length < _sectorSize ||
            (bytes.Length - _sectorSize) % _sectorSize != 0 || U32(0x38) != 4096) throw new InvalidDataException();
        for (var offset = 512; offset < _sectorSize; offset++)
            if (bytes[offset] != 0) throw new InvalidDataException();
        var sectorCount = (bytes.Length - _sectorSize) / _sectorSize;
        if (sectorCount <= 0) throw new InvalidDataException();

        var fatCount = U32(0x2C);
        if (fatCount == 0 || fatCount > sectorCount) throw new InvalidDataException();
        var fatSectors = new List<uint>();
        for (var index = 0; index < 109; index++)
        {
            var id = U32(0x4C + index * 4);
            if (id != Free) fatSectors.Add(id);
        }
        var difat = U32(0x44);
        var difatCount = U32(0x48);
        if (difatCount > sectorCount) throw new InvalidDataException();
        var difatSeen = new HashSet<uint>();
        for (var index = 0; index < difatCount; index++)
        {
            if (!difatSeen.Add(difat)) throw new InvalidDataException();
            MarkSector(difat, "@difat");
            var sector = Sector(difat);
            for (var item = 0; item < _sectorSize / 4 - 1; item++)
            {
                var id = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(item * 4, 4));
                if (id != Free) fatSectors.Add(id);
            }
            difat = BinaryPrimitives.ReadUInt32LittleEndian(sector[^4..]);
        }
        if (difat != End || fatSectors.Count != fatCount || fatSectors.Distinct().Count() != fatSectors.Count)
            throw new InvalidDataException();
        _fat = new uint[checked((int)fatCount * (_sectorSize / 4))];
        for (var index = 0; index < fatSectors.Count; index++)
        {
            var sector = Sector(fatSectors[index]);
            for (var item = 0; item < _sectorSize / 4; item++)
                _fat[index * (_sectorSize / 4) + item] = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(item * 4, 4));
        }
        if (_fat.Length < sectorCount) throw new InvalidDataException();
        foreach (var id in fatSectors)
        {
            MarkSector(id, "@fat");
            if (_fat[id] != FatSector) throw new InvalidDataException();
        }
        foreach (var id in difatSeen) if (_fat[id] != DifSector) throw new InvalidDataException();

        var miniCount = U32(0x40);
        var miniStart = U32(0x3C);
        if (miniCount > sectorCount || (miniCount == 0 && miniStart != End)) throw new InvalidDataException();
        var miniBytes = miniCount == 0 ? [] : Chain(miniStart, checked((ulong)miniCount * (uint)_sectorSize), _fat, _sectorSize, false, "@mini-fat");
        _miniFat = new uint[miniBytes.Length / 4];
        for (var index = 0; index < _miniFat.Length; index++)
            _miniFat[index] = BinaryPrimitives.ReadUInt32LittleEndian(miniBytes.AsSpan(index * 4, 4));

        _directoryBytes = Chain(U32(0x30), null, _fat, _sectorSize, false, "@directory");
        if (_directoryBytes.Length == 0 || _directoryBytes.Length % 128 != 0 ||
            _directoryBytes.Length / 128 > 4096) throw new InvalidDataException();
        _directory = [];
        for (var offset = 0; offset < _directoryBytes.Length; offset += 128)
            _directory.Add(DirectoryEntry.Parse(_directoryBytes.AsSpan(offset, 128)));
        if (_directory[0].Kind != 5 || _directory[0].Left != Free || _directory[0].Right != Free)
            throw new InvalidDataException();
        var root = _directory[0];
        _miniStream = root.Size == 0 ? [] : Chain(root.Start, root.Size, _fat, _sectorSize, false, "@root-mini-stream");

        AddDirectoryEntry(0, "@root", root);
        WalkSiblings(root.Child, "@root", new HashSet<int>(), null, null, false, true);
        for (var index = 1; index < _directory.Count; index++)
            if (_directory[index].Kind != 0 && !_visited.Contains(index)) throw new InvalidDataException();
        for (uint sector = 0; sector < sectorCount; sector++)
        {
            if (_sectorOwners.ContainsKey(sector))
            {
                if (_fat[sector] == Free) throw new InvalidDataException();
                _ownedSectorHashes.Add(sector, Convert.ToHexString(SHA256.HashData(Sector(sector))));
            }
            else
            {
                if (_fat[sector] != Free) throw new InvalidDataException();
                _freeSectorHashes.Add(sector, Convert.ToHexString(SHA256.HashData(Sector(sector))));
            }
        }
        for (uint mini = 0; mini < _miniStream.Length / 64; mini++)
        {
            if (_miniOwners.ContainsKey(mini))
            {
                if (mini >= _miniFat.Length || _miniFat[mini] == Free) throw new InvalidDataException();
                _ownedMiniHashes.Add(mini, Convert.ToHexString(SHA256.HashData(_miniStream.AsSpan((int)mini * 64, 64))));
            }
            else
            {
                if (mini < _miniFat.Length && _miniFat[mini] != Free) throw new InvalidDataException();
                _freeMiniHashes.Add(mini, Convert.ToHexString(SHA256.HashData(_miniStream.AsSpan((int)mini * 64, 64))));
            }
        }
        for (var mini = _miniStream.Length / 64; mini < _miniFat.Length; mini++)
            if (_miniFat[mini] != Free) throw new InvalidDataException();
    }

    private void WalkSiblings(uint id, string parent, HashSet<int> recursion,
        string? lower, string? upper, bool parentRed, bool top)
    {
        if (id == Free) return;
        if (id >= _directory.Count || !recursion.Add((int)id) || !_visited.Add((int)id)) throw new InvalidDataException();
        var entry = _directory[(int)id];
        if (entry.Kind is not (1 or 2) || string.IsNullOrEmpty(entry.Name) ||
            (top && entry.Color != 1) || (parentRed && entry.Color == 0) ||
            (lower is not null && CompareNames(entry.Name, lower) <= 0) ||
            (upper is not null && CompareNames(entry.Name, upper) >= 0)) throw new InvalidDataException();
        WalkSiblings(entry.Left, parent, recursion, lower, entry.Name, entry.Color == 0, false);
        var path = parent + "/" + Escape(entry.Name);
        AddDirectoryEntry((int)id, path, entry);
        if (entry.Kind == 1) WalkSiblings(entry.Child, path, recursion, null, null, false, true);
        else if (entry.Child != Free) throw new InvalidDataException();
        WalkSiblings(entry.Right, parent, recursion, entry.Name, upper, entry.Color == 0, false);
        recursion.Remove((int)id);
    }

    internal static int CompareNames(string left, string right)
    {
        var length = left.Length.CompareTo(right.Length);
        if (length != 0) return length;
        for (var i = 0; i < left.Length; i++)
        {
            var comparison = char.ToUpperInvariant(left[i]).CompareTo(char.ToUpperInvariant(right[i]));
            if (comparison != 0) return comparison;
        }
        return 0;
    }

    private void AddDirectoryEntry(int id, string path, DirectoryEntry entry)
    {
        var content = entry.Kind == 2
            ? entry.Size == 0 ? [] : entry.Size < 4096
                ? Chain(entry.Start, entry.Size, _miniFat, 64, true, path)
                : Chain(entry.Start, entry.Size, _fat, _sectorSize, false, path)
            : [];
        if (!_items.TryAdd(path, new(path, entry.Name, entry.Kind switch { 1 => "Storage", 2 => "Stream", _ => "Root" },
            entry.Size, entry.Kind == 2 ? Convert.ToHexString(SHA256.HashData(content)) : "None",
            Convert.ToHexString(entry.Clsid), entry.State, entry.Created, entry.Modified, id, entry.Start)))
            throw new InvalidDataException();
    }

    private byte[] Chain(uint start, ulong? length, uint[] fat, int unit, bool mini, string owner)
    {
        if (start == End || start == Free) throw new InvalidDataException();
        var visited = new HashSet<uint>();
        var physical = mini ? null : new List<uint>();
        var miniature = mini ? new List<uint>() : null;
        using var output = new MemoryStream();
        var current = start;
        while (current != End)
        {
            if (current >= fat.Length || !visited.Add(current) || visited.Count > MaximumBytes / unit)
                throw new InvalidDataException();
            if (mini)
            {
                if (!_miniOwners.TryAdd(current, owner)) throw new InvalidDataException();
                miniature!.Add(current);
                var offset = checked((long)current * unit);
                if (offset + unit > _miniStream.Length) throw new InvalidDataException();
                output.Write(_miniStream.AsSpan((int)offset, unit));
            }
            else
            {
                MarkSector(current, owner);
                physical!.Add(current);
                output.Write(Sector(current));
            }
            current = fat[current];
            if (current is Free or FatSector or DifSector) throw new InvalidDataException();
        }
        if (physical is not null && !_sectorChains.TryAdd(owner, physical)) throw new InvalidDataException();
        if (miniature is not null && !_miniChains.TryAdd(owner, miniature)) throw new InvalidDataException();
        if (length is null) return output.ToArray();
        var exact = checked((long)length.Value);
        if (exact > output.Length || (exact == 0 && output.Length != 0) ||
            output.Length - exact >= unit) throw new InvalidDataException();
        var bytes = output.ToArray();
        Array.Resize(ref bytes, (int)exact);
        return bytes;
    }

    private void MarkSector(uint sector, string owner)
    {
        if (!_sectorOwners.TryAdd(sector, owner)) throw new InvalidDataException();
    }

    private ReadOnlySpan<byte> Sector(uint id)
    {
        var offset = (long)_sectorSize * (id + 1L);
        if (offset < _sectorSize || offset + _sectorSize > _bytes.Length) throw new InvalidDataException();
        return _bytes.AsSpan((int)offset, _sectorSize);
    }
    private ushort U16(int offset) => BinaryPrimitives.ReadUInt16LittleEndian(_bytes.AsSpan(offset, 2));
    private uint U32(int offset) => BinaryPrimitives.ReadUInt32LittleEndian(_bytes.AsSpan(offset, 4));
    private static string Escape(string value)
    {
        var output = new StringBuilder();
        foreach (var ch in value)
            if (ch is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '-' or '_') output.Append(ch);
            else output.Append("\\u").Append(((int)ch).ToString("X4"));
        return output.ToString();
    }

    private sealed record DirectoryEntry(string Name, byte Kind, byte Color, uint Left, uint Right, uint Child,
        byte[] Clsid, uint State, ulong Created, ulong Modified, uint Start, ulong Size)
    {
        internal static DirectoryEntry Parse(ReadOnlySpan<byte> raw)
        {
            var kind = raw[0x42];
            var color = raw[0x43];
            if (color is not (0 or 1)) throw new InvalidDataException();
            if (kind == 0) return new("", 0, color, Free, Free, Free, [], 0, 0, 0, End, 0);
            if (kind is not (1 or 2 or 5)) throw new InvalidDataException();
            var nameBytes = BinaryPrimitives.ReadUInt16LittleEndian(raw.Slice(0x40, 2));
            if (nameBytes is < 2 or > 64 || nameBytes % 2 != 0 || raw[nameBytes - 2] != 0 || raw[nameBytes - 1] != 0)
                throw new InvalidDataException();
            var name = new UnicodeEncoding(false, false, true).GetString(raw.Slice(0, nameBytes - 2));
            if (name.Contains('\0') || name.IndexOfAny(['/', '\\', ':', '!']) >= 0) throw new InvalidDataException();
            return new(name, kind, color, BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(0x44, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(0x48, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(0x4C, 4)), raw.Slice(0x50, 16).ToArray(),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(0x60, 4)),
                BinaryPrimitives.ReadUInt64LittleEndian(raw.Slice(0x64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(raw.Slice(0x6C, 8)),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(0x74, 4)),
                BinaryPrimitives.ReadUInt64LittleEndian(raw.Slice(0x78, 8)));
        }
    }
}
