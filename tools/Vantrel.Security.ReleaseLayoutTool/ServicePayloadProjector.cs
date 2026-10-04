using Vantrel.Security.ManifestTool;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>Projects only the canonical service components from raw SDK publish output.</summary>
public sealed class ServicePayloadProjector
{
    private static readonly StringComparer Names = StringComparer.OrdinalIgnoreCase;

    public void Project(string rawPublishDirectory, string finalServiceDirectory)
    {
        var source = RequireSafeDirectory(rawPublishDirectory);
        var destination = Path.TrimEndingDirectorySeparator(Path.GetFullPath(finalServiceDirectory));
        var parent = Path.GetDirectoryName(destination);
        if (string.IsNullOrEmpty(parent)) throw new IOException("Service destination is unavailable.");
        RequireSafeDirectory(parent);
        if (File.Exists(destination) || Directory.Exists(destination)) throw new IOException("Service destination already exists.");
        var projection = destination + ".projection";
        if (File.Exists(projection) || Directory.Exists(projection)) throw new IOException("Service projection residue is unavailable.");

        var sources = ResolveComponentSources(source);
        Directory.CreateDirectory(projection);
        try
        {
            foreach (var pair in sources)
                File.Copy(pair.Value, Path.Combine(projection, pair.Key), overwrite: false);
            ValidateExactFlatProjection(projection);
            Directory.Move(projection, destination);
        }
        finally
        {
            if (Directory.Exists(projection)) RemoveSafeProjectionResidue(projection);
        }
    }

    private static IReadOnlyDictionary<string, string> ResolveComponentSources(string source)
    {
        var expected = ReleasePayloadVerifier.ServiceComponents.Select(component => component.FileName).ToHashSet(StringComparer.Ordinal);
        var found = new Dictionary<string, string>(Names);
        foreach (var entry in Directory.EnumerateFileSystemEntries(source))
        {
            var name = Path.GetFileName(entry);
            if (!found.TryAdd(name, entry)) throw new IOException("Service publish output has case-colliding entries.");
            if (IsReparse(entry) || Directory.Exists(entry) || !File.Exists(entry))
                throw new IOException("Service publish output contains an unsafe entry.");
            var canonical = ReleasePayloadVerifier.ServiceComponents.SingleOrDefault(component => Names.Equals(component.FileName, name));
            if (canonical is null) continue;
            if (!string.Equals(canonical.FileName, name, StringComparison.Ordinal) || !expected.Remove(canonical.FileName))
                throw new IOException("Service component source is unsafe.");
        }
        if (expected.Count != 0) throw new IOException("Service component source is incomplete.");
        return ReleasePayloadVerifier.ServiceComponents.ToDictionary(component => component.FileName, component => found[component.FileName], StringComparer.Ordinal);
    }

    private static void ValidateExactFlatProjection(string projection)
    {
        var expected = ReleasePayloadVerifier.ServiceComponents.Select(component => component.FileName).ToHashSet(StringComparer.Ordinal);
        var entries = Directory.EnumerateFileSystemEntries(projection).ToArray();
        if (entries.Length != expected.Count || entries.Any(entry => !File.Exists(entry) || IsReparse(entry) ||
            (File.GetAttributes(entry) & FileAttributes.Directory) != 0 || !expected.Remove(Path.GetFileName(entry))))
            throw new IOException("Service projection is unsafe.");
    }

    private static string RequireSafeDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new IOException("Service directory is unavailable.");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        for (var current = new DirectoryInfo(full); current is not null; current = current.Parent)
            if (!current.Exists || IsReparse(current.FullName)) throw new IOException("Service directory is unavailable or redirected.");
        return full;
    }

    private static void RemoveSafeProjectionResidue(string projection)
    {
        var expected = ReleasePayloadVerifier.ServiceComponents.Select(component => component.FileName).ToHashSet(StringComparer.Ordinal);
        var entries = Directory.EnumerateFileSystemEntries(projection).ToArray();
        if (entries.Any(entry => !File.Exists(entry) || IsReparse(entry) ||
            (File.GetAttributes(entry) & FileAttributes.Directory) != 0 || !expected.Remove(Path.GetFileName(entry))))
            throw new IOException("Service projection residue is unsafe.");
        foreach (var entry in entries) File.Delete(entry);
        Directory.Delete(projection);
    }

    private static bool IsReparse(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
}
