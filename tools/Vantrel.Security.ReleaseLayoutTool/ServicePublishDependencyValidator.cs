using System.Collections.ObjectModel;
using System.Text.Json;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>Build-only file observed and hash-bound outside the deployable inventory.</summary>
public sealed record ServicePublishExcludedBuildArtifact(string RelativePath, string Sha256);

/// <summary>Separates deployable files from an explicitly approved SDK copy of the source lockfile.</summary>
public sealed class ServicePublishDependencyValidation
{
    internal ServicePublishDependencyValidation(IReadOnlyList<TrustedManifestV2File> deployableFiles,
        IReadOnlyList<ServicePublishExcludedBuildArtifact> excludedBuildArtifacts)
    {
        DeployableFiles = new ReadOnlyCollection<TrustedManifestV2File>(deployableFiles.ToArray());
        ExcludedBuildArtifacts = new ReadOnlyCollection<ServicePublishExcludedBuildArtifact>(excludedBuildArtifacts.ToArray());
    }

    public IReadOnlyList<TrustedManifestV2File> DeployableFiles { get; }
    public IReadOnlyList<ServicePublishExcludedBuildArtifact> ExcludedBuildArtifacts { get; }
}

/// <summary>
/// Checks the internal consistency of one controlled, framework-dependent win-x64 Service
/// publish. This is not a release authorization: a matching directory and .deps.json can both
/// be incomplete unless separately bound to a clean, locked SDK build.
/// </summary>
public static class ServicePublishDependencyValidator
{
    private const string RuntimeTarget = ".NETCoreApp,Version=v10.0/win-x64";
    private const string SourceLockFileName = "packages.lock.json";
    private const string NeutralTarget = ".NETCoreApp,Version=v10.0";
    private const string Invalid = "Service publish dependency closure is invalid.";
    private const string PlaceholderHash = "0000000000000000000000000000000000000000000000000000000000000000";

    private static readonly IReadOnlyDictionary<string, string> DirectDependencies =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Microsoft.Extensions.Hosting.WindowsServices"] = "10.0.12",
            ["System.ServiceProcess.ServiceController"] = "10.0.12",
            ["Vantrel.Security.Core"] = "0.1.0",
            ["Vantrel.Security.Infrastructure"] = "0.1.0"
        });

    private static readonly string[] RequiredSupportingFiles =
    [
        "Vantrel.Security.Service.exe",
        ServicePublishFileSnapshot.DepsFileName,
        ServicePublishFileSnapshot.RuntimeConfigFileName,
        "appsettings.json"
    ];

    private static readonly HashSet<string> OptionalSupportingFiles = new(StringComparer.Ordinal)
    {
        "appsettings.Development.json",
        "Vantrel.Security.Service.pdb",
        "Vantrel.Security.Core.pdb",
        "Vantrel.Security.Infrastructure.pdb"
    };

    /// <summary>
    /// Returns the exact measured, ordered v2 deployable inventory when no build residue is
    /// present. No production signer, installer, or updater calls this method.
    /// </summary>
    public static IReadOnlyList<TrustedManifestV2File> Validate(string publishRoot)
    {
        return ValidateCore(publishRoot, approvedSourceLockSha256: null).DeployableFiles;
    }

    /// <summary>
    /// Accepts only an exact root-level SDK copy of a separately approved Service source
    /// packages.lock.json. The caller must establish the source hash from its locked build;
    /// equality proves content, not historical file-copy provenance.
    /// </summary>
    public static ServicePublishDependencyValidation ValidateSdkPublish(string publishRoot,
        string approvedSourceLockSha256)
    {
        if (approvedSourceLockSha256 is not { Length: 64 } ||
            approvedSourceLockSha256.Any(c => !char.IsAsciiDigit(c) && c is not (>= 'A' and <= 'F')))
            throw new InvalidDataException(Invalid);
        return ValidateCore(publishRoot, approvedSourceLockSha256);
    }

    private static ServicePublishDependencyValidation ValidateCore(string publishRoot,
        string? approvedSourceLockSha256)
    {
        var snapshot = ServicePublishFileSnapshot.Capture(publishRoot);
        ValidateRuntimeConfiguration(snapshot.RuntimeConfigBytes);
        var requiredPaths = ReadRequiredDependencyPaths(snapshot.DepsBytes);
        foreach (var path in RequiredSupportingFiles)
            AddUnique(requiredPaths, path);

        var deployable = new List<TrustedManifestV2File>(snapshot.Files.Count);
        var excluded = new List<ServicePublishExcludedBuildArtifact>(1);
        foreach (var file in snapshot.Files)
        {
            if (file.Path == SourceLockFileName)
            {
                if (approvedSourceLockSha256 is null || file.Sha256 != approvedSourceLockSha256)
                    throw new InvalidDataException(Invalid);
                excluded.Add(new(file.Path, file.Sha256));
            }
            else deployable.Add(file);
        }
        var measured = deployable;
        foreach (var file in measured)
            if (OptionalSupportingFiles.Contains(file.Path)) AddUnique(requiredPaths, file.Path);
        if (measured.Count != requiredPaths.Count)
            throw new InvalidDataException(Invalid);
        foreach (var file in measured)
        {
            if (!requiredPaths.TryGetValue(file.Path, out var canonical) ||
                !string.Equals(canonical, file.Path, StringComparison.Ordinal) ||
                !requiredPaths.Remove(file.Path))
                throw new InvalidDataException(Invalid);
        }
        if (requiredPaths.Count != 0) throw new InvalidDataException(Invalid);
        return new ServicePublishDependencyValidation(measured, excluded);
    }

    /// <summary>Also requires exact path and SHA-256 equality with a separately supplied inventory.</summary>
    public static IReadOnlyList<TrustedManifestV2File> Validate(string publishRoot,
        IReadOnlyList<TrustedManifestV2File> expectedInventory)
    {
        ArgumentNullException.ThrowIfNull(expectedInventory);
        var expected = expectedInventory.ToArray();
        var measured = Validate(publishRoot);
        if (expected.Length != measured.Count ||
            !expected.SequenceEqual(measured))
            throw new InvalidDataException(Invalid);
        return measured;
    }

    private static void ValidateRuntimeConfiguration(byte[] bytes)
    {
        using var document = ParseStrict(bytes);
        var root = RequireObject(document.RootElement);
        RequireFields(root, "runtimeOptions");
        var options = RequireObject(Required(root, "runtimeOptions"));
        RequireFields(options, "tfm", "framework", "configProperties");
        if (RequireString(Required(options, "tfm")) != "net10.0" ||
            options.TryGetProperty("frameworks", out _) ||
            options.TryGetProperty("includedFrameworks", out _))
            throw new InvalidDataException(Invalid);
        var framework = RequireObject(Required(options, "framework"));
        RequireFields(framework, "name", "version");
        if (RequireString(Required(framework, "name")) != "Microsoft.NETCore.App" ||
            RequireString(Required(framework, "version")) != "10.0.0")
            throw new InvalidDataException(Invalid);
        if (options.TryGetProperty("configProperties", out var properties))
        {
            RequireObject(properties);
            RequireFields(properties,
                "System.Reflection.Metadata.MetadataUpdater.IsSupported",
                "System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization",
                "CSWINRT_USE_WINDOWS_UI_XAML_PROJECTIONS");
            foreach (var property in properties.EnumerateObject())
                if (property.Value.ValueKind != JsonValueKind.False)
                    throw new InvalidDataException(Invalid);
        }
    }

    private static HashSet<string> ReadRequiredDependencyPaths(byte[] bytes)
    {
        using var document = ParseStrict(bytes);
        var root = RequireObject(document.RootElement);
        RequireFields(root, "runtimeTarget", "compilationOptions", "targets", "libraries");
        var targetIdentity = RequireObject(Required(root, "runtimeTarget"));
        RequireFields(targetIdentity, "name", "signature");
        if (RequireString(Required(targetIdentity, "name")) != RuntimeTarget ||
            (targetIdentity.TryGetProperty("signature", out var signature) &&
             signature.ValueKind != JsonValueKind.String))
            throw new InvalidDataException(Invalid);

        var targets = RequireObject(Required(root, "targets"));
        if (targets.EnumerateObject().Count() is < 1 or > 2)
            throw new InvalidDataException(Invalid);
        foreach (var target in targets.EnumerateObject())
        {
            if (target.Name != RuntimeTarget && target.Name != NeutralTarget)
                throw new InvalidDataException(Invalid);
            RequireObject(target.Value);
        }
        var selected = RequireObject(Required(targets, RuntimeTarget));
        if (selected.EnumerateObject().Count() is < 1 or > 1024)
            throw new InvalidDataException(Invalid);

        var libraries = RequireObject(Required(root, "libraries"));
        var byName = new Dictionary<string, Library>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in selected.EnumerateObject())
        {
            var (name, version) = ParseLibraryIdentity(item.Name);
            if (!byName.TryAdd(name, new Library(name, version, RequireObject(item.Value))))
                throw new InvalidDataException(Invalid);
            var library = RequireObject(Required(libraries, item.Name));
            var type = RequireString(Required(library, "type"));
            if (type is not ("package" or "project"))
                throw new InvalidDataException(Invalid);
        }
        if (libraries.EnumerateObject().Count() != byName.Count ||
            !byName.TryGetValue("Vantrel.Security.Service", out var service) ||
            service.Name != "Vantrel.Security.Service" || service.Version != "0.1.0")
            throw new InvalidDataException(Invalid);
        RequireRootDependencies(service.Body);
        CheckDependencyGraph(byName, service);

        var required = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var library in byName.Values)
            AddAssets(library.Body, required);
        foreach (var project in new[]
        {
            "Vantrel.Security.Service", "Vantrel.Security.Core", "Vantrel.Security.Infrastructure"
        })
            if (!required.Contains(project + ".dll"))
                throw new InvalidDataException(Invalid);
        return required;
    }

    private static void RequireRootDependencies(JsonElement rootLibrary)
    {
        var dependencies = RequireObject(Required(rootLibrary, "dependencies"));
        if (dependencies.EnumerateObject().Count() != DirectDependencies.Count)
            throw new InvalidDataException(Invalid);
        foreach (var dependency in DirectDependencies)
            if (RequireString(Required(dependencies, dependency.Key)) != dependency.Value)
                throw new InvalidDataException(Invalid);
    }

    private static void CheckDependencyGraph(Dictionary<string, Library> libraries, Library root)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<Library>();
        pending.Push(root);
        while (pending.TryPop(out var current))
        {
            if (!visited.Add(current.Name)) continue;
            if (!current.Body.TryGetProperty("dependencies", out var dependencies)) continue;
            RequireObject(dependencies);
            foreach (var dependency in dependencies.EnumerateObject())
            {
                if (!libraries.TryGetValue(dependency.Name, out var target) ||
                    target.Name != dependency.Name ||
                    target.Version != RequireString(dependency.Value))
                    throw new InvalidDataException(Invalid);
                pending.Push(target);
            }
        }
        if (visited.Count != libraries.Count)
            throw new InvalidDataException(Invalid);
    }

    private static void AddAssets(JsonElement library, HashSet<string> required)
    {
        RequireFields(library, "dependencies", "runtime", "native", "resources", "runtimeTargets", "compile");
        var runtimePaths = new List<string>();
        var nativePaths = new List<string>();
        foreach (var section in new[] { "runtime", "native" })
        {
            if (!library.TryGetProperty(section, out var assets)) continue;
            RequireObject(assets);
            foreach (var asset in assets.EnumerateObject())
            {
                var leaf = Leaf(asset.Name);
                if (!leaf.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(Invalid);
                RequireObject(asset.Value);
                RequireFields(asset.Value, "assemblyVersion", "fileVersion");
                (section == "runtime" ? runtimePaths : nativePaths).Add(leaf);
            }
        }
        if (library.TryGetProperty("resources", out var resources))
        {
            RequireObject(resources);
            foreach (var resource in resources.EnumerateObject())
            {
                var leaf = Leaf(resource.Name);
                if (!leaf.EndsWith(".resources.dll", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(Invalid);
                RequireObject(resource.Value);
                RequireFields(resource.Value, "locale");
                var locale = RequireString(Required(resource.Value, "locale"));
                RequireSafeAssetPath(locale + "/" + leaf);
                if (!resource.Name.Contains("/" + locale + "/", StringComparison.Ordinal))
                    throw new InvalidDataException(Invalid);
                AddUnique(required, locale + "/" + leaf);
            }
        }
        var selected = library.TryGetProperty("runtimeTargets", out var targets)
            ? AddRidAssets(RequireObject(targets), required)
            : (Runtime: false, Native: false);
        // The host chooses a RID separately for each package and asset type. A selected
        // RID-specific asset set supersedes that type's generic entries, not other types.
        if (!selected.Runtime)
            foreach (var path in runtimePaths) AddUnique(required, path);
        if (!selected.Native)
            foreach (var path in nativePaths) AddUnique(required, path);
        if (library.TryGetProperty("compile", out var compile)) RequireObject(compile);
    }

    private static (bool Runtime, bool Native) AddRidAssets(JsonElement targets, HashSet<string> required)
    {
        var candidates = new List<(string Path, string Rid, string Kind)>();
        foreach (var target in targets.EnumerateObject())
        {
            RequireSafeAssetPath(target.Name);
            var segments = target.Name.Split('/');
            if (segments.Length < 4 || segments[0] != "runtimes")
                throw new InvalidDataException(Invalid);
            var metadata = RequireObject(target.Value);
            RequireFields(metadata, "rid", "assetType", "assemblyVersion", "fileVersion");
            var rid = RequireString(Required(metadata, "rid"));
            var kind = RequireString(Required(metadata, "assetType"));
            if (segments[1] != rid ||
                (kind == "runtime" && segments[2] != "lib") ||
                (kind == "native" && segments[2] != "native") ||
                kind is not ("runtime" or "native") ||
                (kind == "runtime" && segments.Length < 5) ||
                !segments[^1].EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException(Invalid);
            candidates.Add((target.Name, rid, kind));
        }
        // Only this pinned win-x64 portable fallback is selected. Foreign RID candidates
        // are valid metadata but cannot contribute files to this publish inventory.
        var foundRuntime = false;
        var foundNative = false;
        foreach (var kind in new[] { "runtime", "native" })
        {
            var chosenRid = new[] { "win-x64", "win", "any", "base" }
                .FirstOrDefault(rid => candidates.Any(item => item.Kind == kind && item.Rid == rid));
            if (chosenRid is null) continue;
            var selectedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in candidates.Where(item => item.Kind == kind && item.Rid == chosenRid))
            {
                if (!selectedNames.Add(Leaf(item.Path))) throw new InvalidDataException(Invalid);
                AddUnique(required, item.Path);
            }
            if (kind == "runtime") foundRuntime = true;
            else foundNative = true;
        }
        return (foundRuntime, foundNative);
    }

    private static (string Name, string Version) ParseLibraryIdentity(string key)
    {
        var separator = key.IndexOf('/');
        if (separator <= 0 || separator == key.Length - 1 || separator != key.LastIndexOf('/') ||
            key[..separator].Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_')) ||
            key[(separator + 1)..].Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_')))
            throw new InvalidDataException(Invalid);
        return (key[..separator], key[(separator + 1)..]);
    }

    private static string Leaf(string assetPath)
    {
        RequireSafeAssetPath(assetPath);
        return assetPath[(assetPath.LastIndexOf('/') + 1)..];
    }

    private static void RequireSafeAssetPath(string path)
    {
        try
        {
            _ = TrustedManifestV2Codec.CreateCanonicalPayload("0.0.0", 1,
                [new TrustedManifestV2File(path, PlaceholderHash)]);
        }
        catch (ArgumentException) { throw new InvalidDataException(Invalid); }
    }

    private static void AddUnique(HashSet<string> paths, string path)
    {
        RequireSafeAssetPath(path);
        if (!paths.Add(path)) throw new InvalidDataException(Invalid);
    }

    private static JsonDocument ParseStrict(byte[] bytes)
    {
        try
        {
            var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32
            });
            try
            {
                var nodes = 0;
                CheckDuplicates(document.RootElement, ref nodes);
                return document;
            }
            catch { document.Dispose(); throw; }
        }
        catch (JsonException) { throw new InvalidDataException(Invalid); }
    }

    private static void CheckDuplicates(JsonElement element, ref int nodes)
    {
        if (++nodes > 200_000) throw new InvalidDataException(Invalid);
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException(Invalid);
                CheckDuplicates(property.Value, ref nodes);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var value in element.EnumerateArray()) CheckDuplicates(value, ref nodes);
    }

    private static JsonElement RequireObject(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException(Invalid);
        return value;
    }

    private static JsonElement Required(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property)) throw new InvalidDataException(Invalid);
        return property;
    }

    private static string RequireString(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String || value.GetString() is not { } text)
            throw new InvalidDataException(Invalid);
        return text;
    }

    private static void RequireFields(JsonElement value, params string[] allowed)
    {
        foreach (var property in value.EnumerateObject())
            if (!allowed.Contains(property.Name, StringComparer.Ordinal))
                throw new InvalidDataException(Invalid);
    }

    private sealed record Library(string Name, string Version, JsonElement Body);
}
