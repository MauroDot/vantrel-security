using System.Collections.ObjectModel;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

internal enum ProductPublishKind { Desktop, OfflineUpdateTool }

internal sealed class ProductPublishValidation
{
    internal ProductPublishValidation(IReadOnlyList<TrustedManifestV2File> files,
        IReadOnlyList<TrustedManifestV2File> symbols,
        IReadOnlyList<ServicePublishExcludedBuildArtifact> residue)
    {
        Files = new ReadOnlyCollection<TrustedManifestV2File>(files.ToArray());
        DiagnosticSymbols = new ReadOnlyCollection<TrustedManifestV2File>(symbols.ToArray());
        ExcludedBuildArtifacts = new ReadOnlyCollection<ServicePublishExcludedBuildArtifact>(residue.ToArray());
    }

    internal IReadOnlyList<TrustedManifestV2File> Files { get; }
    internal IReadOnlyList<TrustedManifestV2File> DiagnosticSymbols { get; }
    internal IReadOnlyList<ServicePublishExcludedBuildArtifact> ExcludedBuildArtifacts { get; }
}

/// <summary>Exact, framework-dependent win-x64 publish closure for the two non-Service products.</summary>
internal static class ProductPublishDependencyValidator
{
    private const string Invalid = "V2 product publish dependency closure is invalid.";
    private static readonly IReadOnlyDictionary<string, string> DesktopDependencies =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Microsoft.Extensions.Hosting"] = "10.0.12",
            ["Vantrel.Security.Core"] = "0.1.0",
            ["Vantrel.Security.Infrastructure"] = "0.1.0"
        });
    private static readonly IReadOnlyDictionary<string, string> ToolDependencies =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Vantrel.Security.Service"] = "0.1.0"
        });

    internal static ProductPublishValidation ValidateSdkPublish(string root,
        ProductPublishKind kind, string approvedCopiedLockSha256,
        IReadOnlyDictionary<string, string>? approvedServiceHostResidue = null)
    {
        RequireHash(approvedCopiedLockSha256);
        var exclusions = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["packages.lock.json"] = approvedCopiedLockSha256
        };
        if (kind == ProductPublishKind.OfflineUpdateTool)
        {
            if (approvedServiceHostResidue is null || approvedServiceHostResidue.Count != 3)
                throw new InvalidDataException(Invalid);
            foreach (var name in new[] { "Vantrel.Security.Service.exe",
                "Vantrel.Security.Service.deps.json", "Vantrel.Security.Service.runtimeconfig.json" })
            {
                if (!approvedServiceHostResidue.TryGetValue(name, out var hash))
                    throw new InvalidDataException(Invalid);
                RequireHash(hash);
                exclusions.Add(name, hash);
            }
        }
        return Validate(root, kind, exclusions, includeSymbols: true);
    }

    internal static ProductPublishValidation ValidateProjected(string root, ProductPublishKind kind,
        IReadOnlyList<TrustedManifestV2File> expected)
    {
        var result = Validate(root, kind, new Dictionary<string, string>(), includeSymbols: false);
        if (!result.Files.SequenceEqual(expected) || result.DiagnosticSymbols.Count != 0 ||
            result.ExcludedBuildArtifacts.Count != 0) throw new InvalidDataException(Invalid);
        return result;
    }

    private static ProductPublishValidation Validate(string root, ProductPublishKind kind,
        IReadOnlyDictionary<string, string> excluded, bool includeSymbols)
    {
        if (kind is not (ProductPublishKind.Desktop or ProductPublishKind.OfflineUpdateTool))
            throw new InvalidDataException(Invalid);
        var name = kind == ProductPublishKind.Desktop
            ? "Vantrel.Security.Desktop" : "Vantrel.Security.OfflineUpdateTool";
        var projectNames = kind == ProductPublishKind.Desktop
            ? new[] { name, "Vantrel.Security.Core", "Vantrel.Security.Infrastructure" }
            : new[] { name, "Vantrel.Security.Service", "Vantrel.Security.Core",
                "Vantrel.Security.Infrastructure" };
        var symbols = projectNames.Select(project => project + ".pdb")
            .ToHashSet(StringComparer.Ordinal);
        var supporting = kind == ProductPublishKind.Desktop
            ? new[] { name + ".exe", name + ".deps.json", name + ".runtimeconfig.json" }
            : new[] { name + ".exe", name + ".deps.json", name + ".runtimeconfig.json",
                "appsettings.json" };
        var optional = new HashSet<string>(StringComparer.Ordinal);
        if (includeSymbols) optional.UnionWith(symbols);
        if (kind == ProductPublishKind.OfflineUpdateTool)
            optional.Add("appsettings.Development.json");
        var contract = new PublishDependencyContract(name, name + ".deps.json",
            name + ".runtimeconfig.json",
            kind == ProductPublishKind.Desktop ? DesktopDependencies : ToolDependencies,
            supporting, optional, projectNames,
            kind == ProductPublishKind.Desktop
                ? ["Microsoft.NETCore.App", "Microsoft.WindowsDesktop.App"]
                : ["Microsoft.NETCore.App"], excluded,
            RequireExactProjectLibraries: true);
        var validated = ServicePublishDependencyValidator.ValidateProductPublish(root, contract);
        var diagnostics = validated.DeployableFiles.Where(file => symbols.Contains(file.Path)).ToArray();
        var files = validated.DeployableFiles.Where(file => !symbols.Contains(file.Path)).ToArray();
        if (files.Count(file => file.Path == name + ".exe") != 1 ||
            files.Any(file => file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase) ||
                file.Path == "packages.lock.json")) throw new InvalidDataException(Invalid);
        var prefix = kind == ProductPublishKind.Desktop ? "desktop/" : "offline-update-tool/";
        var approvedOwned = ReleaseSigningContract.VantrelOwnedPeArtifacts
            .Where(item => item.RelativePath.StartsWith(prefix, StringComparison.Ordinal))
            .Select(item => item.RelativePath[prefix.Length..])
            .ToHashSet(StringComparer.Ordinal);
        var actualOwned = files.Where(file => IsVantrelOwnedPe(file.Path))
            .Select(file => file.Path).ToArray();
        if (actualOwned.Length != approvedOwned.Count ||
            actualOwned.Any(path => !approvedOwned.Contains(path)))
            throw new InvalidDataException(Invalid);
        return new(files, diagnostics, validated.ExcludedBuildArtifacts);
    }

    private static bool IsVantrelOwnedPe(string path)
    {
        var name = path[(path.LastIndexOf('/') + 1)..];
        return name.StartsWith("Vantrel.Security.", StringComparison.OrdinalIgnoreCase) &&
            (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
             name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
    }

    private static void RequireHash(string? hash)
    {
        if (hash is not { Length: 64 } || hash.Any(c => c is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
            throw new InvalidDataException(Invalid);
    }
}
