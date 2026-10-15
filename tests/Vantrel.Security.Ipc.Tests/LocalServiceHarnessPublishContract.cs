using System.Text.Json;

namespace Vantrel.Security.Ipc.Tests;

/// <summary>
/// Validates the fixed, framework-dependent win-x64 LocalService harness publication.
/// The caller supplies bytes read from its already validated, retained file handles.
/// </summary>
internal static class LocalServiceHarnessPublishContract
{
    // The protected-file loader also checks these JSON-specific ceilings against its
    // retained file handles before allocating the semantic input buffers.
    internal const int MaximumRuntimeConfigBytes = 16 * 1024;
    internal const int MaximumDepsBytes = 1024 * 1024;
    private const string FrameworkTarget = ".NETCoreApp,Version=v10.0";
    private const string RuntimeTarget = FrameworkTarget + "/win-x64";
    private const string ProjectLibrary = "Kestermere.Security.LocalServiceAclHarness/0.1.0";
    private const string EventLogLibrary = "System.Diagnostics.EventLog/10.0.12";
    private const string ServiceControllerLibrary = "System.ServiceProcess.ServiceController/10.0.12";

    private const string ProjectAssembly = "Kestermere.Security.LocalServiceAclHarness.dll";
    private const string EventLogAssembly = "runtimes/win/lib/net10.0/System.Diagnostics.EventLog.dll";
    private const string EventLogMessagesAssembly = "runtimes/win/lib/net10.0/System.Diagnostics.EventLog.Messages.dll";
    private const string ServiceControllerAssembly = "runtimes/win/lib/net10.0/System.ServiceProcess.ServiceController.dll";

    internal static void Validate(ReadOnlySpan<byte> runtimeConfig, ReadOnlySpan<byte> deps)
    {
        ValidateRuntimeConfig(runtimeConfig);
        ValidateDeps(deps);
    }

    internal static void ValidateRuntimeConfig(ReadOnlySpan<byte> runtimeConfig)
    {
        using var document = Parse(runtimeConfig, MaximumRuntimeConfigBytes);
        var root = document.RootElement;
        RequireNoDuplicateProperties(root);
        RequireProperties(root, "runtimeOptions");

        var options = Get(root, "runtimeOptions");
        RequireProperties(options, "tfm", "framework", "configProperties");
        RequireText(Get(options, "tfm"), "net10.0");

        // SDK 10.0.401 emits one framework for this framework-dependent Exe.
        // Another framework, a frameworks list, includedFrameworks, rollForward,
        // or an applyPatches override changes the reviewed runtime contract.
        var framework = Get(options, "framework");
        RequireProperties(framework, "name", "version");
        RequireText(Get(framework, "name"), "Microsoft.NETCore.App");
        RequireText(Get(framework, "version"), "10.0.0");

        var configuration = Get(options, "configProperties");
        RequireObject(configuration);
        var names = configuration.EnumerateObject().Select(property => property.Name).ToArray();
        if (names.Length is < 2 or > 3 ||
            !names.Contains("System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization", StringComparer.Ordinal) ||
            !names.Contains("CSWINRT_USE_WINDOWS_UI_XAML_PROJECTIONS", StringComparer.Ordinal) ||
            names.Any(name => name is not ("System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization" or
                "CSWINRT_USE_WINDOWS_UI_XAML_PROJECTIONS" or
                "System.Reflection.Metadata.MetadataUpdater.IsSupported")))
            throw Invalid();
        foreach (var property in configuration.EnumerateObject())
            if (property.Value.ValueKind != JsonValueKind.False) throw Invalid();
    }

    internal static void ValidateDeps(ReadOnlySpan<byte> deps)
    {
        using var document = Parse(deps, MaximumDepsBytes);
        var root = document.RootElement;
        RequireNoDuplicateProperties(root);
        RequireProperties(root, "runtimeTarget", "compilationOptions", "targets", "libraries");

        var runtimeTarget = Get(root, "runtimeTarget");
        RequireProperties(runtimeTarget, "name", "signature");
        RequireText(Get(runtimeTarget, "name"), RuntimeTarget);
        RequireText(Get(runtimeTarget, "signature"), "");
        RequireProperties(Get(root, "compilationOptions"));

        var targets = Get(root, "targets");
        RequireProperties(targets, FrameworkTarget, RuntimeTarget);
        RequireProperties(Get(targets, FrameworkTarget));
        var selectedTarget = Get(targets, RuntimeTarget);
        RequireProperties(selectedTarget, ProjectLibrary, EventLogLibrary, ServiceControllerLibrary);

        var observedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var observedPublishedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var project = Get(selectedTarget, ProjectLibrary);
        RequireProperties(project, "dependencies", "runtime");
        RequireDependency(Get(project, "dependencies"), "System.ServiceProcess.ServiceController", "10.0.12");
        RequireRuntimeAssets(Get(project, "runtime"), observedPaths, observedPublishedNames, ProjectAssembly);

        var eventLog = Get(selectedTarget, EventLogLibrary);
        RequireProperties(eventLog, "runtime");
        RequireRuntimeAssets(Get(eventLog, "runtime"), observedPaths, observedPublishedNames,
            EventLogMessagesAssembly, EventLogAssembly);

        var serviceController = Get(selectedTarget, ServiceControllerLibrary);
        RequireProperties(serviceController, "dependencies", "runtime");
        RequireDependency(Get(serviceController, "dependencies"), "System.Diagnostics.EventLog", "10.0.12");
        RequireRuntimeAssets(Get(serviceController, "runtime"), observedPaths, observedPublishedNames,
            ServiceControllerAssembly);

        if (observedPaths.Count != 4 || observedPublishedNames.Count != 4 ||
            !observedPublishedNames.SetEquals(new[]
            {
                ProjectAssembly,
                "System.Diagnostics.EventLog.Messages.dll",
                "System.Diagnostics.EventLog.dll",
                "System.ServiceProcess.ServiceController.dll"
            }))
            throw Invalid();

        var libraries = Get(root, "libraries");
        RequireProperties(libraries, ProjectLibrary, EventLogLibrary, ServiceControllerLibrary);
        var projectMetadata = Get(libraries, ProjectLibrary);
        RequireProperties(projectMetadata, "type", "serviceable", "sha512");
        RequireText(Get(projectMetadata, "type"), "project");
        RequireBoolean(Get(projectMetadata, "serviceable"), false);
        RequireText(Get(projectMetadata, "sha512"), "");

        RequirePackageMetadata(Get(libraries, EventLogLibrary),
            "system.diagnostics.eventlog/10.0.12",
            "system.diagnostics.eventlog.10.0.12.nupkg.sha512",
            "sha512-sOZM+VyRj1pg/ItlHsvrSbjws6oGqZveTzTNBGZ9ziwRDyKsOF3ub6vhvOdxotCIqtlnyHAIwP5sLNvgiZC+pQ==");
        RequirePackageMetadata(Get(libraries, ServiceControllerLibrary),
            "system.serviceprocess.servicecontroller/10.0.12",
            "system.serviceprocess.servicecontroller.10.0.12.nupkg.sha512",
            "sha512-sFV+RM/yPtshiCAEIuTm8Dt4F7VuKRbL50PnGC9nXHolk/jw+z3T8zx7axKTBC8mqtQU2ZmjsoPC9b1iwOilNQ==");
    }

    private static JsonDocument Parse(ReadOnlySpan<byte> bytes, int maximumBytes)
    {
        if (bytes.IsEmpty || bytes.Length > maximumBytes) throw Invalid();
        try
        {
            return JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions
            {
                MaxDepth = 16,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });
        }
        catch (JsonException)
        {
            throw Invalid();
        }
    }

    private static void RequireNoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw Invalid();
                RequireNoDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var value in element.EnumerateArray()) RequireNoDuplicateProperties(value);
        }
    }

    private static void RequireProperties(JsonElement element, params string[] expected)
    {
        RequireObject(element);
        var actual = element.EnumerateObject().Select(property => property.Name).ToArray();
        if (actual.Length != expected.Length || !actual.ToHashSet(StringComparer.Ordinal).SetEquals(expected))
            throw Invalid();
    }

    private static void RequireObject(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object) throw Invalid();
    }

    private static JsonElement Get(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out var value))
            throw Invalid();
        return value;
    }

    private static void RequireText(JsonElement element, string expected)
    {
        if (element.ValueKind != JsonValueKind.String ||
            !string.Equals(element.GetString(), expected, StringComparison.Ordinal))
            throw Invalid();
    }

    private static void RequireBoolean(JsonElement element, bool expected)
    {
        if (element.ValueKind != (expected ? JsonValueKind.True : JsonValueKind.False)) throw Invalid();
    }

    private static void RequireDependency(JsonElement dependencies, string name, string version)
    {
        RequireProperties(dependencies, name);
        RequireText(Get(dependencies, name), version);
    }

    private static void RequirePackageMetadata(JsonElement library, string path, string hashPath, string sha512)
    {
        RequireProperties(library, "type", "serviceable", "sha512", "path", "hashPath");
        RequireText(Get(library, "type"), "package");
        RequireBoolean(Get(library, "serviceable"), true);
        RequireText(Get(library, "sha512"), sha512);
        RequireText(Get(library, "path"), path);
        RequireText(Get(library, "hashPath"), hashPath);
    }

    private static void RequireRuntimeAssets(JsonElement runtime, HashSet<string> observedPaths,
        HashSet<string> observedPublishedNames, params string[] expectedPaths)
    {
        RequireObject(runtime);
        var count = 0;
        foreach (var asset in runtime.EnumerateObject())
        {
            var path = RequireSafeRelativeAssetPath(asset.Name);
            var basename = path[(path.LastIndexOf('/') + 1)..];
            if (!observedPaths.Add(path) || !observedPublishedNames.Add(basename) ||
                !expectedPaths.Contains(path, StringComparer.Ordinal))
                throw Invalid();
            if (path == ProjectAssembly)
                RequireProperties(asset.Value);
            else
            {
                RequireProperties(asset.Value, "assemblyVersion", "fileVersion");
                RequireNonemptyText(Get(asset.Value, "assemblyVersion"));
                RequireNonemptyText(Get(asset.Value, "fileVersion"));
            }
            count++;
        }
        if (count != expectedPaths.Length) throw Invalid();
    }

    private static void RequireNonemptyText(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(element.GetString())) throw Invalid();
    }

    private static string RequireSafeRelativeAssetPath(string path)
    {
        // The manifest uses package-relative paths with '/', then SDK publish flattens
        // these particular runtime assets to the payload root. Never use OS-dependent
        // Path.GetFileName on an unvalidated manifest key.
        if (path.Length is < 1 or > 256) throw Invalid();
        foreach (var part in path.Split('/'))
        {
            if (part.Length == 0 || part is "." or ".." || part[0] == '.' || part[^1] == '.')
                throw Invalid();
            foreach (var character in part)
                if (!((character is >= 'a' and <= 'z') || (character is >= 'A' and <= 'Z') ||
                      (character is >= '0' and <= '9') || character is '.' or '_' or '-'))
                    throw Invalid();
        }
        return path;
    }

    private static IOException Invalid() => new("Local-service harness publish contract is invalid.");
}
