using System.Globalization;
using System.Security;
using System.Text;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.InstallerPreflight;

/// <summary>Canonical, public-only installer-input serialization consumed by the first-install WiX authoring project.</summary>
public static class InstallerInputPlanCodec
{
    public const string Schema = "vantrel-installer-input-v1";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static bool TryParse(ReadOnlySpan<byte> bytes, out InstallerInputPlan? plan)
    {
        plan = null;
        if (bytes.Length is 0 or > 1024 * 1024 || bytes.IndexOf((byte)'\r') >= 0 || HasBom(bytes) || HasNonAscii(bytes)) return false;
        string text;
        try { text = Utf8.GetString(bytes); } catch (DecoderFallbackException) { return false; }
        if (!text.EndsWith('\n')) return false;
        var lines = text.Split('\n');
        if (lines.Length < 34 || lines[^1].Length != 0) return false;
        var keys = new[]
        {
            "schema", "source-commit", "release-version", "release-sequence", "published-at-utc", "configuration", "runtime", "sdk-version", "release-notes-sha256", "msi-product-version",
            "service-directory", "desktop-directory", "offline-update-tool-directory", "service-name", "service-display-name", "service-account", "service-type", "service-start",
            "service-dependencies", "service-failure-actions", "service-start-action", "event-log-source", "event-log-name", "event-log-message-resource",
            "desktop-shortcut", "desktop-shortcut-elevation", "desktop-shortcut-service-start", "desktop-shortcut-updater-action", "desktop-shortcut-target", "programdata", "future-operations", "artifact-count"
        };
        var values = new string[keys.Length];
        for (var index = 0; index < keys.Length; index++)
        {
            var prefix = keys[index] + "=";
            if (!lines[index].StartsWith(prefix, StringComparison.Ordinal)) return false;
            values[index] = lines[index][prefix.Length..];
        }
        if (values[0] != Schema || !uint.TryParse(values[31], NumberStyles.None, CultureInfo.InvariantCulture, out var artifactCount) || artifactCount == 0 || artifactCount > int.MaxValue ||
            (long)lines.Length != 33L + artifactCount ||
            values[10] != InitialInstallContract.ServiceDirectory || values[11] != InitialInstallContract.DesktopDirectory || values[12] != InitialInstallContract.OfflineUpdateToolDirectory ||
            values[13] != "VantrelSecurityService" || values[14] != "Vantrel Security Service" || values[15] != "NT AUTHORITY\\LocalService" || values[16] != "own-process" || values[17] != "demand" ||
            values[18] != "none" || values[19] != "none" || values[20] != "none" || values[21] != "VantrelSecurityService" || values[22] != "Application" ||
            values[23] != "ProgramFiles64Folder\\Vantrel Security\\Service\\System.Diagnostics.EventLog.Messages.dll" ||
            values[24] != "all-users-non-advertised" || values[25] != "none" || values[26] != "none" || values[27] != "none" ||
            values[28] != "ProgramFiles64Folder\\Vantrel Security\\Desktop\\Vantrel.Security.Desktop.exe" || values[29] != "excluded" || values[30] != "unsupported" ||
            !MsiProductVersion.TryParse(values[9], out _)) return false;
        var descriptorBytes = Utf8.GetBytes($"schema={BetaReleaseDescriptorCodec.Schema}\nsource-commit={values[1]}\nrelease-version={values[2]}\nrelease-sequence={values[3]}\npublished-at-utc={values[4]}\nconfiguration={values[5]}\nruntime={values[6]}\nsdk-version={values[7]}\nrelease-notes-sha256={values[8]}\n");
        if (!BetaReleaseDescriptorCodec.TryParse(descriptorBytes, out var descriptor) || descriptor is null) return false;
        var artifacts = new List<InstallerPlanArtifact>((int)artifactCount);
        for (var index = 0; index < artifactCount; index++)
        {
            var line = lines[32 + index];
            if (!line.StartsWith("artifact=", StringComparison.Ordinal)) return false;
            var parts = line["artifact=".Length..].Split('|');
            if (parts.Length != 3 || !InstallerInputValidator.IsAllowedArtifactPath(parts[0]) || !InstallerInputValidator.IsInstallArtifact(parts[0]) ||
                !TryParseDestination(parts[1], out var destination) || destination != InstallerInputValidator.DestinationFor(parts[0]) || !IsHash(parts[2])) return false;
            artifacts.Add(new(parts[0], destination, parts[2]));
        }
        if (artifacts.Select(item => item.SourceRelativePath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != artifacts.Count) return false;
        try
        {
            plan = new(descriptor, values[9], Array.AsReadOnly(artifacts.ToArray()), InitialInstallContract.Model);
            return bytes.SequenceEqual(Utf8.GetBytes(InstallerInputValidator.CreateCanonicalPlan(plan)));
        }
        catch (ArgumentException) { plan = null; return false; }
    }

    private static bool TryParseDestination(string value, out InstallerDestination destination)
    {
        destination = null!;
        const string prefix = "ProgramFiles64Folder\\";
        if (!value.StartsWith(prefix, StringComparison.Ordinal) || value.Length == prefix.Length || value.Contains('|') || value.Contains(':') || value.Contains("\\\\", StringComparison.Ordinal)) return false;
        destination = new("ProgramFiles64Folder", value[prefix.Length..]);
        return true;
    }
    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(value => value is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool HasBom(ReadOnlySpan<byte> bytes) => bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
    private static bool HasNonAscii(ReadOnlySpan<byte> bytes) { foreach (var value in bytes) if (value > 0x7f) return true; return false; }
}

/// <summary>Build-time WiX authoring generator. It consumes only a reparsed plan that exactly reproduces a current validated layout.</summary>
public static class WixFirstInstallAuthoring
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static void ValidateAndWrite(string releaseLayoutRoot, string installerPlanPath, string wixOutputPath)
    {
        if (!File.Exists(installerPlanPath) || (File.GetAttributes(installerPlanPath) & FileAttributes.ReparsePoint) != 0 ||
            !InstallerInputPlanCodec.TryParse(File.ReadAllBytes(installerPlanPath), out var plan) || plan is null)
            throw new IOException("Installer input plan is unavailable.");
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(releaseLayoutRoot));
        var output = Path.GetFullPath(wixOutputPath);
        if (output.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new IOException("WiX authoring output is unavailable.");
        var current = new InstallerInputValidator().CreatePlan(releaseLayoutRoot, plan.MsiProductVersion);
        if (!string.Equals(InstallerInputValidator.CreateCanonicalPlan(current), InstallerInputValidator.CreateCanonicalPlan(plan), StringComparison.Ordinal))
            throw new IOException("Installer input plan does not match the validated release layout.");
        WriteAtomically(wixOutputPath, CreateWixSource(plan));
    }

    public static string CreateWixSource(InstallerInputPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var canonical = InstallerInputValidator.CreateCanonicalPlan(plan);
        if (!InstallerInputPlanCodec.TryParse(Utf8.GetBytes(canonical), out var parsed) || parsed is null) throw new ArgumentException("Installer input plan is not canonical.", nameof(plan));
        var source = new StringBuilder();
        var componentIds = new List<string>();
        var fileIds = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var artifact in plan.Artifacts) fileIds.Add(artifact.SourceRelativePath, FileId(artifact.SourceRelativePath));
        source.Append("<Wix xmlns=\"http://wixtoolset.org/schemas/v4/wxs\">\n")
            .Append("  <Package Name=\"Vantrel Security\" Manufacturer=\"Mauro Interactive\" Version=\"").Append(Xml(plan.MsiProductVersion)).Append("\" Scope=\"perMachine\">\n")
            .Append("    <MediaTemplate EmbedCab=\"yes\" />\n")
            .Append("    <StandardDirectory Id=\"ProgramFiles64Folder\">\n")
            .Append("      <Directory Id=\"VantrelProductFolder\" Name=\"Vantrel Security\">\n");
        EmitGroup(source, "service", "VantrelServiceFolder", "Service", plan.Artifacts.Where(item => item.SourceRelativePath.StartsWith("service/", StringComparison.Ordinal)).ToArray(), fileIds, componentIds);
        EmitGroup(source, "desktop", "VantrelDesktopFolder", "Desktop", plan.Artifacts.Where(item => item.SourceRelativePath.StartsWith("desktop/", StringComparison.Ordinal)).ToArray(), fileIds, componentIds);
        EmitGroup(source, "offline-update-tool", "VantrelOfflineUpdateToolFolder", "OfflineUpdateTool", plan.Artifacts.Where(item => item.SourceRelativePath.StartsWith("offline-update-tool/", StringComparison.Ordinal)).ToArray(), fileIds, componentIds);
        source.Append("      </Directory>\n")
            .Append("    </StandardDirectory>\n")
            .Append("    <StandardDirectory Id=\"ProgramMenuFolder\" />\n")
            .Append("    <Feature Id=\"MainFeature\" Title=\"Vantrel Security\" Level=\"1\">\n");
        foreach (var componentId in componentIds) source.Append("      <ComponentRef Id=\"").Append(componentId).Append("\" />\n");
        source.Append("    </Feature>\n  </Package>\n</Wix>\n");
        return source.ToString();
    }

    private static void EmitGroup(StringBuilder source, string group, string rootId, string name, IReadOnlyList<InstallerPlanArtifact> artifacts,
        IReadOnlyDictionary<string, string> fileIds, List<string> componentIds)
    {
        var root = new DirectoryNode();
        foreach (var artifact in artifacts)
        {
            var node = root;
            foreach (var segment in artifact.SourceRelativePath[(group.Length + 1)..].Split('/')[..^1])
                node = node.Children.TryGetValue(segment, out var child) ? child : node.Children[segment] = new();
            node.Artifacts.Add(artifact);
        }
        source.Append("        <Directory Id=\"").Append(rootId).Append("\" Name=\"").Append(name).Append("\">\n");
        EmitDirectoryContents(source, root, "          ", group, fileIds, componentIds);
        source.Append("        </Directory>\n");
    }

    private static void EmitDirectoryContents(StringBuilder source, DirectoryNode node, string indent, string group,
        IReadOnlyDictionary<string, string> fileIds, List<string> componentIds)
    {
        foreach (var artifact in node.Artifacts.OrderBy(item => item.SourceRelativePath, StringComparer.Ordinal))
        {
            var componentId = "C_" + DigestId(artifact.SourceRelativePath);
            componentIds.Add(componentId);
            var fileId = fileIds[artifact.SourceRelativePath];
            source.Append(indent).Append("<Component Id=\"").Append(componentId).Append("\" Bitness=\"always64\">\n")
                .Append(indent).Append("  <File Id=\"").Append(fileId).Append("\" Source=\"$(var.ReleaseLayoutRoot)\\").Append(Xml(artifact.SourceRelativePath.Replace('/', '\\'))).Append("\" KeyPath=\"yes\"");
            if (artifact.SourceRelativePath == "desktop/Vantrel.Security.Desktop.exe")
            {
                source.Append(">\n").Append(indent).Append("    <Shortcut Id=\"VantrelStartMenuShortcut\" Directory=\"ProgramMenuFolder\" Name=\"Vantrel Security\" Advertise=\"no\" WorkingDirectory=\"VantrelDesktopFolder\" />\n").Append(indent).Append("  </File>\n");
            }
            else
            {
                source.Append(" />\n");
            }
            if (artifact.SourceRelativePath == "service/Vantrel.Security.Service.exe")
                source.Append(indent).Append("  <ServiceInstall Id=\"VantrelSecurityServiceInstall\" Name=\"VantrelSecurityService\" DisplayName=\"Vantrel Security Service\" Account=\"NT AUTHORITY\\LocalService\" Start=\"demand\" Type=\"ownProcess\" />\n");
            if (artifact.SourceRelativePath == "service/System.Diagnostics.EventLog.Messages.dll")
                source.Append(indent).Append("  <RegistryValue Root=\"HKLM\" Key=\"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\VantrelSecurityService\" Name=\"EventMessageFile\" Value=\"[#").Append(fileId).Append("]\" Type=\"expandable\" />\n");
            source.Append(indent).Append("</Component>\n");
        }
        foreach (var child in node.Children.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            var id = "D_" + DigestId(group + "/" + child.Key);
            source.Append(indent).Append("<Directory Id=\"").Append(id).Append("\" Name=\"").Append(Xml(child.Key)).Append("\">\n");
            EmitDirectoryContents(source, child.Value, indent + "  ", group + "/" + child.Key, fileIds, componentIds);
            source.Append(indent).Append("</Directory>\n");
        }
    }

    private sealed class DirectoryNode
    {
        internal List<InstallerPlanArtifact> Artifacts { get; } = [];
        internal Dictionary<string, DirectoryNode> Children { get; } = new(StringComparer.Ordinal);
    }

    private static string FileId(string value) => "F_" + DigestId(value);
    private static string DigestId(string value) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Utf8.GetBytes(value)))[..16];
    private static string Xml(string value) => SecurityElement.Escape(value) ?? throw new ArgumentException("Authoring value is unavailable.", nameof(value));
    private static void WriteAtomically(string path, string content)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new IOException("WiX authoring output is unavailable.");
        var full = Path.GetFullPath(path); var parent = Path.GetDirectoryName(full);
        if (string.IsNullOrWhiteSpace(parent) || Directory.Exists(full) || (File.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) || (Directory.Exists(parent) && (File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0)) throw new IOException("WiX authoring output is unavailable.");
        Directory.CreateDirectory(parent);
        var temporary = full + ".tmp";
        try { File.WriteAllBytes(temporary, Utf8.GetBytes(content)); File.Move(temporary, full, true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
