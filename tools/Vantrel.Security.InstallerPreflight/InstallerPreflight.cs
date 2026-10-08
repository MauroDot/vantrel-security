using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.ManifestTool;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.InstallerPreflight;

public sealed record MsiProductVersion(byte Major, byte Minor, ushort Build)
{
    public override string ToString() => $"{Major.ToString(CultureInfo.InvariantCulture)}.{Minor.ToString(CultureInfo.InvariantCulture)}.{Build.ToString(CultureInfo.InvariantCulture)}";

    public static bool TryParse(string? value, out MsiProductVersion? version)
    {
        version = null;
        if (string.IsNullOrWhiteSpace(value)) return false;
        var parts = value.Split('.');
        if (parts.Length != 3 || parts.Any(part => part.Length == 0 || (part.Length > 1 && part[0] == '0') || !part.All(character => character is >= '0' and <= '9'))) return false;
        if (!uint.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var major) || major > 255 ||
            !uint.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var minor) || minor > 255 ||
            !uint.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var build) || build > 65535)
            return false;
        version = new((byte)major, (byte)minor, (ushort)build);
        return value == version.ToString();
    }
}

public sealed record InstallerDestination(string DirectoryId, string RelativePath);
public sealed record InstallerPlanArtifact(string SourceRelativePath, InstallerDestination Destination, string Sha256);
public sealed record InstallerServiceModel(string Name, string DisplayName, string Account, string ServiceType,
    string StartType, bool HasDependencies, bool HasFailureActions, bool StartsDuringInstall);
public sealed record InstallerEventLogModel(string SourceName, string LogName, InstallerDestination MessageResource);
public sealed record InstallerShortcutModel(string Name, string Scope, bool Advertised, bool DesktopShortcut,
    bool Elevates, bool StartsService, bool InvokesUpdater, InstallerDestination Target);
public sealed record InitialInstallModel(
    string ServiceDirectory, string DesktopDirectory, string OfflineUpdateToolDirectory,
    InstallerServiceModel Service, InstallerEventLogModel EventLog, InstallerShortcutModel DesktopShortcut,
    IReadOnlyList<string> ExcludedDataRoots);
public sealed record InstallerInputPlan(BetaReleaseDescriptor Descriptor, string MsiProductVersion,
    IReadOnlyList<InstallerPlanArtifact> Artifacts, InitialInstallModel Installation);

public static class InitialInstallContract
{
    public const string ServiceDirectory = "ProgramFiles64Folder\\Vantrel Security\\Service";
    public const string DesktopDirectory = "ProgramFiles64Folder\\Vantrel Security\\Desktop";
    public const string OfflineUpdateToolDirectory = "ProgramFiles64Folder\\Vantrel Security\\OfflineUpdateTool";
    public const string EventLogResource = "System.Diagnostics.EventLog.Messages.dll";
    public static IReadOnlyList<string> ExcludedDataRoots { get; } = Array.AsReadOnly(new[]
    {
        "ProgramData\\Vantrel Security\\Updates",
        "ProgramData\\Vantrel Security\\Updates\\Staged",
        "ProgramData\\Vantrel Security\\Updates\\Transactions",
        "ProgramData\\Vantrel Security\\Updates\\Backups",
        "ProgramData\\Vantrel Security\\Updates\\.update-journal-v1.lock",
        "ProgramData\\Vantrel Security\\Updates\\.offline-update-owner-v1.lock",
        "ProgramData\\Vantrel Security\\ReleasePolicy"
    });
    public static InitialInstallModel Model { get; } = new(
        ServiceDirectory, DesktopDirectory, OfflineUpdateToolDirectory,
        new("VantrelSecurityService", "Vantrel Security Service", "NT AUTHORITY\\LocalService", "own-process", "demand", false, false, false),
        new("VantrelSecurityService", "Application", new("ProgramFiles64Folder", "Vantrel Security\\Service\\" + EventLogResource)),
        new("Vantrel Security", "all-users", false, false, false, false, false, new("ProgramFiles64Folder", "Vantrel Security\\Desktop\\Vantrel.Security.Desktop.exe")),
        ExcludedDataRoots);
}

public sealed class InstallerInputValidator
{
    public const string PlanFileName = "vantrel-installer-input-v1.txt";
    private const string PlanSchema = "vantrel-installer-input-v1";
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly HashSet<string> SecretExtensions = new(StringComparer.OrdinalIgnoreCase) { ".pk8", ".pem", ".key", ".pfx", ".p12", ".snk" };
    private static readonly HashSet<string> ForbiddenExtensions = new(StringComparer.OrdinalIgnoreCase) { ".pdb", ".cs", ".csx", ".ps1", ".cmd", ".bat", ".sln", ".csproj", ".wixproj", ".wxs" };
    private static readonly HashSet<string> ForbiddenSegments = new(StringComparer.OrdinalIgnoreCase) { ".service-publish", "staging", "source", "sources", "scripts", "tests", "tools", "bin", "obj" };

    public InstallerInputPlan CreateAndWritePlan(string releaseLayoutRoot, string msiProductVersion, string planPath)
    {
        var plan = CreatePlan(releaseLayoutRoot, msiProductVersion);
        WritePlan(plan, releaseLayoutRoot, planPath);
        return plan;
    }

    public InstallerInputPlan CreatePlan(string releaseLayoutRoot, string msiProductVersion)
    {
        if (!MsiProductVersion.TryParse(msiProductVersion, out var msiVersion) || msiVersion is null)
            throw new IOException("MSI product version is invalid.");
        var root = RequireDirectory(releaseLayoutRoot);
        var recordPath = Path.Combine(root, BetaReleaseLayoutValidator.RecordFileName);
        if (!BetaReleaseRecordCodec.TryParse(ReadFile(recordPath), out var record) || record is null)
            throw new IOException("Completed release record is unavailable.");
        ValidateCompletedRecord(record);
        ValidateRootEntries(root);
        if (record.Artifacts.Select(artifact => artifact.RelativePath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != record.Artifacts.Count)
            throw new IOException("Release record contains colliding artifact identities.");
        var records = record.Artifacts.ToDictionary(artifact => artifact.RelativePath, artifact => artifact.Sha256, StringComparer.Ordinal);
        var observed = CollectArtifacts(root).ToArray();
        if (records.Count != observed.Length || observed.Any(artifact => !records.TryGetValue(artifact.RelativePath, out var expected) || !string.Equals(expected, artifact.Sha256, StringComparison.Ordinal)))
            throw new IOException("Release layout does not match its record.");
        RequireExactService(records.Keys, observed);
        RequireDirectoryCorrespondence(BetaReleaseLayoutValidator.DesktopDirectoryName, records.Keys, observed, "Vantrel.Security.Desktop.exe");
        RequireDirectoryCorrespondence(BetaReleaseLayoutValidator.OfflineUpdateToolDirectoryName, records.Keys, observed, "Vantrel.Security.OfflineUpdateTool.exe");
        var artifacts = observed.Where(artifact => IsInstallArtifact(artifact.RelativePath) && !IsRecordedNonInstallerResidue(artifact.RelativePath)).Select(artifact => new InstallerPlanArtifact(
            artifact.RelativePath, DestinationFor(artifact.RelativePath), artifact.Sha256)).ToArray();
        if (artifacts.Length == 0) throw new IOException("Installer input contains no distributable artifacts.");
        return new(record.Descriptor, msiVersion.ToString(), Array.AsReadOnly(artifacts), InitialInstallContract.Model);
    }

    private static void ValidateCompletedRecord(BetaReleaseRecord record)
    {
        if (record.AuthenticodeEvidence.Count != ReleaseSigningContract.VantrelOwnedPeArtifacts.Count ||
            record.AuthenticodeEvidence.Any(item => item.Category != AuthenticodeVerificationCategory.Valid) ||
            !record.AuthenticodeEvidence.Select(item => item.RelativePath).SequenceEqual(ReleaseSigningContract.VantrelOwnedPeArtifacts.Select(item => item.RelativePath), StringComparer.Ordinal) ||
            record.AuthenticodeEvidence.Any(item => string.IsNullOrWhiteSpace(item.SignerPolicyId) || item.SignerPolicyId.Length > 128 || item.SignerPolicyId.Any(char.IsControl)))
            throw new IOException("Release record is not a completed Authenticode validation.");
    }

    private static void ValidateRootEntries(string root)
    {
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            BetaReleaseDescriptorCodec.FileName, BetaReleaseLayoutValidator.ReleaseNotesFileName, BetaReleaseLayoutValidator.RecordFileName,
            BetaReleaseLayoutValidator.ServiceDirectoryName, BetaReleaseLayoutValidator.DesktopDirectoryName, BetaReleaseLayoutValidator.OfflineUpdateToolDirectoryName
        };
        var entries = Directory.EnumerateFileSystemEntries(root).ToArray();
        if (entries.Length != expected.Count || entries.Any(entry => IsReparse(entry) || !expected.Remove(Path.GetFileName(entry))))
            throw new IOException("Release layout root is not exact.");
    }

    private static IEnumerable<ReleaseArtifact> CollectArtifacts(string root)
    {
        foreach (var fixedFile in new[] { BetaReleaseDescriptorCodec.FileName, BetaReleaseLayoutValidator.ReleaseNotesFileName })
            yield return new(fixedFile, HashFile(Path.Combine(root, fixedFile)));
        foreach (var directory in new[] { BetaReleaseLayoutValidator.ServiceDirectoryName, BetaReleaseLayoutValidator.DesktopDirectoryName, BetaReleaseLayoutValidator.OfflineUpdateToolDirectoryName })
        {
            var directoryRoot = RequireDirectory(Path.Combine(root, directory));
            var pending = new Stack<string>(); pending.Push(directoryRoot);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (pending.Count != 0)
            {
                var current = pending.Pop();
                foreach (var entry in Directory.EnumerateFileSystemEntries(current))
                {
                    if (IsReparse(entry)) throw new IOException("Release artifact is redirected.");
                    if (Directory.Exists(entry)) { pending.Push(entry); continue; }
                    if (!File.Exists(entry)) throw new IOException("Release artifact is unavailable.");
                    var relative = directory + "/" + Path.GetRelativePath(directoryRoot, entry).Replace('\\', '/');
                    if ((!IsAllowedArtifactPath(relative) && !IsRecordedNonInstallerResidue(relative)) || !seen.Add(relative)) throw new IOException("Release artifact is not eligible for installation.");
                    yield return new(relative, HashFile(entry));
                }
            }
        }
    }

    private static void RequireExactService(IEnumerable<string> recordedPaths, IReadOnlyList<ReleaseArtifact> observed)
    {
        var expected = ReleasePayloadVerifier.ExactFileNames.Select(name => "service/" + name).OrderBy(item => item, StringComparer.Ordinal).ToArray();
        var actual = observed.Where(item => item.RelativePath.StartsWith("service/", StringComparison.Ordinal)).Select(item => item.RelativePath).OrderBy(item => item, StringComparer.Ordinal).ToArray();
        if (!actual.SequenceEqual(expected, StringComparer.Ordinal) || recordedPaths.Count(item => item.StartsWith("service/", StringComparison.Ordinal)) != expected.Length)
            throw new IOException("Service payload is not exact.");
    }

    private static void RequireDirectoryCorrespondence(string directory, IEnumerable<string> recordedPaths, IReadOnlyList<ReleaseArtifact> observed, string requiredExecutable)
    {
        var prefix = directory + "/";
        var actual = observed.Where(item => item.RelativePath.StartsWith(prefix, StringComparison.Ordinal)).ToArray();
        if (actual.Length == 0 || !actual.Any(item => item.RelativePath == prefix + requiredExecutable) ||
            recordedPaths.Count(item => item.StartsWith(prefix, StringComparison.Ordinal)) != actual.Length)
            throw new IOException("Release directory does not match its record.");
    }

    internal static bool IsInstallArtifact(string relativePath) => relativePath.StartsWith("service/", StringComparison.Ordinal) || relativePath.StartsWith("desktop/", StringComparison.Ordinal) || relativePath.StartsWith("offline-update-tool/", StringComparison.Ordinal);
    internal static InstallerDestination DestinationFor(string relativePath)
    {
        var slash = relativePath.IndexOf('/');
        var child = relativePath[(slash + 1)..].Replace('/', '\\');
        var directory = relativePath[..slash] switch
        {
            "service" => InitialInstallContract.ServiceDirectory,
            "desktop" => InitialInstallContract.DesktopDirectory,
            "offline-update-tool" => InitialInstallContract.OfflineUpdateToolDirectory,
            _ => throw new IOException("Release artifact destination is unavailable.")
        };
        return new("ProgramFiles64Folder", directory["ProgramFiles64Folder\\".Length..] + "\\" + child);
    }

    internal static bool IsAllowedArtifactPath(string path)
    {
        if (!IsSafeArtifactPathSyntax(path)) return false;
        var fileName = Path.GetFileName(path);
        if (SecretExtensions.Contains(Path.GetExtension(fileName)) || ForbiddenExtensions.Contains(Path.GetExtension(fileName)) ||
            fileName.Equals("packages.lock.json", StringComparison.OrdinalIgnoreCase) || fileName.Contains("manifesttool", StringComparison.OrdinalIgnoreCase) || fileName.Contains("releaselay", StringComparison.OrdinalIgnoreCase) || fileName.Contains("installerpreflight", StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static bool IsRecordedNonInstallerResidue(string path)
    {
        if (!IsSafeArtifactPathSyntax(path)) return false;
        var separator = path.IndexOf('/');
        if (separator < 0 || path.IndexOf('/', separator + 1) >= 0) return false;
        var directory = path[..separator];
        if (directory != BetaReleaseLayoutValidator.DesktopDirectoryName && directory != BetaReleaseLayoutValidator.OfflineUpdateToolDirectoryName) return false;
        var fileName = path[(separator + 1)..];
        if (fileName.Contains("manifesttool", StringComparison.OrdinalIgnoreCase) || fileName.Contains("releaselay", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("installerpreflight", StringComparison.OrdinalIgnoreCase)) return false;
        return Path.GetExtension(fileName).Equals(".pdb", StringComparison.OrdinalIgnoreCase) || fileName == "packages.lock.json";
    }

    private static bool IsSafeArtifactPathSyntax(string path) =>
        !string.IsNullOrWhiteSpace(path) && path.Length <= 512 && !path.Contains(':') && !path.Contains('\\') &&
        !path.Contains("//", StringComparison.Ordinal) && !path.Split('/').Any(segment => segment is "" or "." or ".." || ForbiddenSegments.Contains(segment)) &&
        path.All(character => character is >= '!' and <= '~' && character != '|');

    private static string RequireDirectory(string path)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        for (var current = new DirectoryInfo(full); current is not null; current = current.Parent)
            if (!current.Exists || (current.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Release layout root is unavailable.");
        return full;
    }
    private static byte[] ReadFile(string path)
    {
        if (!File.Exists(path) || IsReparse(path)) throw new IOException("Release record is unavailable.");
        return File.ReadAllBytes(path);
    }
    private static string HashFile(string path)
    {
        var before = new FileInfo(path);
        if (!before.Exists || IsReparse(path)) throw new IOException("Release artifact is unsafe.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        var after = new FileInfo(path);
        if (!after.Exists || IsReparse(path) || before.Length != after.Length || before.LastWriteTimeUtc != after.LastWriteTimeUtc) throw new IOException("Release artifact changed while hashing.");
        return hash;
    }
    private static bool IsReparse(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;

    private static void WritePlan(InstallerInputPlan plan, string root, string output)
    {
        if (string.IsNullOrWhiteSpace(output)) throw new IOException("Installer plan output is unavailable.");
        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var fullOutput = Path.GetFullPath(output);
        if (fullOutput.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || File.Exists(fullOutput) || Directory.Exists(fullOutput)) throw new IOException("Installer plan output is unavailable.");
        var parent = RequireDirectory(Path.GetDirectoryName(fullOutput) ?? throw new IOException("Installer plan output is unavailable."));
        if (IsReparse(parent)) throw new IOException("Installer plan output is unavailable.");
        var text = CreateCanonicalPlan(plan);
        var temporary = fullOutput + ".tmp";
        try { File.WriteAllBytes(temporary, Utf8.GetBytes(text)); File.Move(temporary, fullOutput); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static string CreateCanonicalPlan(InstallerInputPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!MsiProductVersion.TryParse(plan.MsiProductVersion, out _) || plan.Installation != InitialInstallContract.Model ||
            !BetaReleaseDescriptorCodec.TryParse(BetaReleaseDescriptorCodec.CreateCanonical(plan.Descriptor), out _) || plan.Artifacts.Count == 0 ||
            plan.Artifacts.Any(item => item is null || !IsInstallArtifact(item.SourceRelativePath) || item.Destination.DirectoryId != "ProgramFiles64Folder" ||
                item.Destination != DestinationFor(item.SourceRelativePath) || !IsAllowedArtifactPath(item.SourceRelativePath) || !IsHash(item.Sha256)) ||
            plan.Artifacts.Select(item => item.SourceRelativePath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != plan.Artifacts.Count)
            throw new ArgumentException("Installer input plan is not canonical.", nameof(plan));
        var descriptor = plan.Descriptor;
        var output = new StringBuilder()
            .Append("schema=").Append(PlanSchema).Append('\n')
            .Append("source-commit=").Append(descriptor.SourceCommit).Append('\n')
            .Append("release-version=").Append(descriptor.ReleaseVersion).Append('\n')
            .Append("release-sequence=").Append(descriptor.ReleaseSequence.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("published-at-utc=").Append(descriptor.PublishedAtUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)).Append('\n')
            .Append("configuration=").Append(descriptor.Configuration).Append('\n')
            .Append("runtime=").Append(descriptor.Runtime).Append('\n')
            .Append("sdk-version=").Append(descriptor.SdkVersion).Append('\n')
            .Append("release-notes-sha256=").Append(descriptor.ReleaseNotesSha256).Append('\n')
            .Append("msi-product-version=").Append(plan.MsiProductVersion).Append('\n')
            .Append("service-directory=").Append(plan.Installation.ServiceDirectory).Append('\n')
            .Append("desktop-directory=").Append(plan.Installation.DesktopDirectory).Append('\n')
            .Append("offline-update-tool-directory=").Append(plan.Installation.OfflineUpdateToolDirectory).Append('\n')
            .Append("service-name=").Append(plan.Installation.Service.Name).Append('\n')
            .Append("service-display-name=").Append(plan.Installation.Service.DisplayName).Append('\n')
            .Append("service-account=").Append(plan.Installation.Service.Account).Append('\n')
            .Append("service-type=").Append(plan.Installation.Service.ServiceType).Append('\n')
            .Append("service-start=").Append(plan.Installation.Service.StartType).Append('\n')
            .Append("service-dependencies=none\nservice-failure-actions=none\nservice-start-action=none\n")
            .Append("event-log-source=").Append(plan.Installation.EventLog.SourceName).Append('\n')
            .Append("event-log-name=").Append(plan.Installation.EventLog.LogName).Append('\n')
            .Append("event-log-message-resource=").Append(plan.Installation.EventLog.MessageResource.DirectoryId).Append('\\').Append(plan.Installation.EventLog.MessageResource.RelativePath).Append('\n')
            .Append("desktop-shortcut=all-users-non-advertised\ndesktop-shortcut-elevation=none\ndesktop-shortcut-service-start=none\ndesktop-shortcut-updater-action=none\n")
            .Append("desktop-shortcut-target=").Append(plan.Installation.DesktopShortcut.Target.DirectoryId).Append('\\').Append(plan.Installation.DesktopShortcut.Target.RelativePath).Append('\n')
            .Append("programdata=excluded\nfuture-operations=unsupported\nartifact-count=").Append(plan.Artifacts.Count.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (var artifact in plan.Artifacts.OrderBy(item => item.SourceRelativePath, StringComparer.Ordinal))
            output.Append("artifact=").Append(artifact.SourceRelativePath).Append('|').Append(artifact.Destination.DirectoryId).Append('\\').Append(artifact.Destination.RelativePath).Append('|').Append(artifact.Sha256).Append('\n');
        return output.ToString();
    }

    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(value => value is >= '0' and <= '9' or >= 'A' and <= 'F');
}
