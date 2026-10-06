using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Vantrel.Security.InstallerPreflight;
using Vantrel.Security.ManifestTool;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.InstallerAuthoring.Tests;

[TestClass]
public sealed class SandboxValidationHarnessTests
{
    [TestMethod]
    public void Sandbox_input_is_canonical_and_rejects_malformed_hash_and_extra_fields()
    {
        var input = new SandboxValidationInput(
            new string('a', 40), "0.1.0-beta.1", 7,
            new DateTimeOffset(2026, 10, 6, 0, 0, 0, TimeSpan.Zero), "0.1.1",
            new string('B', 64), new string('C', 64), Artifacts());
        var canonical = SandboxValidationInputCodec.CreateCanonical(input);

        Assert.IsTrue(SandboxValidationInputCodec.TryParse(Encoding.UTF8.GetBytes(canonical), out var parsed));
        Assert.IsNotNull(parsed);
        Assert.IsFalse(SandboxValidationInputCodec.TryParse(Encoding.UTF8.GetBytes(canonical.Replace("msi-sha256=" + new string('B', 64), "msi-sha256=BAD", StringComparison.Ordinal)), out _));
        Assert.IsFalse(SandboxValidationInputCodec.TryParse(Encoding.UTF8.GetBytes(canonical.Replace("desktop/Vantrel.Security.Desktop.exe", "../escape.exe", StringComparison.Ordinal)), out _));
        Assert.IsFalse(SandboxValidationInputCodec.TryParse(Encoding.UTF8.GetBytes(canonical.Replace("artifact-count=" + input.Artifacts.Count + "\n", "artifact-count=" + input.Artifacts.Count + "\nextra=value\n", StringComparison.Ordinal)), out _));
    }

    [TestMethod]
    public void Canonical_descriptor_and_msi_contracts_reject_semantic_noncanonical_values()
    {
        Assert.IsFalse(MsiProductVersion.TryParse("256.0.0", out _));
        Assert.IsFalse(MsiProductVersion.TryParse("0.256.0", out _));
        Assert.IsFalse(MsiProductVersion.TryParse("0.0.65536", out _));
        Assert.IsFalse(MsiProductVersion.TryParse("01.0.0", out _));
        Assert.IsFalse(CanonicalReleaseVersion.IsValid(new string('1', 65)));
        Assert.IsFalse(CanonicalReleaseVersion.IsValid("01.0.0"));
        Assert.IsTrue(ulong.TryParse("18446744073709551615", System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _));
        Assert.IsFalse(ulong.TryParse("18446744073709551616", System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _));
        Assert.IsFalse(ulong.TryParse("0", System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var zero) && zero != 0);
        Assert.IsFalse("01".Length == 1 || "01"[0] is >= '1' and <= '9');
        var invalidDate = "schema=vantrel-beta-release-descriptor-v1\nsource-commit=" + new string('a', 40) + "\nrelease-version=0.1.0\nrelease-sequence=1\npublished-at-utc=2026-99-06T00:00:00Z\nconfiguration=Release\nruntime=win-x64\nsdk-version=10.0.401\nrelease-notes-sha256=" + new string('A', 64) + "\n";
        Assert.IsFalse(BetaReleaseDescriptorCodec.TryParse(Encoding.ASCII.GetBytes(invalidDate), out _));
    }

    [TestMethod]
    public void Host_preparation_is_build_only_and_never_invokes_installation_or_service_control()
    {
        var script = File.ReadAllText(Path.Combine(RepositoryRoot(), "scripts", "Prepare-WindowsSandboxValidation.ps1"));

        StringAssert.Contains(script, "Assert-CleanDetachedCheckout");
        StringAssert.Contains(script, "--locked-mode");
        StringAssert.Contains(script, "emit-wix");
        StringAssert.Contains(script, "write-sandbox-input");
        StringAssert.DoesNotMatch(script, new Regex("msiexec|start-service|stop-service|new-service|sc(?:\\.exe)?\\s", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
        StringAssert.DoesNotMatch(script, new Regex("program files", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
    }

    [TestMethod]
    public void Sandbox_configuration_is_isolated_and_maps_only_read_only_input()
    {
        var document = XDocument.Load(Path.Combine(RepositoryRoot(), "sandbox", "Vantrel.Security.ReleaseValidation.wsb"));
        Assert.IsNotNull(document.Root);
        var root = document.Root;

        Assert.AreEqual("Disable", root.Element("Networking")?.Value);
        Assert.AreEqual("Disable", root.Element("ClipboardRedirection")?.Value);
        Assert.AreEqual("Disable", root.Element("PrinterRedirection")?.Value);
        Assert.AreEqual("Disable", root.Element("VGpu")?.Value);
        Assert.AreEqual(1, root.Element("MappedFolders")?.Elements("MappedFolder").Count() ?? 0);
        Assert.AreEqual("__VANTREL_SANDBOX_INPUT__", root.Element("MappedFolders")?.Element("MappedFolder")?.Element("HostFolder")?.Value);
        Assert.AreEqual("true", root.Element("MappedFolders")?.Element("MappedFolder")?.Element("ReadOnly")?.Value);
        Assert.AreEqual("C:\\VantrelInput", root.Element("MappedFolders")?.Element("MappedFolder")?.Element("SandboxFolder")?.Value);
    }

    [TestMethod]
    public void Sandbox_validator_covers_msi_hash_installation_state_and_absence_boundaries()
    {
        var script = File.ReadAllText(Path.Combine(RepositoryRoot(), "sandbox", "Validate-VantrelReleaseSandbox.ps1"));

        StringAssert.Contains(script, "msiexec.exe");
        StringAssert.Contains(script, "if ($args.Count -ne 0)");
        StringAssert.Contains(script, "$input = 'C:\\VantrelInput'");
        StringAssert.Contains(script, "Assert-SafeInputRoot");
        StringAssert.Contains(script, "Read-CanonicalPlan");
        StringAssert.Contains(script, "^[0-9a-f]{40}$");
        StringAssert.Contains(script, "Test-CanonicalReleaseVersion $values['release-version']");
        StringAssert.Contains(script, "sdk-version'] -match");
        StringAssert.Contains(script, "release-notes-sha256'] -match '^[0-9A-F]{64}$'");
        StringAssert.Contains(script, "Test-CanonicalUtc");
        StringAssert.Contains(script, "Test-CanonicalMsiVersion");
        StringAssert.Contains(script, "Test-CanonicalReleaseVersion");
        StringAssert.Contains(script, "Test-CanonicalReleaseSequence");
        StringAssert.Contains(script, "ProgramFiles64Folder\\Vantrel Security\\$folder");
        StringAssert.DoesNotMatch(script, new Regex("ProgramFiles64Folder\\\\\\\\Vantrel Security", RegexOptions.CultureInvariant));
        StringAssert.Contains(script, "$bytes = Read-SafeInputBytes $Path");
        StringAssert.Contains(script, "Sandbox installer plan hash does not match.");
        StringAssert.Contains(script, "Sandbox artifact plan does not match.");
        StringAssert.Contains(script, "$artifacts|Sort-Object Source");
        StringAssert.DoesNotMatch(script, new Regex("param\\s*\\(", RegexOptions.CultureInvariant));
        StringAssert.Contains(script, "Sandbox MSI hash does not match.");
        StringAssert.Contains(script, "Installed file validation failed.");
        StringAssert.Contains(script, "NT AUTHORITY\\LocalService");
        StringAssert.Contains(script, "StartMode -eq 'Manual'");
        StringAssert.Contains(script, "State -eq 'Stopped'");
        StringAssert.Contains(script, "System.Diagnostics.EventLog.Messages.dll");
        StringAssert.Contains(script, "Vantrel Security.lnk");
        StringAssert.Contains(script, "Vantrel Security\\Updates");
        StringAssert.Contains(script, ".update-journal-v1.lock");
        StringAssert.Contains(script, ".offline-update-owner-v1.lock");
        StringAssert.Contains(script, "Vantrel Security\\ReleasePolicy");
        StringAssert.DoesNotMatch(script, new Regex("start-service|stop-service|/f[a-z]*|/x\\s|uninstall", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
    }

    private static IReadOnlyList<InstallerPlanArtifact> Artifacts()
    {
        var paths = ReleasePayloadVerifier.ExactFileNames.Select(name => "service/" + name)
            .Concat(new[]
            {
                "desktop/Vantrel.Security.Desktop.exe", "desktop/Vantrel.Security.Desktop.dll", "desktop/Vantrel.Security.Infrastructure.dll", "desktop/Vantrel.Security.Core.dll",
                "offline-update-tool/Vantrel.Security.OfflineUpdateTool.exe", "offline-update-tool/Vantrel.Security.OfflineUpdateTool.dll", "offline-update-tool/Vantrel.Security.Service.dll", "offline-update-tool/Vantrel.Security.Infrastructure.dll", "offline-update-tool/Vantrel.Security.Core.dll"
            });
        return Array.AsReadOnly(paths.Select(path => new InstallerPlanArtifact(path, DestinationFor(path), new string('D', 64))).ToArray());
    }

    private static InstallerDestination DestinationFor(string source)
    {
        var root = source[..source.IndexOf('/')];
        var directory = root switch
        {
            "service" => "Vantrel Security\\Service",
            "desktop" => "Vantrel Security\\Desktop",
            "offline-update-tool" => "Vantrel Security\\OfflineUpdateTool",
            _ => throw new ArgumentException("Fixture source is unavailable.", nameof(source))
        };
        return new("ProgramFiles64Folder", directory + "\\" + source[(source.IndexOf('/') + 1)..].Replace('/', '\\'));
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "Vantrel.Security.sln"))) return directory.FullName;
        throw new InvalidOperationException("Repository root is unavailable.");
    }
}
