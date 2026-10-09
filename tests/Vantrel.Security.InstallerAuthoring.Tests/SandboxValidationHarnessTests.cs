using System.Diagnostics;
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
    public void Signed_candidate_host_path_is_separate_and_never_builds_or_installs()
    {
        var script = File.ReadAllText(Path.Combine(RepositoryRoot(), "scripts", "Prepare-SignedWindowsSandboxValidation.ps1"));
        StringAssert.Contains(script, "prepare-signed-sandbox-input");
        StringAssert.Contains(script, "--no-build");
        StringAssert.Contains(script, "--no-restore");
        StringAssert.Contains(script, "$DistributionRecordSha256");
        StringAssert.DoesNotMatch(script, new Regex("emit-wix|wixproj|msiexec|signtool|windowssandbox\\.exe|start-service|stop-service", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
        var cli = File.ReadAllText(Path.Combine(RepositoryRoot(), "tools", "Vantrel.Security.InstallerPreflight", "Program.cs"));
        StringAssert.Contains(cli, "prepare-signed-sandbox-input");
        StringAssert.Contains(cli, "SignedSandboxCandidatePreparation.Prepare");
    }

    [TestMethod]
    public void Signed_candidate_sandbox_configuration_is_isolated_and_has_approved_hash_argument()
    {
        var document = XDocument.Load(Path.Combine(RepositoryRoot(), "sandbox", "Vantrel.Security.SignedReleaseValidation.wsb"));
        var root = document.Root!;
        foreach (var key in new[] { "Networking", "ClipboardRedirection", "PrinterRedirection", "VGpu" })
            Assert.AreEqual("Disable", root.Element(key)?.Value);
        var mappings = root.Element("MappedFolders")?.Elements("MappedFolder").ToArray() ?? [];
        Assert.HasCount(1, mappings);
        Assert.AreEqual("true", mappings[0].Element("ReadOnly")?.Value);
        Assert.AreEqual("C:\\VantrelInput", mappings[0].Element("SandboxFolder")?.Value);
        Assert.AreEqual("__VANTREL_SIGNED_SANDBOX_INPUT__", mappings[0].Element("HostFolder")?.Value);
        StringAssert.Contains(root.Element("LogonCommand")!.Element("Command")!.Value, "-ApprovedDistributionRecordSha256 \"__VANTREL_DISTRIBUTION_HASH__\"");
    }

    [TestMethod]
    public void Signed_candidate_host_generates_xml_from_real_logic_with_quoted_approved_argument()
    {
        var root = Path.Combine(Path.GetTempPath(), "vantrel-signed-wsb-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var harness = Path.Combine(root, "generate.ps1");
            var output = Path.Combine(root, "generated.wsb");
            const string mappedInput = @"C:\Vantrel Bundle & QA's\input";
            var approvedHash = new string('A', 64);
            File.WriteAllText(harness, """
                $ErrorActionPreference = 'Stop'
                try {
                    $source = Get-Content -Raw -LiteralPath $args[0]
                    $tokens = $null
                    $parseErrors = $null
                    $ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
                    if ($parseErrors.Count -ne 0) { throw 'Host script is invalid.' }
                    $definitions = @($ast.FindAll({ param($node)
                        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -ceq 'Write-SignedSandboxConfiguration'
                    }, $true))
                    if ($definitions.Count -ne 1) { throw 'Configuration generator is unavailable.' }
                    . ([ScriptBlock]::Create($definitions[0].Extent.Text))
                    Write-SignedSandboxConfiguration $args[1] $args[2] $args[3] $args[4]
                } catch { exit 1 }
                """);
            using var process = Process.Start(new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                ArgumentList =
                {
                    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness,
                    Path.Combine(RepositoryRoot(), "scripts", "Prepare-SignedWindowsSandboxValidation.ps1"),
                    Path.Combine(RepositoryRoot(), "sandbox", "Vantrel.Security.SignedReleaseValidation.wsb"),
                    mappedInput, approvedHash, output
                }
            })!;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            Assert.IsTrue(process.WaitForExit(10000), "Configuration generation did not finish.");
            Task.WaitAll(stdout, stderr);
            Assert.AreEqual(0, process.ExitCode, "Real configuration generation failed.");

            var document = XDocument.Load(output);
            var configuration = document.Root!;
            foreach (var key in new[] { "Networking", "ClipboardRedirection", "PrinterRedirection", "VGpu" })
                Assert.AreEqual("Disable", configuration.Element(key)?.Value);
            var mappings = configuration.Element("MappedFolders")!.Elements("MappedFolder").ToArray();
            Assert.HasCount(1, mappings);
            Assert.AreEqual(mappedInput, mappings[0].Element("HostFolder")?.Value);
            Assert.AreEqual("C:\\VantrelInput", mappings[0].Element("SandboxFolder")?.Value);
            Assert.AreEqual("true", mappings[0].Element("ReadOnly")?.Value);
            var command = configuration.Element("LogonCommand")!.Element("Command")!.Value;
            Assert.AreEqual(
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"C:\\VantrelInput\\Validate-VantrelSignedCandidateSandbox.ps1\" -ApprovedDistributionRecordSha256 \"" + approvedHash + "\"",
                command);
            StringAssert.Contains(File.ReadAllText(output), "Vantrel Bundle &amp; QA");
            StringAssert.DoesNotMatch(command, new Regex("__VANTREL_", RegexOptions.CultureInvariant));
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public void Signed_candidate_sandbox_checks_all_bindings_before_installation()
    {
        var script = File.ReadAllText(Path.Combine(RepositoryRoot(), "sandbox", "Validate-VantrelSignedCandidateSandbox.ps1"));
        var install = script.IndexOf("& \"$env:SystemRoot\\System32\\msiexec.exe\"", StringComparison.Ordinal);
        Assert.IsGreaterThan(0, install);
        foreach (var required in new[]
        {
            "Read-CanonicalPlan $planBytes", "Read-CanonicalSandboxInput $manifestPath",
            "Read-CanonicalDistributionRecord $distributionRecordBytes", "Read-SafeInputBytes $releaseRecordPath",
            "Sandbox distribution approval hash does not match.", "Sandbox distribution binding does not match.",
            "Sandbox artifact plan does not match.", "Sandbox input is invalid."
        })
        {
            var at = script.IndexOf(required, StringComparison.Ordinal);
            Assert.IsGreaterThan(-1, at, required);
            Assert.IsLessThan(install, at, required);
        }
        StringAssert.Contains(script, "'vantrel-signed-sandbox-input-v1'");
        StringAssert.Contains(script, "'ValidRfc3161'");
        StringAssert.Contains(script, "'ExactlyOne'");
        StringAssert.Contains(script, "'Match'");
        StringAssert.Contains(script, "[IO.FileAttributes]::ReparsePoint");
        StringAssert.Contains(script, "Get-BytesHash $distributionRecordBytes");
        StringAssert.DoesNotMatch(script, new Regex("::HashData\\(|::ToHexString\\(|TrimEndingDirectorySeparator", RegexOptions.CultureInvariant));
    }

    [TestMethod]
    public void Signed_candidate_powershell_parsers_reject_noncanonical_manifest_and_distribution_record()
    {
        var legacy = new SandboxValidationInput(new string('a', 40), "0.1.0-beta.1", 1,
            new DateTimeOffset(2026, 10, 8, 15, 41, 6, TimeSpan.Zero), "0.1.0",
            new string('A', 64), new string('B', 64), Artifacts());
        var manifest = Encoding.ASCII.GetString(SignedSandboxCandidateInputCodec.CreateCanonical(
            new(legacy, new string('C', 64), new string('D', 64), MsiAuthenticodeInspectionResult.PolicyId)));
        Assert.IsTrue(RunSignedParser("Read-CanonicalSandboxInput", manifest));
        foreach (var altered in new[]
        {
            manifest.Replace("distribution-record-sha256=" + new string('D', 64), "distribution-record-sha256=BAD", StringComparison.Ordinal),
            manifest.Replace("policy-id=" + MsiAuthenticodeInspectionResult.PolicyId, "policy-id=other", StringComparison.Ordinal),
            manifest.Replace("artifact-count=", "extra=value\nartifact-count=", StringComparison.Ordinal),
            manifest.Replace("desktop/Vantrel.Security.Desktop.exe", "../escape.exe", StringComparison.Ordinal),
            manifest.Replace("\n", "\r\n", StringComparison.Ordinal)
        }) Assert.IsFalse(RunSignedParser("Read-CanonicalSandboxInput", altered));
        var lines = manifest.Split('\n');
        (lines[12], lines[13]) = (lines[13], lines[12]);
        Assert.IsFalse(RunSignedParser("Read-CanonicalSandboxInput", string.Join('\n', lines)));

        var record = MsiDistributionRecordCodec.CreateCanonical(new("VantrelSecurity.msi", new string('A', 64),
            new string('C', 64), new string('B', 64), MsiAuthenticodeInspectionResult.PolicyId,
            NativeAuthenticodeTrustCategory.Success, PrimarySignatureCountPolicyCategory.ExactlyOne,
            NativeDigestAlgorithmCategory.Sha256, TimestampPolicyCategory.ValidRfc3161,
            AuthenticodeEkuPolicyCategory.Match));
        var distribution = Encoding.ASCII.GetString(record);
        Assert.IsTrue(RunSignedParser("Read-CanonicalDistributionRecord", distribution));
        Assert.IsFalse(RunSignedParser("Read-CanonicalDistributionRecord", distribution.Replace("timestamp=ValidRfc3161", "timestamp=Missing", StringComparison.Ordinal)));
        Assert.IsFalse(RunSignedParser("Read-CanonicalDistributionRecord", distribution.Replace("\n", "\r\n", StringComparison.Ordinal)));
    }

    private static bool RunSignedParser(string function, string value)
    {
        var script = File.ReadAllText(Path.Combine(RepositoryRoot(), "sandbox", "Validate-VantrelSignedCandidateSandbox.ps1"));
        var beginning = script.IndexOf("function Assert-Condition", StringComparison.Ordinal);
        var invocation = Regex.Match(script, "(?m)^Assert-SafeInputRoot\\s*$", RegexOptions.CultureInvariant);
        Assert.IsTrue(beginning >= 0 && invocation.Success);
        var definitions = script[beginning..invocation.Index];
        var data = Convert.ToBase64String(Encoding.ASCII.GetBytes(value));
        var command = definitions + "\n$script:synthetic=[Convert]::FromBase64String('" + data + "');" +
            "function Read-SafeInputBytes([string]$Path) { return $script:synthetic };" +
            "try { " + function + " $script:synthetic | Out-Null; exit 0 } catch { exit 1 }";
        if (function == "Read-CanonicalSandboxInput")
            command = definitions + "\n$script:synthetic=[Convert]::FromBase64String('" + data + "');" +
                "function Read-SafeInputBytes([string]$Path) { return ,$script:synthetic };" +
                "try { Read-CanonicalSandboxInput 'synthetic' | Out-Null; exit 0 } catch { exit 1 }";
        var temporary = Path.Combine(Path.GetTempPath(), "vantrel-signed-parser-" + Guid.NewGuid().ToString("N") + ".ps1");
        try
        {
            File.WriteAllText(temporary, command);
            using var process = Process.Start(new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                ArgumentList = { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", temporary }
            })!;
            process.StandardOutput.ReadToEnd();
            process.StandardError.ReadToEnd();
            Assert.IsTrue(process.WaitForExit(10000), "PowerShell parser did not finish.");
            return process.ExitCode == 0;
        }
        finally { File.Delete(temporary); }
    }

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
