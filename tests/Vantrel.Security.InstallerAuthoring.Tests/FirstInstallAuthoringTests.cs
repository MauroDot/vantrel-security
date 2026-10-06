using System.Text;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Vantrel.Security.InstallerPreflight;
using Vantrel.Security.ManifestTool;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.InstallerAuthoring.Tests;

[TestClass]
public sealed class FirstInstallAuthoringTests
{
    [TestMethod]
    public void Canonical_plan_round_trips_and_generates_first_install_only_authoring()
    {
        var plan = CreatePlan();
        var canonical = InstallerInputValidator.CreateCanonicalPlan(plan);

        Assert.IsTrue(InstallerInputPlanCodec.TryParse(Encoding.UTF8.GetBytes(canonical), out var parsed));
        Assert.IsNotNull(parsed);
        var wix = WixFirstInstallAuthoring.CreateWixSource(parsed!);

        StringAssert.Contains(wix, "<Package Name=\"Vantrel Security\" Manufacturer=\"Mauro Interactive\" Version=\"0.1.1\" Scope=\"perMachine\">");
        StringAssert.Contains(wix, "<ServiceInstall Id=\"VantrelSecurityServiceInstall\" Name=\"VantrelSecurityService\" DisplayName=\"Vantrel Security Service\" Account=\"NT AUTHORITY\\LocalService\" Start=\"demand\" Type=\"ownProcess\"");
        AssertEventLogMessageFileTargetsMessageDll(wix);
        StringAssert.Contains(wix, "<Shortcut Id=\"VantrelStartMenuShortcut\" Directory=\"ProgramMenuFolder\" Name=\"Vantrel Security\" Advertise=\"no\"");
        Assert.IsFalse(wix.Contains("ProgramData", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(wix.Contains("<ServiceControl", StringComparison.Ordinal));
        Assert.IsFalse(wix.Contains("<CustomAction", StringComparison.Ordinal));
        Assert.IsFalse(wix.Contains("<MajorUpgrade", StringComparison.Ordinal));
        Assert.IsFalse(wix.Contains("<Upgrade", StringComparison.Ordinal));
        foreach (var artifact in plan.Artifacts)
            StringAssert.Contains(wix, "$(var.ReleaseLayoutRoot)\\" + artifact.SourceRelativePath.Replace('/', '\\'));
    }

    private static void AssertEventLogMessageFileTargetsMessageDll(string wix)
    {
        var messageFile = Regex.Match(wix, "<File Id=\"(?<id>[^\"]+)\" Source=\"\\$\\(var\\.ReleaseLayoutRoot\\)\\\\service\\\\System\\.Diagnostics\\.EventLog\\.Messages\\.dll\"", RegexOptions.CultureInvariant);
        var serviceFile = Regex.Match(wix, "<File Id=\"(?<id>[^\"]+)\" Source=\"\\$\\(var\\.ReleaseLayoutRoot\\)\\\\service\\\\Vantrel\\.Security\\.Service\\.exe\"", RegexOptions.CultureInvariant);
        Assert.IsTrue(messageFile.Success);
        Assert.IsTrue(serviceFile.Success);
        StringAssert.Contains(wix, "Name=\"EventMessageFile\" Value=\"[#" + messageFile.Groups["id"].Value + "]\"");
        Assert.IsFalse(wix.Contains("Name=\"EventMessageFile\" Value=\"[#" + serviceFile.Groups["id"].Value + "]\"", StringComparison.Ordinal));
    }

    [TestMethod]
    [DataRow("../escape.bin")]
    [DataRow("C:/artifact.bin")]
    [DataRow("C:artifact.bin")]
    public void Plan_parser_rejects_unsafe_artifact_paths(string unsafePath)
    {
        var canonical = InstallerInputValidator.CreateCanonicalPlan(CreatePlan());
        var altered = canonical.Replace("desktop/Vantrel.Security.Desktop.exe", unsafePath, StringComparison.Ordinal);

        Assert.IsFalse(InstallerInputPlanCodec.TryParse(Encoding.UTF8.GetBytes(altered), out _));
    }

    [TestMethod]
    public void Authoring_project_pins_Wix_v7_and_records_eula_acceptance()
    {
        var root = FindRepositoryRoot();
        var project = File.ReadAllText(Path.Combine(root, "installer", "Vantrel.Security.Installer", "Vantrel.Security.Installer.wixproj"));

        StringAssert.Contains(project, "Sdk=\"WixToolset.Sdk/7.0.0\"");
        StringAssert.Contains(project, "<AcceptEula>wix7</AcceptEula>");
        StringAssert.Contains(project, "GenerateValidatedFirstInstallAuthoring");
    }

    [TestMethod]
    public void Authoring_output_cannot_be_written_into_the_validated_release_layout()
    {
        using var scope = new LayoutScope();
        Assert.ThrowsExactly<IOException>(() => WixFirstInstallAuthoring.ValidateAndWrite(scope.Root, scope.PlanPath, Path.Combine(scope.Root, "first-install.wxs")));
        Assert.IsFalse(File.Exists(Path.Combine(scope.Root, "first-install.wxs")));
    }

    [TestMethod]
    public void Wix_project_builds_an_msi_only_from_a_validated_disposable_plan()
    {
        using var scope = new LayoutScope();
        var root = FindRepositoryRoot();
        var project = Path.Combine(root, "installer", "Vantrel.Security.Installer", "Vantrel.Security.Installer.wixproj");
        var output = scope.MsiOutputRoot + Path.DirectorySeparatorChar;
#if DEBUG
        const string configuration = "Debug";
#else
        const string configuration = "Release";
#endif
        WixFirstInstallAuthoring.ValidateAndWrite(scope.Root, scope.PlanPath, scope.AuthoringOutputPath);
        var start = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("build"); start.ArgumentList.Add(project); start.ArgumentList.Add("-t:Rebuild"); start.ArgumentList.Add("-c"); start.ArgumentList.Add(configuration); start.ArgumentList.Add("--no-restore");
        start.ArgumentList.Add("/p:InstallerInputPlan=" + scope.PlanPath); start.ArgumentList.Add("/p:ReleaseLayoutRoot=" + scope.Root); start.ArgumentList.Add("/p:OutputPath=" + output);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("WiX build process was unavailable.");
        var standardOutput = process.StandardOutput.ReadToEnd(); var standardError = process.StandardError.ReadToEnd();
        process.WaitForExit();

        Assert.AreEqual(0, process.ExitCode, standardOutput + standardError);
        Assert.HasCount(1, Directory.EnumerateFiles(scope.MsiOutputRoot, "VantrelSecurity.msi", SearchOption.AllDirectories).ToArray());
    }

    private static InstallerInputPlan CreatePlan()
    {
        var descriptor = new BetaReleaseDescriptor(new string('a', 40), "0.1.0-beta.1", 7,
            new DateTimeOffset(2026, 10, 6, 0, 0, 0, TimeSpan.Zero), "Release", "win-x64", "10.0.401", new string('B', 64));
        var paths = ReleasePayloadVerifier.ExactFileNames.Select(name => "service/" + name)
            .Concat(new[]
            {
                "desktop/Vantrel.Security.Desktop.exe", "desktop/Vantrel.Security.Desktop.dll", "desktop/Vantrel.Security.Infrastructure.dll", "desktop/Vantrel.Security.Core.dll",
                "offline-update-tool/Vantrel.Security.OfflineUpdateTool.exe", "offline-update-tool/Vantrel.Security.OfflineUpdateTool.dll", "offline-update-tool/Vantrel.Security.Service.dll", "offline-update-tool/Vantrel.Security.Infrastructure.dll", "offline-update-tool/Vantrel.Security.Core.dll"
            });
        var artifacts = paths.Select(path => new InstallerPlanArtifact(path, DestinationFor(path), new string('C', 64))).ToArray();
        return new(descriptor, "0.1.1", Array.AsReadOnly(artifacts), InitialInstallContract.Model);
    }

    private static InstallerDestination DestinationFor(string source)
    {
        var separator = source.IndexOf('/');
        var root = source[..separator] switch
        {
            "service" => "Vantrel Security\\Service",
            "desktop" => "Vantrel Security\\Desktop",
            "offline-update-tool" => "Vantrel Security\\OfflineUpdateTool",
            _ => throw new ArgumentException("Fixture source is unavailable.", nameof(source))
        };
        return new("ProgramFiles64Folder", root + "\\" + source[(separator + 1)..].Replace('/', '\\'));
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "Vantrel.Security.sln"))) return directory.FullName;
        throw new InvalidOperationException("Repository root is unavailable.");
    }

    private sealed class LayoutScope : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-installer-authoring-" + Guid.NewGuid().ToString("N"));
        internal string MsiOutputRoot { get; } = Path.Combine(Path.GetTempPath(), "vantrel-installer-authoring-msi-" + Guid.NewGuid().ToString("N"));
        internal string AuthoringOutputPath { get; } = Path.Combine(Path.GetTempPath(), "vantrel-installer-authoring-wxs-" + Guid.NewGuid().ToString("N") + ".wxs");
        internal string PlanPath => Path.Combine(Path.GetTempPath(), "vantrel-installer-authoring-plan-" + _id + ".txt");
        private readonly string _id = Guid.NewGuid().ToString("N");

        internal LayoutScope()
        {
            Directory.CreateDirectory(Root);
            var descriptor = new BetaReleaseDescriptor(new string('a', 40), "0.1.0-beta.1", 7,
                new DateTimeOffset(2026, 10, 6, 0, 0, 0, TimeSpan.Zero), "Release", "win-x64", "10.0.401", new string('B', 64));
            Write("release-notes.md", "notes");
            descriptor = descriptor with { ReleaseNotesSha256 = Hash("release-notes.md") };
            File.WriteAllBytes(Path.Combine(Root, BetaReleaseDescriptorCodec.FileName), BetaReleaseDescriptorCodec.CreateCanonical(descriptor));
            foreach (var name in ReleasePayloadVerifier.ExactFileNames) Write("service/" + name, name);
            foreach (var artifact in ReleaseSigningContract.VantrelOwnedPeArtifacts.Where(item => !item.RelativePath.StartsWith("service/", StringComparison.Ordinal))) Write(artifact.RelativePath, artifact.RelativePath);
            var artifacts = EnumerateArtifacts().ToArray();
            var evidence = ReleaseSigningContract.VantrelOwnedPeArtifacts.Select(item => new AuthenticodeReleaseEvidence(item.RelativePath,
                AuthenticodeVerificationCategory.Valid, "test-publisher-policy", PrimarySignatureCountPolicyCategory.ExactlyOne, TimestampPolicyCategory.ValidRfc3161)).ToArray();
            var record = new BetaReleaseRecord(descriptor, new(descriptor.ReleaseVersion, descriptor.ReleaseVersion, descriptor.ReleaseSequence, new string('C', 64)), Array.AsReadOnly(artifacts), Array.AsReadOnly(evidence));
            File.WriteAllBytes(Path.Combine(Root, BetaReleaseLayoutValidator.RecordFileName), BetaReleaseRecordCodec.CreateCanonical(record));
            new InstallerInputValidator().CreateAndWritePlan(Root, "0.1.1", PlanPath);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, true);
            if (Directory.Exists(MsiOutputRoot)) Directory.Delete(MsiOutputRoot, true);
            if (File.Exists(PlanPath)) File.Delete(PlanPath);
            if (File.Exists(AuthoringOutputPath)) File.Delete(AuthoringOutputPath);
        }

        private void Write(string relative, string content)
        {
            var path = Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, content);
        }
        private IEnumerable<ReleaseArtifact> EnumerateArtifacts()
        {
            foreach (var name in new[] { BetaReleaseDescriptorCodec.FileName, BetaReleaseLayoutValidator.ReleaseNotesFileName }) yield return new(name, Hash(name));
            foreach (var directory in new[] { "service", "desktop", "offline-update-tool" })
                foreach (var file in Directory.EnumerateFiles(Path.Combine(Root, directory), "*", SearchOption.AllDirectories).OrderBy(path => path, StringComparer.Ordinal))
                    yield return new(directory + "/" + Path.GetRelativePath(Path.Combine(Root, directory), file).Replace('\\', '/'), Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(file))));
        }
        private string Hash(string relative) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar)))));
    }
}
