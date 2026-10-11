using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2ProductionProjectionTests
{
    private const string Version = "0.1.0-beta.1";
    private const ulong Sequence = 1;
    private const string RuntimeConfig =
        "{\"runtimeOptions\":{\"tfm\":\"net10.0\",\"framework\":{\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.0\"}}}";
    private const string Dependencies = """
        {"runtimeTarget":{"name":".NETCoreApp,Version=v10.0/win-x64","signature":""},"compilationOptions":{},"targets":{".NETCoreApp,Version=v10.0/win-x64":{
        "Vantrel.Security.Service/0.1.0":{"dependencies":{"Microsoft.Extensions.Hosting.WindowsServices":"10.0.12","System.ServiceProcess.ServiceController":"10.0.12","Vantrel.Security.Core":"0.1.0","Vantrel.Security.Infrastructure":"0.1.0"},"runtime":{"Vantrel.Security.Service.dll":{}}},
        "Microsoft.Extensions.Hosting.WindowsServices/10.0.12":{"dependencies":{"Microsoft.Extensions.Hosting":"10.0.12"},"runtime":{"lib/net10.0/Microsoft.Extensions.Hosting.WindowsServices.dll":{}}},
        "Microsoft.Extensions.Hosting/10.0.12":{"runtime":{"lib/net10.0/Microsoft.Extensions.Hosting.dll":{}}},
        "System.ServiceProcess.ServiceController/10.0.12":{"runtime":{"runtimes/win/lib/net10.0/System.ServiceProcess.ServiceController.dll":{}}},
        "Vantrel.Security.Core/0.1.0":{"runtime":{"Vantrel.Security.Core.dll":{}}},
        "Vantrel.Security.Infrastructure/0.1.0":{"runtime":{"Vantrel.Security.Infrastructure.dll":{}}}
        }},"libraries":{"Vantrel.Security.Service/0.1.0":{"type":"project"},"Microsoft.Extensions.Hosting.WindowsServices/10.0.12":{"type":"package"},"Microsoft.Extensions.Hosting/10.0.12":{"type":"package"},"System.ServiceProcess.ServiceController/10.0.12":{"type":"package"},"Vantrel.Security.Core/0.1.0":{"type":"project"},"Vantrel.Security.Infrastructure/0.1.0":{"type":"project"}}}
        """;

    [TestMethod]
    public void Complete_sdk_publish_creates_only_non_pdb_Service_inventory_and_exact_protected_diagnostics()
    {
        using var fixture = new Fixture();
        var projected = fixture.Project();
        Assert.AreEqual(10, projected.ServiceFiles.Count);
        Assert.AreEqual(3, projected.DiagnosticSymbols.Count);
        CollectionAssert.AreEqual(new[]
        {
            "Vantrel.Security.Core.pdb", "Vantrel.Security.Infrastructure.pdb",
            "Vantrel.Security.Service.pdb"
        }, projected.DiagnosticSymbols.Select(file => file.Path).ToArray());
        Assert.IsFalse(projected.ServiceFiles.Any(file => file.Path.EndsWith(".pdb", StringComparison.Ordinal)));
        Assert.IsTrue(projected.ServiceFiles.Any(file => file.Path == "Microsoft.Extensions.Hosting.dll"));
        Assert.IsFalse(projected.ServiceFiles.Any(file => file.Path == "packages.lock.json"));
        Assert.AreEqual(1, projected.ExcludedBuildArtifacts.Count);
        CollectionAssert.AreEqual(TrustedManifestV2Codec.CreateCanonicalPayload(
            Version, Sequence, projected.ServiceFiles), projected.CanonicalManifestPayload);

        var children = Directory.EnumerateFileSystemEntries(fixture.Destination)
            .Select(Path.GetFileName).OrderBy(name => name, StringComparer.Ordinal).ToArray();
        CollectionAssert.AreEqual(new[] { "diagnostic-symbols", "service" }, children);
        var service = Path.Combine(fixture.Destination, "service");
        var diagnostics = Path.Combine(fixture.Destination, "diagnostic-symbols");
        ServiceReleaseV2FileSystemSecurity.RequireProtectedTree(service, projected.ServiceFiles);
        ServicePublishDependencyValidator.Validate(service, projected.ServiceFiles);
        ServiceReleaseV2ProductionProjector.ValidateDiagnosticSymbols(
            diagnostics, projected.DiagnosticSymbols);
        Assert.IsFalse(Directory.EnumerateFiles(service, "*.pdb", SearchOption.AllDirectories).Any());
        Assert.IsFalse(File.Exists(Path.Combine(service, "packages.lock.json")));
    }

    [TestMethod]
    public void Missing_or_extra_symbol_and_unprotected_parent_fail_before_destination()
    {
        using (var fixture = new Fixture())
        {
            File.Delete(fixture.SourceFile("Vantrel.Security.Core.pdb"));
            AssertProjectClosed(fixture);
        }
        using (var fixture = new Fixture())
        {
            fixture.WriteSource("Unexpected.pdb", "unexpected");
            AssertProjectClosed(fixture);
        }
        using (var fixture = new Fixture(protectedParent: false))
            AssertProjectClosed(fixture);
    }

    [TestMethod]
    public void Named_source_stream_and_changed_diagnostics_fail_closed()
    {
        using (var fixture = new Fixture())
        {
            File.WriteAllText(fixture.SourceFile("Vantrel.Security.Core.pdb") + ":hidden",
                "outside the manifest");
            AssertProjectClosed(fixture);
        }
        using (var fixture = new Fixture())
        {
            var projected = fixture.Project();
            var diagnostics = Path.Combine(fixture.Destination, "diagnostic-symbols");
            File.AppendAllText(Path.Combine(diagnostics, "Vantrel.Security.Core.pdb"), "changed");
            Assert.ThrowsException<IOException>(() =>
                ServiceReleaseV2ProductionProjector.ValidateDiagnosticSymbols(
                    diagnostics, projected.DiagnosticSymbols));
        }
    }

    private static void AssertProjectClosed(Fixture fixture)
    {
        Assert.ThrowsException<IOException>(() => fixture.Project());
        Assert.IsFalse(Directory.Exists(fixture.Destination));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly TemporaryDirectory _temporary = new();
        internal string Source { get; }
        internal string Destination { get; }
        internal string LockHash { get; }

        internal Fixture(bool protectedParent = true)
        {
            Source = Path.Combine(_temporary.Root, "publish");
            Directory.CreateDirectory(Source);
            var parent = Path.Combine(_temporary.Root, "protected-parent");
            if (protectedParent)
                ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(parent);
            else Directory.CreateDirectory(parent);
            Destination = Path.Combine(parent, "projected");
            WriteSource(ServicePublishFileSnapshot.DepsFileName, Dependencies);
            WriteSource(ServicePublishFileSnapshot.RuntimeConfigFileName, RuntimeConfig);
            foreach (var path in new[]
            {
                "Vantrel.Security.Service.exe", "Vantrel.Security.Service.dll",
                "Vantrel.Security.Core.dll", "Vantrel.Security.Infrastructure.dll",
                "Microsoft.Extensions.Hosting.WindowsServices.dll", "Microsoft.Extensions.Hosting.dll",
                "System.ServiceProcess.ServiceController.dll", "appsettings.json",
                "Vantrel.Security.Core.pdb", "Vantrel.Security.Infrastructure.pdb",
                "Vantrel.Security.Service.pdb"
            }) WriteSource(path, path);
            WriteSource("packages.lock.json", "approved lock graph");
            LockHash = Convert.ToHexString(SHA256.HashData(
                File.ReadAllBytes(SourceFile("packages.lock.json"))));
        }

        internal string SourceFile(string relative) => Path.Combine(Source, relative.Replace('/', '\\'));
        internal void WriteSource(string relative, string content)
        {
            var path = SourceFile(relative);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content, new UTF8Encoding(false));
        }

        internal ServiceReleaseV2ProductionProjection Project() =>
            new ServiceReleaseV2ProductionProjector().Project(Source, Destination,
                LockHash, Version, Sequence);

        public void Dispose() => _temporary.Dispose();
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(),
            "vantrel-task073-projection-" + Guid.NewGuid().ToString("N"));

        internal TemporaryDirectory() => Directory.CreateDirectory(Root);

        public void Dispose()
        {
            var root = Path.GetFullPath(Root);
            var temp = Path.GetFullPath(Path.GetTempPath());
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(root).StartsWith("vantrel-task073-projection-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(root, recursive: true);
        }
    }
}
