using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2SourceBindingTests
{
    private const string Commit = "0123456789abcdef0123456789abcdef01234567";
    private const string Version = "0.1.0-beta.1";
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
    public void Independent_publish_binds_all_final_Service_bytes_allowing_only_four_signed_PEs()
    {
        using var fixture = new Fixture();
        fixture.Verify();
        Assert.AreEqual(1, fixture.Runner.PublishCount);
    }

    [TestMethod]
    public void Self_consistent_final_PE_with_non_Authenticode_change_is_rejected()
    {
        using var fixture = new Fixture();
        fixture.MutateFinal("Vantrel.Security.Service.dll", bytes => bytes[420] ^= 1);
        Assert.AreEqual("V2 Service source binding failed.",
            Assert.ThrowsException<IOException>(() => fixture.Verify()).Message);
        Assert.AreEqual(1, fixture.Runner.PublishCount);
    }

    [TestMethod]
    public void Self_consistent_final_dependency_change_is_rejected()
    {
        using var fixture = new Fixture();
        fixture.MutateFinal("Microsoft.Extensions.Hosting.dll", bytes => bytes[0] ^= 1);
        Assert.AreEqual("V2 Service source binding failed.",
            Assert.ThrowsException<IOException>(() => fixture.Verify()).Message);
        Assert.AreEqual(1, fixture.Runner.PublishCount);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _temporary = Path.Combine(Path.GetTempPath(),
            "vantrel-task073-source-binding-" + Guid.NewGuid().ToString("N"));
        private string Source => Path.Combine(_temporary, "source");
        private string SourceLock => Path.Combine(Source, "src", "Vantrel.Security.Service",
            "packages.lock.json");
        private string Output => Path.Combine(_temporary, "protected", "release");
        private string Service => Path.Combine(Output, "service");
        private string Diagnostics => Path.Combine(Output, "diagnostic-symbols");
        private readonly Dictionary<string, byte[]> _unsigned = new(StringComparer.Ordinal);
        internal FakeRunner Runner { get; }

        internal Fixture()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SourceLock)!);
            File.WriteAllText(SourceLock, "synthetic approved lock graph");
            File.WriteAllText(Path.Combine(Source, "global.json"),
                "{\"sdk\":{\"version\":\"10.0.401\",\"rollForward\":\"disable\"}}");
            File.WriteAllText(Path.Combine(Source, "src", "Vantrel.Security.Service",
                "Vantrel.Security.Service.csproj"),
                "<Project><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework></PropertyGroup></Project>");
            File.WriteAllText(Path.Combine(Source, "Vantrel.Security.sln"), "synthetic solution");
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Path.Combine(_temporary, "protected"));
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Output);
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Service);
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Diagnostics);

            AddService(ServicePublishFileSnapshot.DepsFileName, Encoding.UTF8.GetBytes(Dependencies));
            AddService(ServicePublishFileSnapshot.RuntimeConfigFileName,
                Encoding.UTF8.GetBytes(RuntimeConfig));
            foreach (var name in new[] { "Vantrel.Security.Service.exe", "Vantrel.Security.Service.dll",
                "Vantrel.Security.Core.dll", "Vantrel.Security.Infrastructure.dll" })
            {
                var unsigned = ServiceReleaseV2PeByteEquivalenceTests.Unsigned(true, 0);
                unsigned[420] ^= (byte)name.Length;
                AddService(name, unsigned, ServiceReleaseV2PeByteEquivalenceTests.Signed(unsigned, true));
            }
            foreach (var name in new[] { "Microsoft.Extensions.Hosting.WindowsServices.dll",
                "Microsoft.Extensions.Hosting.dll", "System.ServiceProcess.ServiceController.dll",
                "appsettings.json" })
                AddService(name, Encoding.UTF8.GetBytes(name));
            foreach (var name in new[] { "Vantrel.Security.Core.pdb",
                "Vantrel.Security.Infrastructure.pdb", "Vantrel.Security.Service.pdb" })
            {
                var bytes = Encoding.UTF8.GetBytes(name);
                _unsigned.Add(name, bytes);
                WriteProtected(Path.Combine(Diagnostics, name), bytes);
            }
            WriteProtected(Path.Combine(Output, "release-notes.md"),
                Encoding.UTF8.GetBytes("# Synthetic notes\n"));
            WriteProtected(Path.Combine(Output, BetaReleaseDescriptorCodec.FileName),
                Encoding.UTF8.GetBytes("test descriptor"));
            Runner = new FakeRunner(Source, SourceLock, _unsigned);
        }

        private void AddService(string name, byte[] unsigned, byte[]? final = null)
        {
            _unsigned.Add(name, unsigned);
            WriteProtected(Path.Combine(Service, name), final ?? unsigned);
        }

        private static void WriteProtected(string path, byte[] bytes)
        {
            File.WriteAllBytes(path, bytes);
            ServiceReleaseV2FileSystemSecurity.ProtectFile(path);
        }

        internal void MutateFinal(string name, Action<byte[]> mutation)
        {
            var path = Path.Combine(Service, name);
            var bytes = File.ReadAllBytes(path);
            mutation(bytes);
            File.WriteAllBytes(path, bytes);
        }

        internal void Verify()
        {
            var serviceFiles = Inventory(Service);
            var diagnostics = Inventory(Diagnostics);
            var expected = Directory.EnumerateFiles(Output).Select(file =>
                    new ServiceReleaseV2BoundFile(Path.GetFileName(file), Hash(file)))
                .Concat(serviceFiles.Select(file =>
                    new ServiceReleaseV2BoundFile("service/" + file.Path, file.Sha256)))
                .Concat(diagnostics.Select(file =>
                    new ServiceReleaseV2BoundFile("diagnostic-symbols/" + file.Path, file.Sha256)))
                .OrderBy(file => file.RelativePath, StringComparer.Ordinal).ToArray();
            using var binding = ServiceReleaseV2FinalBinding.Open(Output, expected);
            var descriptor = new BetaReleaseDescriptor(Commit, Version, 1,
                new DateTimeOffset(2026, 10, 10, 12, 0, 0, TimeSpan.Zero), "Release", "win-x64",
                "10.0.401", new string('A', 64));
            var provenance = new ServiceReleaseV2BuildProvenance(Commit, "10.0.401",
                Hash(SourceLock), "net10.0-windows", "win-x64", "framework-dependent");
            new ProductionServiceReleaseV2SourceBinding(Source, Commit, Runner).Verify(
                Output, descriptor, provenance, serviceFiles, diagnostics, binding);
        }

        private static TrustedManifestV2File[] Inventory(string directory) =>
            Directory.EnumerateFiles(directory).Select(file =>
                new TrustedManifestV2File(Path.GetFileName(file), Hash(file)))
                .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();

        private static string Hash(string path) =>
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

        public void Dispose()
        {
            var root = Path.GetFullPath(_temporary);
            var temp = Path.GetFullPath(Path.GetTempPath());
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(root).StartsWith("vantrel-task073-source-binding-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(root, recursive: true);
        }
    }

    private sealed class FakeRunner(string source, string sourceLock,
        IReadOnlyDictionary<string, byte[]> publishFiles) : IReleaseV2CommandRunner
    {
        internal int PublishCount { get; private set; }

        public ReleaseV2CommandResult Run(string executable, IReadOnlyList<string> arguments,
            string workingDirectory, bool captureStandardOutput)
        {
            Assert.AreEqual(source, workingDirectory);
            if (executable == "git")
            {
                if (ServiceReleaseV2FakeGitProof.TryRun(arguments, source, out var proof))
                    return proof;
                return arguments[2] switch
                {
                    "rev-parse" when arguments.Last() == "--show-toplevel" => new(0, source + "\n"),
                    "rev-parse" when arguments.Last() == "HEAD^{commit}" => new(0, Commit + "\n"),
                    "cat-file" => new(0, "commit\n"),
                    "status" => new(0, string.Empty),
                    "ls-files" when arguments.Last() == "-z" => new(0,
                        "global.json\0src/Vantrel.Security.Service/Vantrel.Security.Service.csproj\0" +
                        "src/Vantrel.Security.Service/packages.lock.json\0Vantrel.Security.sln\0"),
                    "ls-files" => new(0, arguments.Last() + "\n"),
                    _ => throw new AssertFailedException("Unexpected Git invocation")
                };
            }

            Assert.AreEqual("dotnet", executable);
            Assert.AreEqual("publish", arguments[0]);
            Assert.IsFalse(captureStandardOutput);
            PublishCount++;
            var output = arguments[Array.IndexOf(arguments.ToArray(), "--output") + 1];
            foreach (var file in publishFiles)
                File.WriteAllBytes(Path.Combine(output, file.Key), file.Value);
            File.Copy(sourceLock, Path.Combine(output, "packages.lock.json"));
            return new(0, string.Empty);
        }

        public ReleaseV2CommandResult RunWithInput(string executable,
            IReadOnlyList<string> arguments, string workingDirectory, Stream standardInput)
        {
            Assert.AreEqual("git", executable);
            Assert.AreEqual(source, workingDirectory);
            return ServiceReleaseV2FakeGitProof.RunWithInput(arguments, standardInput);
        }
    }
}
