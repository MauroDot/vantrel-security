using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2PreparationTests
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
    public void Clean_locked_source_publishes_before_projection_and_creates_exact_protected_unsigned_output()
    {
        using var fixture = new Fixture();
        var prepared = fixture.Prepare();
        Assert.AreEqual(Commit, prepared.Descriptor.SourceCommit);
        Assert.AreEqual(Version, prepared.Descriptor.ReleaseVersion);
        Assert.AreEqual(1UL, prepared.Descriptor.ReleaseSequence);
        Assert.AreEqual("Release", prepared.Descriptor.Configuration);
        Assert.AreEqual("win-x64", prepared.Descriptor.Runtime);
        Assert.AreEqual("10.0.401", prepared.Descriptor.SdkVersion);
        Assert.AreEqual(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fixture.Notes))),
            prepared.Descriptor.ReleaseNotesSha256);
        CollectionAssert.AreEqual(new[]
        {
            BetaReleaseDescriptorCodec.FileName, "diagnostic-symbols", "release-notes.md", "service"
        }, Directory.EnumerateFileSystemEntries(fixture.Output).Select(Path.GetFileName)
            .OrderBy(name => name, StringComparer.Ordinal).ToArray());
        Assert.IsFalse(File.Exists(Path.Combine(fixture.Output, "beta-release-record-v1.txt")));
        Assert.IsTrue(prepared.PublishScratchRoot.StartsWith(fixture.ProtectedParent + "\\",
            StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(prepared.PublishScratchRoot.StartsWith(fixture.Output + "\\",
            StringComparison.OrdinalIgnoreCase));
        Assert.AreEqual(1, fixture.Runner.RestoreCount);
        Assert.AreEqual(1, fixture.Runner.PublishCount);
        Assert.IsTrue(fixture.Runner.Calls.FindIndex(c => c.Contains("restore", StringComparison.Ordinal)) <
            fixture.Runner.Calls.FindIndex(c => c.Contains("publish", StringComparison.Ordinal)));
        ServiceReleaseV2FileSystemSecurity.RequireProtectedFile(Path.Combine(
            fixture.Output, BetaReleaseDescriptorCodec.FileName));
        ServiceReleaseV2FileSystemSecurity.RequireProtectedFile(Path.Combine(
            fixture.Output, BetaReleaseLayoutValidator.ReleaseNotesFileName));
        Assert.IsTrue(BetaReleaseDescriptorCodec.TryParse(File.ReadAllBytes(Path.Combine(
            fixture.Output, BetaReleaseDescriptorCodec.FileName)), out var parsed));
        Assert.AreEqual(prepared.Descriptor, parsed);
        Assert.AreEqual(10, prepared.Projection.ServiceFiles.Count);
        Assert.AreEqual(3, prepared.Projection.DiagnosticSymbols.Count);
        Assert.IsFalse(prepared.Projection.ServiceFiles.Any(f => f.Path.EndsWith(".pdb", StringComparison.Ordinal)));
        Assert.IsTrue(prepared.Projection.ServiceFiles.Any(f => f.Path == "Microsoft.Extensions.Hosting.dll"));
    }

    [TestMethod]
    public void Invalid_source_or_existing_destination_prevents_restore_publish_and_output_creation()
    {
        using (var fixture = new Fixture())
        {
            fixture.Runner.Status = "?? untracked.bin";
            Assert.ThrowsException<IOException>(() => fixture.Prepare());
            Assert.AreEqual(0, fixture.Runner.RestoreCount);
            Assert.AreEqual(0, fixture.Runner.PublishCount);
            Assert.IsFalse(Directory.Exists(fixture.Output));
        }
        using (var fixture = new Fixture())
        {
            Directory.CreateDirectory(fixture.Output);
            Assert.ThrowsException<IOException>(() => fixture.Prepare());
            Assert.AreEqual(0, fixture.Runner.RestoreCount);
            Assert.AreEqual(0, fixture.Runner.PublishCount);
        }
        using (var fixture = new Fixture())
        {
            File.WriteAllText(fixture.Notes + ":hidden", "not bound");
            Assert.ThrowsException<IOException>(() => fixture.Prepare());
            Assert.AreEqual(0, fixture.Runner.RestoreCount);
            Assert.AreEqual(0, fixture.Runner.PublishCount);
        }
    }

    [TestMethod]
    public void Failed_or_incomplete_publish_cannot_create_completed_output()
    {
        using (var fixture = new Fixture())
        {
            fixture.Runner.PublishExit = 1;
            Assert.ThrowsException<IOException>(() => fixture.Prepare());
            Assert.AreEqual(1, fixture.Runner.PublishCount);
            Assert.IsFalse(Directory.Exists(fixture.Output));
        }
        using (var fixture = new Fixture())
        {
            fixture.Runner.OmitHosting = true;
            Assert.ThrowsException<IOException>(() => fixture.Prepare());
            Assert.AreEqual(1, fixture.Runner.PublishCount);
            Assert.IsFalse(Directory.Exists(fixture.Output));
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(),
            "vantrel-task073-prepare-" + Guid.NewGuid().ToString("N"));
        internal string Source => Path.Combine(_root, "source");
        internal string ProtectedParent => Path.Combine(_root, "protected");
        internal string Output => Path.Combine(ProtectedParent, "release");
        internal string Notes => Path.Combine(_root, "external-notes.md");
        internal string SourceLock => Path.Combine(Source, "src", "Vantrel.Security.Service", "packages.lock.json");
        internal FakeRunner Runner { get; }

        internal Fixture()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SourceLock)!);
            File.WriteAllText(Path.Combine(Source, "global.json"),
                "{\"sdk\":{\"version\":\"10.0.401\",\"rollForward\":\"disable\"}}");
            File.WriteAllText(Path.Combine(Source, "src", "Vantrel.Security.Service",
                "Vantrel.Security.Service.csproj"),
                "<Project><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework></PropertyGroup></Project>");
            File.WriteAllText(SourceLock, "synthetic approved lock graph");
            File.WriteAllText(Path.Combine(Source, "Vantrel.Security.sln"), "synthetic solution");
            File.WriteAllText(Notes, "# Synthetic v2 release notes\n", new UTF8Encoding(false));
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(ProtectedParent);
            Runner = new FakeRunner(Source, SourceLock);
        }

        internal ServiceReleaseV2PreparationResult Prepare() =>
            ServiceReleaseV2Preparation.Prepare(Source, Commit, Output, Notes, Version, 1,
                new DateTimeOffset(2026, 10, 10, 12, 0, 0, TimeSpan.Zero), Runner);

        public void Dispose()
        {
            var root = Path.GetFullPath(_root);
            var temp = Path.GetFullPath(Path.GetTempPath());
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(root).StartsWith("vantrel-task073-prepare-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(root, recursive: true);
        }
    }

    private sealed class FakeRunner(string source, string sourceLock) : IReleaseV2CommandRunner
    {
        internal string Status { get; set; } = string.Empty;
        internal int PublishExit { get; set; }
        internal bool OmitHosting { get; set; }
        internal int RestoreCount { get; private set; }
        internal int PublishCount { get; private set; }
        internal List<string> Calls { get; } = [];

        public ReleaseV2CommandResult Run(string executable, IReadOnlyList<string> arguments,
            string workingDirectory, bool captureStandardOutput)
        {
            Assert.AreEqual(source, workingDirectory);
            Calls.Add(executable + " " + string.Join(" ", arguments));
            if (executable == "git")
            {
                Assert.AreEqual("-C", arguments[0]);
                Assert.AreEqual(source, arguments[1]);
                if (ServiceReleaseV2FakeGitProof.TryRun(arguments, source, out var proof))
                    return proof;
                return arguments[2] switch
                {
                    "rev-parse" when arguments.Last() == "--show-toplevel" => new(0, source + "\n"),
                    "rev-parse" when arguments.Last() == "HEAD^{commit}" => new(0, Commit + "\n"),
                    "cat-file" => new(0, "commit\n"),
                    "status" => new(0, Status),
                    "ls-files" when arguments.Last() == "-z" => new(0,
                        "global.json\0src/Vantrel.Security.Service/Vantrel.Security.Service.csproj\0" +
                        "src/Vantrel.Security.Service/packages.lock.json\0Vantrel.Security.sln\0"),
                    "ls-files" => new(0, arguments.Last() + "\n"),
                    _ => throw new AssertFailedException("Unexpected Git command")
                };
            }
            Assert.AreEqual("dotnet", executable);
            if (arguments.SequenceEqual(["--version"])) return new(0, "10.0.401\n");
            Assert.IsFalse(captureStandardOutput);
            if (arguments[0] == "restore")
            {
                RestoreCount++;
                CollectionAssert.Contains(arguments.ToArray(), "--locked-mode");
                CollectionAssert.Contains(arguments.ToArray(), "win-x64");
                return new(0, string.Empty);
            }
            Assert.AreEqual("publish", arguments[0]);
            PublishCount++;
            CollectionAssert.Contains(arguments.ToArray(), "--no-restore");
            CollectionAssert.Contains(arguments.ToArray(), "--self-contained");
            CollectionAssert.Contains(arguments.ToArray(), "false");
            if (PublishExit != 0) return new(PublishExit, string.Empty);
            var output = arguments[Array.IndexOf(arguments.ToArray(), "--output") + 1];
            WritePublish(output, sourceLock, OmitHosting);
            return new(0, string.Empty);
        }

        public ReleaseV2CommandResult RunWithInput(string executable,
            IReadOnlyList<string> arguments, string workingDirectory, Stream standardInput)
        {
            Assert.AreEqual("git", executable);
            Assert.AreEqual(source, workingDirectory);
            return ServiceReleaseV2FakeGitProof.RunWithInput(arguments, standardInput);
        }

        private static void WritePublish(string output, string sourceLock, bool omitHosting)
        {
            File.WriteAllText(Path.Combine(output, ServicePublishFileSnapshot.DepsFileName),
                Dependencies, new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(output, ServicePublishFileSnapshot.RuntimeConfigFileName),
                RuntimeConfig, new UTF8Encoding(false));
            foreach (var file in new[]
            {
                "Vantrel.Security.Service.exe", "Vantrel.Security.Service.dll",
                "Vantrel.Security.Core.dll", "Vantrel.Security.Infrastructure.dll",
                "Microsoft.Extensions.Hosting.WindowsServices.dll", "Microsoft.Extensions.Hosting.dll",
                "System.ServiceProcess.ServiceController.dll", "appsettings.json",
                "Vantrel.Security.Core.pdb", "Vantrel.Security.Infrastructure.pdb",
                "Vantrel.Security.Service.pdb"
            })
                if (!omitHosting || file != "Microsoft.Extensions.Hosting.dll")
                    File.WriteAllText(Path.Combine(output, file), file, new UTF8Encoding(false));
            File.Copy(sourceLock, Path.Combine(output, "packages.lock.json"));
        }
    }
}
