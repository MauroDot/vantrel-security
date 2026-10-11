using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2SigningGateTests
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
    public void Injected_signer_visits_exact_four_Service_targets_in_contract_order_without_sidecars_or_record()
    {
        using var fixture = new Fixture();
        var result = fixture.Sign();
        string[] expected = ["service/Vantrel.Security.Service.exe",
            "service/Vantrel.Security.Service.dll", "service/Vantrel.Security.Infrastructure.dll",
            "service/Vantrel.Security.Core.dll"];
        CollectionAssert.AreEqual(expected, result.Select(item => item.RelativePath).ToArray());
        CollectionAssert.AreEqual(expected, fixture.Runner.Targets.Select(path =>
            "service/" + Path.GetFileName(path)).ToArray());
        CollectionAssert.AreEqual(expected, fixture.Auth.Verified.ToArray());
        Assert.AreEqual(4, fixture.Runner.Targets.Count);
        foreach (var args in fixture.Runner.InvocationArguments)
        {
            Assert.AreEqual(13, args.Count);
            CollectionAssert.AreEqual(new[] { "sign", "/v", "/fd", "SHA256", "/tr",
                AzureArtifactSigningOrchestrator.TimestampEndpoint, "/td", "SHA256", "/dlib" },
                args.Take(9).ToArray());
            Assert.AreEqual("Azure.CodeSigning.Dlib.dll", Path.GetFileName(args[9]));
            Assert.AreEqual("/dmdf", args[10]);
            Assert.AreEqual(AzureArtifactSigningMetadataCodec.LocalMetadataFileName,
                Path.GetFileName(args[11]));
        }
        Assert.IsFalse(File.Exists(Path.Combine(fixture.Output, BetaReleaseRecordV2Codec.FileName)));
        Assert.IsFalse(File.Exists(Path.Combine(fixture.Output, ServiceReleaseV2RecordGate.ManifestFileName)));
        Assert.IsFalse(File.Exists(Path.Combine(fixture.Output, ServiceReleaseV2RecordGate.MetadataFileName)));
    }

    [TestMethod]
    public void First_nonzero_signer_result_stops_without_verification_or_record()
    {
        using var fixture = new Fixture();
        fixture.Runner.ExitAt = 1;
        var error = Assert.ThrowsException<IOException>(() => fixture.Sign());
        Assert.AreEqual("V2 Service PE signing failed.", error.Message);
        Assert.AreEqual(1, fixture.Runner.Targets.Count);
        Assert.AreEqual(0, fixture.Auth.Verified.Count);
        Assert.IsFalse(File.Exists(Path.Combine(fixture.Output, BetaReleaseRecordV2Codec.FileName)));
    }

    [TestMethod]
    public void Mutation_of_unsigned_dependency_after_first_signer_invocation_fails_before_next_target()
    {
        using var fixture = new Fixture();
        fixture.Runner.MutateNonTarget = true;
        var error = Assert.ThrowsException<IOException>(() => fixture.Sign());
        Assert.AreEqual("V2 Service PE signing failed.", error.Message);
        Assert.AreEqual(1, fixture.Runner.Targets.Count);
        Assert.AreEqual(0, fixture.Auth.Verified.Count);
        Assert.IsFalse(File.Exists(Path.Combine(fixture.Output, BetaReleaseRecordV2Codec.FileName)));
    }

    [TestMethod]
    public void Unsigned_or_wrong_policy_post_sign_evidence_fails_without_record()
    {
        foreach (var failure in new[] { AuthFailure.Unsigned, AuthFailure.WrongPolicy })
        {
            using var fixture = new Fixture();
            fixture.Auth.Failure = failure;
            var error = Assert.ThrowsException<IOException>(() => fixture.Sign());
            Assert.AreEqual("V2 Service PE signing failed.", error.Message);
            Assert.AreEqual(4, fixture.Runner.Targets.Count);
            Assert.AreEqual(1, fixture.Auth.Verified.Count);
            Assert.IsFalse(File.Exists(Path.Combine(fixture.Output, BetaReleaseRecordV2Codec.FileName)));
        }
    }

    [TestMethod]
    public void Self_consistent_prepared_payload_that_differs_from_clean_source_is_not_signed()
    {
        using var fixture = new Fixture();
        fixture.ChangePreparedDependency();
        var error = Assert.ThrowsException<IOException>(() => fixture.Sign());
        Assert.AreEqual("V2 Service PE signing failed.", error.Message);
        Assert.AreEqual(0, fixture.Runner.Targets.Count);
        Assert.IsFalse(File.Exists(Path.Combine(fixture.Output, BetaReleaseRecordV2Codec.FileName)));
    }

    private enum AuthFailure { None, Unsigned, WrongPolicy }

    private sealed class FakeAuthGate : IServiceReleaseV2AuthenticodeGate
    {
        internal AuthFailure Failure { get; set; }
        internal List<string> Verified { get; } = [];

        public AuthenticodeReleaseEvidence Verify(string relativePath, string absolutePath,
            SafeFileHandle retainedHandle)
        {
            Assert.IsFalse(retainedHandle.IsInvalid || retainedHandle.IsClosed);
            Assert.IsTrue(File.Exists(absolutePath));
            Verified.Add(relativePath);
            return new AuthenticodeReleaseEvidence(relativePath,
                Failure == AuthFailure.Unsigned ? AuthenticodeVerificationCategory.Unsigned :
                    AuthenticodeVerificationCategory.Valid,
                Failure == AuthFailure.WrongPolicy ? "wrong-policy" :
                    BetaReleaseRecordV2Codec.SigningPolicyId,
                PrimarySignatureCountPolicyCategory.ExactlyOne,
                TimestampPolicyCategory.ValidRfc3161);
        }
    }

    private sealed class FakeSigner(string serviceRoot) : IAzureArtifactSigningProcessRunner
    {
        internal int ExitAt { get; set; }
        internal bool MutateNonTarget { get; set; }
        internal List<string> Targets { get; } = [];
        internal List<IReadOnlyList<string>> InvocationArguments { get; } = [];

        public int Run(string executablePath, IReadOnlyList<string> arguments)
        {
            Assert.AreEqual("signtool.exe", Path.GetFileName(executablePath));
            Targets.Add(arguments.Last());
            InvocationArguments.Add(arguments.ToArray());
            if (ExitAt == Targets.Count) return 1;
            File.AppendAllText(arguments.Last(), "synthetic signature " + Targets.Count,
                new UTF8Encoding(false));
            if (MutateNonTarget)
                File.AppendAllText(Path.Combine(serviceRoot, "Microsoft.Extensions.Hosting.dll"),
                    "changed dependency", new UTF8Encoding(false));
            return 0;
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(),
            "vantrel-task073-sign-gate-" + Guid.NewGuid().ToString("N"));
        private string Source => Path.Combine(_root, "source");
        private string SourceLock => Path.Combine(Source, "src", "Vantrel.Security.Service",
            "packages.lock.json");
        internal string Output => Path.Combine(_root, "protected", "release");
        private string Service => Path.Combine(Output, "service");
        private string Diagnostics => Path.Combine(Output, "diagnostic-symbols");
        private AzureArtifactSigningToolPaths Tools { get; }
        private FakeBuildRunner BuildRunner { get; }
        internal FakeSigner Runner { get; }
        internal FakeAuthGate Auth { get; } = new();

        internal Fixture()
        {
            Directory.CreateDirectory(_root);
            Directory.CreateDirectory(Path.GetDirectoryName(SourceLock)!);
            File.WriteAllText(Path.Combine(Source, "global.json"),
                "{\"sdk\":{\"version\":\"10.0.401\",\"rollForward\":\"disable\"}}");
            File.WriteAllText(Path.Combine(Source, "src", "Vantrel.Security.Service",
                "Vantrel.Security.Service.csproj"),
                "<Project><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework></PropertyGroup></Project>");
            File.WriteAllText(SourceLock, "synthetic approved lock graph");
            File.WriteAllText(Path.Combine(Source, "Vantrel.Security.sln"), "synthetic solution");
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(
                Path.Combine(_root, "protected"));
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Output);
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Service);
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Diagnostics);
            WriteProtected(Path.Combine(Service, ServicePublishFileSnapshot.DepsFileName), Dependencies);
            WriteProtected(Path.Combine(Service, ServicePublishFileSnapshot.RuntimeConfigFileName), RuntimeConfig);
            foreach (var file in new[]
            {
                "Vantrel.Security.Service.exe", "Vantrel.Security.Service.dll",
                "Vantrel.Security.Core.dll", "Vantrel.Security.Infrastructure.dll",
                "Microsoft.Extensions.Hosting.WindowsServices.dll", "Microsoft.Extensions.Hosting.dll",
                "System.ServiceProcess.ServiceController.dll", "appsettings.json"
            }) WriteProtected(Path.Combine(Service, file), file);
            foreach (var file in new[]
            {
                "Vantrel.Security.Core.pdb", "Vantrel.Security.Infrastructure.pdb",
                "Vantrel.Security.Service.pdb"
            }) WriteProtected(Path.Combine(Diagnostics, file), file);
            var notes = "# Synthetic v2 release notes\n";
            WriteProtected(Path.Combine(Output, BetaReleaseLayoutValidator.ReleaseNotesFileName), notes);
            var descriptor = new BetaReleaseDescriptor(Commit, Version, 1,
                new DateTimeOffset(2026, 10, 10, 12, 0, 0, TimeSpan.Zero), "Release", "win-x64",
                "10.0.401", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(notes))));
            WriteProtectedBytes(Path.Combine(Output, BetaReleaseDescriptorCodec.FileName),
                BetaReleaseDescriptorCodec.CreateCanonical(descriptor));

            var toolRoot = Path.Combine(_root, "tools");
            Directory.CreateDirectory(toolRoot);
            var signTool = Path.Combine(toolRoot, "signtool.exe");
            var dlib = Path.Combine(toolRoot, "Azure.CodeSigning.Dlib.dll");
            var metadata = Path.Combine(toolRoot, AzureArtifactSigningMetadataCodec.LocalMetadataFileName);
            File.WriteAllText(signTool, "injected only");
            File.WriteAllText(dlib, "injected only");
            File.WriteAllBytes(metadata, AzureArtifactSigningMetadataCodec.CreateCanonical(
                new AzureArtifactSigningMetadata(AzureArtifactSigningMetadataCodec.Endpoint,
                    AzureArtifactSigningMetadataCodec.AccountName,
                    AzureArtifactSigningMetadataCodec.CertificateProfileName, null,
                    InteractiveBrowserOnly: true)));
            Tools = new(signTool, dlib, metadata);
            BuildRunner = new FakeBuildRunner(Source, SourceLock, Service, Diagnostics);
            Runner = new FakeSigner(Service);
        }

        internal IReadOnlyList<AuthenticodeReleaseEvidence> Sign() =>
            new ServiceReleaseV2PeSigningGate(Runner, Auth).SignPreparedService(
                Output, Source, Commit, Tools, BuildRunner);

        internal void ChangePreparedDependency()
        {
            var path = Path.Combine(Service, "Microsoft.Extensions.Hosting.dll");
            File.AppendAllText(path, "changed after prepare");
        }

        private static void WriteProtected(string path, string value) =>
            WriteProtectedBytes(path, Encoding.UTF8.GetBytes(value));

        private static void WriteProtectedBytes(string path, byte[] bytes)
        {
            File.WriteAllBytes(path, bytes);
            ServiceReleaseV2FileSystemSecurity.ProtectFile(path);
        }

        public void Dispose()
        {
            var root = Path.GetFullPath(_root);
            var temp = Path.GetFullPath(Path.GetTempPath());
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(root).StartsWith("vantrel-task073-sign-gate-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(root, recursive: true);
        }
    }

    private sealed class FakeBuildRunner : IReleaseV2CommandRunner
    {
        private readonly string _source;
        private readonly string _sourceLock;
        private readonly IReadOnlyDictionary<string, byte[]> _publishFiles;

        internal FakeBuildRunner(string source, string sourceLock, string service, string diagnostics)
        {
            _source = source;
            _sourceLock = sourceLock;
            _publishFiles = Directory.EnumerateFiles(service).Concat(Directory.EnumerateFiles(diagnostics))
                .ToDictionary(path => Path.GetFileName(path)!, File.ReadAllBytes, StringComparer.Ordinal);
        }

        public ReleaseV2CommandResult Run(string executable, IReadOnlyList<string> arguments,
            string workingDirectory, bool captureStandardOutput)
        {
            Assert.AreEqual(_source, workingDirectory);
            if (executable == "git")
            {
                Assert.AreEqual("-C", arguments[0]);
                Assert.AreEqual(_source, arguments[1]);
                if (ServiceReleaseV2FakeGitProof.TryRun(arguments, _source, out var proof))
                    return proof;
                return arguments[2] switch
                {
                    "rev-parse" when arguments.Last() == "--show-toplevel" => new(0, _source + "\n"),
                    "rev-parse" when arguments.Last() == "HEAD^{commit}" => new(0, Commit + "\n"),
                    "cat-file" => new(0, "commit\n"),
                    "status" => new(0, string.Empty),
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
                CollectionAssert.Contains(arguments.ToArray(), "--locked-mode");
                return new(0, string.Empty);
            }
            Assert.AreEqual("publish", arguments[0]);
            var output = arguments[Array.IndexOf(arguments.ToArray(), "--output") + 1];
            foreach (var file in _publishFiles)
                File.WriteAllBytes(Path.Combine(output, file.Key), file.Value);
            File.Copy(_sourceLock, Path.Combine(output, "packages.lock.json"));
            return new(0, string.Empty);
        }

        public ReleaseV2CommandResult RunWithInput(string executable,
            IReadOnlyList<string> arguments, string workingDirectory, Stream standardInput)
        {
            Assert.AreEqual("git", executable);
            Assert.AreEqual(_source, workingDirectory);
            return ServiceReleaseV2FakeGitProof.RunWithInput(arguments, standardInput);
        }
    }
}
