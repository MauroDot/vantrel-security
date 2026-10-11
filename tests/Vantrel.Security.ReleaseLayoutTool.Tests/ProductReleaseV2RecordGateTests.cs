using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using Vantrel.Security.Core;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
[SupportedOSPlatform("windows")]
public sealed class ProductReleaseV2RecordGateTests
{
    private const string HashText = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string Commit = "0123456789abcdef0123456789abcdef01234567";

    [TestMethod]
    public void Complete_synthetic_product_emits_exact_service_bound_record_after_thirteen_checks()
    {
        using var fixture = new Fixture();
        var auth = new SyntheticAuthenticode();
        var record = fixture.Gate(auth).ValidateAndWriteRecord(fixture.Root, fixture.Provenance);
        Assert.AreEqual(13, auth.Paths.Count);
        CollectionAssert.AreEqual(ReleaseSigningContract.VantrelOwnedPeArtifacts
            .Select(item => item.RelativePath).ToArray(), auth.Paths.ToArray());
        Assert.AreEqual(fixture.ServiceRecordHash, record.ServiceRecordSha256);
        Assert.AreEqual(4, record.ExcludedBuildArtifacts.Count);
        Assert.AreEqual(10, record.DiagnosticSymbols.Count);
        Assert.IsTrue(record.ToolFiles.Any(file => file.Path == "Vantrel.Security.Service.dll"));
        Assert.IsFalse(record.ServiceFiles.Any(file => file.Path == "Vantrel.Security.OfflineUpdateTool.dll"));
        var bytes = File.ReadAllBytes(fixture.ProductRecordPath);
        Assert.IsTrue(ProductReleaseRecordV2Codec.TryParse(bytes, out var parsed));
        CollectionAssert.AreEqual(bytes, ProductReleaseRecordV2Codec.CreateCanonical(parsed!));
    }

    [TestMethod]
    public void Changed_service_record_or_product_bytes_never_publish_product_evidence()
    {
        using (var fixture = new Fixture())
        {
            fixture.Mutate(BetaReleaseRecordV2Codec.FileName);
            Assert.ThrowsException<IOException>(() => fixture.Gate().ValidateAndWriteRecord(
                fixture.Root, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.ProductRecordPath));
        }
        foreach (var path in new[] { "desktop/Microsoft.Extensions.Hosting.dll",
            "offline-update-tool/Vantrel.Security.Service.dll" })
        {
            using var fixture = new Fixture();
            fixture.Mutate(path);
            Assert.ThrowsException<IOException>(() => fixture.Gate().ValidateAndWriteRecord(
                fixture.Root, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.ProductRecordPath));
        }
    }

    [TestMethod]
    public void Wrong_authenticode_policy_extra_file_and_missing_file_fail_before_publication()
    {
        using (var fixture = new Fixture())
        {
            Assert.ThrowsException<IOException>(() => fixture.Gate(new SyntheticAuthenticode
            { Reject = "desktop/Vantrel.Security.Desktop.exe" }).ValidateAndWriteRecord(
                fixture.Root, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.ProductRecordPath));
        }
        using (var fixture = new Fixture())
        {
            fixture.Write("desktop/unrecorded.dll", "extra"u8.ToArray());
            Assert.ThrowsException<IOException>(() => fixture.Gate().ValidateAndWriteRecord(
                fixture.Root, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.ProductRecordPath));
        }
        using (var fixture = new Fixture())
        {
            File.Delete(Path.Combine(fixture.Root, "offline-update-tool", "Vantrel.Security.Core.dll"));
            Assert.ThrowsException<IOException>(() => fixture.Gate().ValidateAndWriteRecord(
                fixture.Root, fixture.Provenance));
            Assert.IsFalse(File.Exists(fixture.ProductRecordPath));
        }
    }

    [TestMethod]
    public void Final_product_file_handles_deny_writes_during_authenticode_inspection()
    {
        using var fixture = new Fixture();
        var authenticode = new SyntheticAuthenticode { AttemptMutation =
            "desktop/Vantrel.Security.Desktop.exe" };
        _ = fixture.Gate(authenticode).ValidateAndWriteRecord(fixture.Root, fixture.Provenance);
        Assert.IsTrue(authenticode.MutationDenied);
        Assert.IsTrue(File.Exists(fixture.ProductRecordPath));
    }

    [TestMethod]
    public void Existing_product_record_is_never_replaced()
    {
        using var fixture = new Fixture();
        var existing = "competing product record"u8.ToArray();
        fixture.Write(ProductReleaseRecordV2Codec.FileName, existing);
        Assert.ThrowsException<IOException>(() => fixture.Gate().ValidateAndWriteRecord(
            fixture.Root, fixture.Provenance));
        CollectionAssert.AreEqual(existing, File.ReadAllBytes(fixture.ProductRecordPath));
    }

    [TestMethod]
    public void Projector_copies_only_validated_service_desktop_and_tool_files_into_an_exact_layout()
    {
        using var fixture = new Fixture();
        var (serviceOnly, destination, inputs) = fixture.ProjectionInputs();
        ProductReleaseV2Projector.Project(serviceOnly, destination, inputs,
            fixture.SignatureGate());
        Assert.IsTrue(BetaReleaseRecordV2Codec.TryParse(File.ReadAllBytes(Path.Combine(destination,
            BetaReleaseRecordV2Codec.FileName)), out _));
        Assert.IsFalse(File.Exists(Path.Combine(destination, ProductReleaseRecordV2Codec.FileName)));
        Assert.IsTrue(File.Exists(Path.Combine(destination, "offline-update-tool",
            "Vantrel.Security.Service.dll")));
        foreach (var excluded in new[] { "packages.lock.json", "Vantrel.Security.Service.exe",
            "Vantrel.Security.Service.deps.json", "Vantrel.Security.Service.runtimeconfig.json" })
            Assert.IsFalse(File.Exists(Path.Combine(destination, "offline-update-tool", excluded)));
        Assert.IsFalse(Directory.GetFiles(Path.Combine(destination, "desktop"), "*.pdb").Any());
        Assert.IsFalse(Directory.GetFiles(Path.Combine(destination, "offline-update-tool"), "*.pdb").Any());
        Assert.AreEqual(10, Directory.GetFiles(Path.Combine(destination, "diagnostic-symbols"),
            "*.pdb", SearchOption.AllDirectories).Length);
        _ = ProductPublishDependencyValidator.ValidateProjected(Path.Combine(destination, "desktop"),
            ProductPublishKind.Desktop, inputs.DesktopValidation.Files);
        _ = ProductPublishDependencyValidator.ValidateProjected(Path.Combine(destination,
            "offline-update-tool"), ProductPublishKind.OfflineUpdateTool, inputs.ToolValidation.Files);
    }

    private sealed class SyntheticAuthenticode : IServiceReleaseV2AuthenticodeGate
    {
        internal List<string> Paths { get; } = [];
        internal string? Reject { get; init; }
        internal string? AttemptMutation { get; init; }
        internal bool MutationDenied { get; private set; }
        public AuthenticodeReleaseEvidence Verify(string relativePath, string absolutePath,
            SafeFileHandle retainedHandle)
        {
            Paths.Add(relativePath);
            Assert.IsFalse(retainedHandle.IsClosed || retainedHandle.IsInvalid);
            if (relativePath == AttemptMutation)
            {
                try { File.AppendAllText(absolutePath, "changed"); }
                catch (IOException) { MutationDenied = true; }
            }
            return new(relativePath, relativePath == Reject
                    ? AuthenticodeVerificationCategory.AlteredOrTrustFailure
                    : AuthenticodeVerificationCategory.Valid,
                BetaReleaseRecordV2Codec.SigningPolicyId,
                PrimarySignatureCountPolicyCategory.ExactlyOne,
                TimestampPolicyCategory.ValidRfc3161);
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _temporary = Path.Combine(Path.GetTempPath(),
            "vantrel-product-record-" + Guid.NewGuid().ToString("N"));
        private readonly ECDsa _manifestKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _metadataKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly TrustedManifestV2File[] _desktopFiles;
        private readonly TrustedManifestV2File[] _toolFiles;
        internal string Root { get; }
        internal string ProductRecordPath => Path.Combine(Root, ProductReleaseRecordV2Codec.FileName);
        internal string ServiceRecordHash { get; }
        internal ServiceReleaseV2BuildProvenance Provenance { get; } = new(Commit,
            "10.0.401", HashText, "net10.0-windows", "win-x64", "framework-dependent");

        internal Fixture()
        {
            Directory.CreateDirectory(_temporary);
            var parent = Path.Combine(_temporary, "protected");
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(parent);
            Root = Path.Combine(parent, "layout");
            foreach (var part in new[] { Root, Path.Combine(Root, "service"),
                Path.Combine(Root, "desktop"), Path.Combine(Root, "offline-update-tool"),
                Path.Combine(Root, "diagnostic-symbols") })
                ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(part);
            Write("release-notes.md", "# Synthetic product\n"u8.ToArray());
            var descriptor = new BetaReleaseDescriptor(Commit, "0.1.0-beta.1", 1,
                new DateTimeOffset(2026, 10, 10, 12, 0, 0, TimeSpan.Zero), "Release",
                "win-x64", "10.0.401", Hash(File.ReadAllBytes(Path.Combine(Root, "release-notes.md"))));
            Write(BetaReleaseDescriptorCodec.FileName, BetaReleaseDescriptorCodec.CreateCanonical(descriptor));
            WriteGroup("service", "Vantrel.Security.Service", ["Vantrel.Security.Service",
                "Vantrel.Security.Core", "Vantrel.Security.Infrastructure",
                "Microsoft.Extensions.Hosting.WindowsServices", "Microsoft.Extensions.Hosting",
                "System.ServiceProcess.ServiceController"], true);
            WriteGroup("desktop", "Vantrel.Security.Desktop", ["Vantrel.Security.Desktop",
                "Vantrel.Security.Core", "Vantrel.Security.Infrastructure",
                "Microsoft.Extensions.Hosting"], false);
            WriteGroup("offline-update-tool", "Vantrel.Security.OfflineUpdateTool",
                ["Vantrel.Security.OfflineUpdateTool", "Vantrel.Security.Service",
                    "Vantrel.Security.Core", "Vantrel.Security.Infrastructure"], false);
            _desktopFiles = Inventory("desktop");
            _toolFiles = Inventory("offline-update-tool");
            var service = Inventory("service");
            var manifest = TrustedManifestV2Codec.CreateFile(descriptor.ReleaseVersion,
                descriptor.ReleaseSequence, service, _manifestKey);
            Write(ServiceReleaseV2RecordGate.ManifestFileName, manifest);
            var metadata = ReleaseMetadataCodec.CreateFile(1, Hash(manifest),
                descriptor.ReleaseVersion, descriptor.PublishedAtUtc, _metadataKey);
            Write(ServiceReleaseV2RecordGate.MetadataFileName, metadata);
            var symbols = new[] { "Vantrel.Security.Core.pdb",
                "Vantrel.Security.Infrastructure.pdb", "Vantrel.Security.Service.pdb" }
                .Select(name => new TrustedManifestV2File(name, Hash(File.ReadAllBytes(
                    Path.Combine(Root, "diagnostic-symbols", name)))))
                .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
            var evidence = ReleaseSigningContract.VantrelOwnedPeArtifacts.Take(4)
                .Select(item => new AuthenticodeReleaseEvidence(item.RelativePath,
                    AuthenticodeVerificationCategory.Valid, BetaReleaseRecordV2Codec.SigningPolicyId,
                    PrimarySignatureCountPolicyCategory.ExactlyOne,
                    TimestampPolicyCategory.ValidRfc3161)).ToArray();
            var serviceRecord = new BetaReleaseRecordV2(descriptor, HashText, Hash(manifest),
                Hash(TrustedManifestV2Codec.CreateCanonicalPayload(descriptor.ReleaseVersion,
                    descriptor.ReleaseSequence, service)), Hash(metadata), service, evidence, symbols);
            var recordBytes = BetaReleaseRecordV2Codec.CreateCanonical(serviceRecord);
            Write(BetaReleaseRecordV2Codec.FileName, recordBytes);
            ServiceRecordHash = Hash(recordBytes);
        }

        internal ProductReleaseV2RecordGate Gate(SyntheticAuthenticode? auth = null) => new(
            new SyntheticServiceSource(), new SyntheticProductSource(_desktopFiles, _toolFiles),
            SignatureGate(), auth ?? new SyntheticAuthenticode());

        internal IServiceReleaseV2SignatureGate SignatureGate() => new SyntheticSignatureGate(
            _manifestKey.ExportSubjectPublicKeyInfo(), _metadataKey.ExportSubjectPublicKeyInfo());

        internal (string ServiceOnly, string Destination, ProductPublishInputs Inputs) ProjectionInputs()
        {
            var parent = Path.GetDirectoryName(Root)!;
            var serviceOnly = Path.Combine(parent, "service-only");
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(serviceOnly);
            foreach (var name in new[] { "service", "diagnostic-symbols" })
                ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Path.Combine(serviceOnly, name));
            foreach (var name in new[] { BetaReleaseDescriptorCodec.FileName, "release-notes.md",
                ServiceReleaseV2RecordGate.ManifestFileName, ServiceReleaseV2RecordGate.MetadataFileName,
                BetaReleaseRecordV2Codec.FileName })
                CopyProtected(Path.Combine(Root, name), Path.Combine(serviceOnly, name));
            foreach (var name in new[] { "service", "diagnostic-symbols" })
                foreach (var path in Directory.GetFiles(Path.Combine(Root, name)))
                    CopyProtected(path, Path.Combine(serviceOnly, name, Path.GetFileName(path)));

            var desktopSource = Path.Combine(parent, "desktop-publish");
            var toolSource = Path.Combine(parent, "tool-publish");
            Directory.CreateDirectory(desktopSource);
            Directory.CreateDirectory(toolSource);
            foreach (var (group, source) in new[] { ("desktop", desktopSource),
                ("offline-update-tool", toolSource) })
            {
                foreach (var path in Directory.GetFiles(Path.Combine(Root, group)))
                    File.Copy(path, Path.Combine(source, Path.GetFileName(path)));
                foreach (var path in Directory.GetFiles(Path.Combine(Root,
                    "diagnostic-symbols", group)))
                    File.Copy(path, Path.Combine(source, Path.GetFileName(path)));
            }
            var serviceHost = new[] { "Vantrel.Security.Service.exe",
                "Vantrel.Security.Service.deps.json",
                "Vantrel.Security.Service.runtimeconfig.json" }
                .ToDictionary(name => name, name =>
                {
                    var from = Path.Combine(serviceOnly, "service", name);
                    File.Copy(from, Path.Combine(toolSource, name));
                    return Hash(File.ReadAllBytes(from));
                }, StringComparer.Ordinal);
            var lockBytes = "synthetic source lock"u8.ToArray();
            File.WriteAllBytes(Path.Combine(toolSource, "packages.lock.json"), lockBytes);
            var lockHash = Hash(lockBytes);
            var desktop = ProductPublishDependencyValidator.ValidateSdkPublish(desktopSource,
                ProductPublishKind.Desktop, HashText);
            var tool = ProductPublishDependencyValidator.ValidateSdkPublish(toolSource,
                ProductPublishKind.OfflineUpdateTool, lockHash, serviceHost);
            return (serviceOnly, Path.Combine(parent, "projected-product"),
                new ProductPublishInputs(Path.Combine(serviceOnly, "service"), desktopSource,
                    toolSource, desktop, tool, lockHash, HashText, HashText, serviceHost));
        }

        private static void CopyProtected(string source, string destination)
        {
            File.Copy(source, destination);
            ServiceReleaseV2FileSystemSecurity.ProtectFile(destination);
        }

        internal void Mutate(string relative)
        {
            var path = Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));
            File.AppendAllText(path, "changed");
        }

        internal void Write(string relative, byte[] bytes)
        {
            var path = Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));
            File.WriteAllBytes(path, bytes);
            ServiceReleaseV2FileSystemSecurity.ProtectFile(path);
        }

        private void WriteGroup(string group, string rootName, string[] assemblies, bool service)
        {
            Write(group + "/" + rootName + ".deps.json", Encoding.UTF8.GetBytes(Deps(rootName)));
            var runtime = service || group == "offline-update-tool"
                ? "{\"runtimeOptions\":{\"tfm\":\"net10.0\",\"framework\":{\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.0\"}}}"
                : "{\"runtimeOptions\":{\"tfm\":\"net10.0\",\"frameworks\":[{\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.0\"},{\"name\":\"Microsoft.WindowsDesktop.App\",\"version\":\"10.0.0\"}]}}";
            Write(group + "/" + rootName + ".runtimeconfig.json", Encoding.UTF8.GetBytes(runtime));
            Write(group + "/" + rootName + ".exe", "MZsynthetic"u8.ToArray());
            foreach (var assembly in assemblies)
                Write(group + "/" + assembly + ".dll", Encoding.ASCII.GetBytes(assembly));
            if (service || group == "offline-update-tool")
                Write(group + "/appsettings.json", "{}"u8.ToArray());
            var symbols = group == "service"
                ? new[] { "Vantrel.Security.Service", "Vantrel.Security.Core",
                    "Vantrel.Security.Infrastructure" }
                : group == "desktop"
                    ? new[] { "Vantrel.Security.Desktop", "Vantrel.Security.Core",
                        "Vantrel.Security.Infrastructure" }
                    : new[] { "Vantrel.Security.OfflineUpdateTool", "Vantrel.Security.Service",
                        "Vantrel.Security.Core", "Vantrel.Security.Infrastructure" };
            if (group != "service")
                ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(Path.Combine(Root,
                    "diagnostic-symbols", group));
            foreach (var symbol in symbols)
                Write("diagnostic-symbols/" + (group == "service" ? "" : group + "/") +
                    symbol + ".pdb", Encoding.ASCII.GetBytes(symbol));
        }

        private static string Deps(string root)
        {
            var libraries = new Dictionary<string, object>(StringComparer.Ordinal);
            var targets = new Dictionary<string, object>(StringComparer.Ordinal);
            var members = root switch
            {
                "Vantrel.Security.Service" => new[] { root, "Vantrel.Security.Core",
                    "Vantrel.Security.Infrastructure", "Microsoft.Extensions.Hosting.WindowsServices",
                    "Microsoft.Extensions.Hosting", "System.ServiceProcess.ServiceController" },
                "Vantrel.Security.Desktop" => new[] { root, "Vantrel.Security.Core",
                    "Vantrel.Security.Infrastructure", "Microsoft.Extensions.Hosting" },
                _ => new[] { root, "Vantrel.Security.Service", "Vantrel.Security.Core",
                    "Vantrel.Security.Infrastructure" }
            };
            foreach (var member in members)
            {
                var isPackage = !member.StartsWith("Vantrel.", StringComparison.Ordinal);
                var version = isPackage ? "10.0.12" : "0.1.0";
                var direct = member == root ? root switch
                {
                    "Vantrel.Security.Service" => new Dictionary<string, string> {
                        ["Microsoft.Extensions.Hosting.WindowsServices"] = "10.0.12",
                        ["System.ServiceProcess.ServiceController"] = "10.0.12",
                        ["Vantrel.Security.Core"] = "0.1.0",
                        ["Vantrel.Security.Infrastructure"] = "0.1.0" },
                    "Vantrel.Security.Desktop" => new Dictionary<string, string> {
                        ["Microsoft.Extensions.Hosting"] = "10.0.12",
                        ["Vantrel.Security.Core"] = "0.1.0",
                        ["Vantrel.Security.Infrastructure"] = "0.1.0" },
                    _ => new Dictionary<string, string> { ["Vantrel.Security.Service"] = "0.1.0" }
                } : member == "Microsoft.Extensions.Hosting.WindowsServices"
                    ? new Dictionary<string, string> { ["Microsoft.Extensions.Hosting"] = "10.0.12" }
                    : member == "Vantrel.Security.Service" && root != member
                        ? new Dictionary<string, string> { ["Vantrel.Security.Core"] = "0.1.0",
                            ["Vantrel.Security.Infrastructure"] = "0.1.0" }
                        : new Dictionary<string, string>();
                targets[member + "/" + version] = new { dependencies = direct,
                    runtime = new Dictionary<string, object> { [member + ".dll"] = new { } } };
                libraries[member + "/" + version] = new { type = isPackage ? "package" : "project" };
            }
            return JsonSerializer.Serialize(new { runtimeTarget = new {
                name = ".NETCoreApp,Version=v10.0/win-x64", signature = "" },
                compilationOptions = new { }, targets = new Dictionary<string, object> {
                    [".NETCoreApp,Version=v10.0/win-x64"] = targets }, libraries });
        }

        private TrustedManifestV2File[] Inventory(string group) =>
            Directory.GetFiles(Path.Combine(Root, group)).Select(path =>
                new TrustedManifestV2File(Path.GetFileName(path), Hash(File.ReadAllBytes(path))))
                .OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();

        private static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));

        public void Dispose()
        {
            _manifestKey.Dispose(); _metadataKey.Dispose();
            if (Directory.Exists(_temporary) &&
                Path.GetFileName(_temporary).StartsWith("vantrel-product-record-", StringComparison.Ordinal))
                Directory.Delete(_temporary, recursive: true);
        }
    }

    private sealed class SyntheticServiceSource : IServiceReleaseV2SourceBinding
    {
        public void Verify(string outputRoot, BetaReleaseDescriptor descriptor,
            ServiceReleaseV2BuildProvenance provenance,
            IReadOnlyList<TrustedManifestV2File> serviceFiles,
            IReadOnlyList<TrustedManifestV2File> diagnosticSymbols,
            ServiceReleaseV2FinalBinding finalBinding) => finalBinding.Recheck();
    }

    private sealed class SyntheticProductSource(
        IReadOnlyList<TrustedManifestV2File> expectedDesktop,
        IReadOnlyList<TrustedManifestV2File> expectedTool) : IProductReleaseV2SourceGate
    {
        public ProductReleaseV2SourceEvidence Verify(string outputRoot, BetaReleaseRecordV2 serviceRecord,
            IReadOnlyList<TrustedManifestV2File> desktopFiles,
            IReadOnlyList<TrustedManifestV2File> toolFiles,
            IReadOnlyList<TrustedManifestV2File> diagnostics,
            ServiceReleaseV2FinalBinding binding)
        {
            binding.Recheck();
            if (!desktopFiles.SequenceEqual(expectedDesktop) || !toolFiles.SequenceEqual(expectedTool))
                throw new IOException("Synthetic product source inventory changed.");
            var residue = new[] { "Vantrel.Security.Service.deps.json",
                "Vantrel.Security.Service.exe", "Vantrel.Security.Service.runtimeconfig.json",
                "packages.lock.json" }.Select(name =>
                new TrustedManifestV2File("publish/offline-update-tool/" + name, HashText)).ToArray();
            return new(HashText, HashText, diagnostics, residue);
        }
    }

    private sealed class SyntheticSignatureGate(byte[] manifestRoot, byte[] metadataRoot)
        : IServiceReleaseV2SignatureGate
    {
        public bool Verify(ReadOnlySpan<byte> manifestBytes, ReadOnlySpan<byte> metadataBytes) =>
            TrustedManifestV2Codec.VerifyBoundMetadata(manifestBytes, metadataBytes,
                manifestRoot, metadataRoot);
    }
}
