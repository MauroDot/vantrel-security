using System.Security.Cryptography;
using System.Runtime.Versioning;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>Explicit, opt-in v2 Service PE signer. It cannot create a manifest or record.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ServiceReleaseV2PeSigningGate
{
    private const string Invalid = "V2 Service PE signing failed.";
    private readonly IAzureArtifactSigningProcessRunner _runner;
    private readonly IServiceReleaseV2AuthenticodeGate _authenticode;

    internal ServiceReleaseV2PeSigningGate(IAzureArtifactSigningProcessRunner runner,
        IServiceReleaseV2AuthenticodeGate? authenticode = null)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _authenticode = authenticode ?? new ProductionServiceReleaseV2AuthenticodeGate();
    }

    internal IReadOnlyList<AuthenticodeReleaseEvidence> SignPreparedService(string outputRoot,
        string sourceRoot, string expectedFullCommit, AzureArtifactSigningToolPaths tools,
        IReleaseV2CommandRunner buildRunner)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(tools);
            ArgumentNullException.ThrowIfNull(buildRunner);
            var provenance = ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(
                sourceRoot, expectedFullCommit, buildRunner);
            if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(outputRoot) ||
                Path.GetFullPath(outputRoot) != outputRoot ||
                provenance.SdkVersion != BetaReleaseRecordV2Codec.SdkVersion ||
                provenance.TargetFramework != BetaReleaseRecordV2Codec.TargetFramework ||
                provenance.RuntimeIdentifier != TrustedManifestV2Codec.Architecture ||
                provenance.Deployment != TrustedManifestV2Codec.Deployment)
                throw new IOException(Invalid);

            var root = outputRoot;
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(root);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedDirectory(
                Path.GetDirectoryName(root) ?? throw new IOException(Invalid));
            RequirePreparedRoot(root);
            var descriptorBytes = ServiceReleaseV2FileSystemSecurity.ReadProtectedFileBytes(
                Path.Combine(root, BetaReleaseDescriptorCodec.FileName), 4096);
            if (!BetaReleaseDescriptorCodec.TryParse(descriptorBytes, out var descriptor) ||
                descriptor is null || descriptor.SourceCommit != provenance.SourceCommit ||
                descriptor.SdkVersion != provenance.SdkVersion || descriptor.Configuration != "Release" ||
                descriptor.Runtime != provenance.RuntimeIdentifier ||
                descriptor.ReleaseNotesSha256 != ServiceReleaseV2FileSystemSecurity.HashProtectedFile(
                    Path.Combine(root, BetaReleaseLayoutValidator.ReleaseNotesFileName), 1024 * 1024))
                throw new IOException(Invalid);
            var serviceRoot = Path.Combine(root, ServiceReleaseV2ProductionProjector.ServiceDirectoryName);
            var diagnosticsRoot = Path.Combine(root,
                ServiceReleaseV2ProductionProjector.DiagnosticDirectoryName);
            var initial = ServicePublishFileSnapshot.Capture(serviceRoot).Files.ToArray();
            if (initial.Any(file => file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)))
                throw new IOException(Invalid);
            _ = ServicePublishDependencyValidator.Validate(serviceRoot, initial);
            _ = TrustedManifestV2Codec.CreateCanonicalPayload(descriptor.ReleaseVersion,
                descriptor.ReleaseSequence, initial);
            ServiceReleaseV2FileSystemSecurity.RequireProtectedTree(serviceRoot, initial);
            var diagnostics = new[] { "Vantrel.Security.Core.pdb", "Vantrel.Security.Infrastructure.pdb",
                "Vantrel.Security.Service.pdb" }.Select(name => new TrustedManifestV2File(name,
                    ServiceReleaseV2FileSystemSecurity.HashProtectedFile(
                        Path.Combine(diagnosticsRoot, name), 1024L * 1024 * 1024))).ToArray();
            _ = ServiceReleaseV2ProductionProjector.ValidateDiagnosticSymbols(diagnosticsRoot, diagnostics);
            // A descriptor and a self-consistent .deps.json cannot prove that a prepared
            // directory came from its asserted commit. Reproduce the unsigned SDK publish
            // from a separately clean checkout before invoking even the first signer.
            var scratch = Path.Combine(Path.GetDirectoryName(root)!, "." +
                Path.GetFileName(root) + ".sign-input-" + Guid.NewGuid().ToString("N"));
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(scratch);
            var project = Path.Combine(sourceRoot, "src", "Vantrel.Security.Service",
                "Vantrel.Security.Service.csproj");
            var published = buildRunner.Run("dotnet", ["publish", project,
                "--configuration", "Release", "--runtime", "win-x64", "--self-contained", "false",
                "--no-restore", "--output", scratch,
                "-p:VantrelReleaseVersion=" + descriptor.ReleaseVersion,
                "-p:VantrelSourceCommit=" + descriptor.SourceCommit], sourceRoot, false);
            if (published.ExitCode != 0 || published.StandardOutput.Length != 0)
                throw new IOException(Invalid);
            var reproduced = ServicePublishDependencyValidator.ValidateSdkPublish(scratch,
                provenance.SourceLockSha256).DeployableFiles;
            if (!initial.SequenceEqual(reproduced.Where(file =>
                    !file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase))) ||
                !diagnostics.SequenceEqual(reproduced.Where(file =>
                    file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase))))
                throw new IOException(Invalid);
            ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(sourceRoot,
                expectedFullCommit, provenance.SourceLockSha256, buildRunner);
            var current = initial.ToDictionary(file => file.Path, file => file.Sha256, StringComparer.Ordinal);
            using (var before = OpenBinding(root, descriptorBytes, descriptor.ReleaseNotesSha256,
                       current, diagnostics)) before.Recheck();

            var metadata = AzureArtifactSigningMetadataCodec.ReadValidatedLocalFile(tools.MetadataPath);
            if (!metadata.InteractiveBrowserOnly) throw new IOException(Invalid);
            var signTool = RequireToolFile(tools.SignToolPath, "signtool.exe");
            var dlib = RequireToolFile(tools.DlibPath, "Azure.CodeSigning.Dlib.dll");
            var metadataPath = RequireToolFile(tools.MetadataPath,
                AzureArtifactSigningMetadataCodec.LocalMetadataFileName, enforceName: false);

            var signed = new List<AuthenticodeReleaseEvidence>(4);
            foreach (var target in ServiceReleaseV2PeContract.VantrelOwnedPeArtifacts)
            {
                RequirePreparedRoot(root);
                var before = ServicePublishFileSnapshot.Capture(serviceRoot).Files;
                RequireMatching(before, current);
                var path = Path.Combine(root, target.RelativePath.Replace('/', '\\'));
                var args = Array.AsReadOnly(new[] { "sign", "/v", "/fd", "SHA256", "/tr",
                    AzureArtifactSigningOrchestrator.TimestampEndpoint, "/td", "SHA256",
                    "/dlib", dlib, "/dmdf", metadataPath, path });
                int result;
                try { result = _runner.Run(signTool, args); }
                catch { throw new IOException(Invalid); }
                if (result != 0) throw new IOException(Invalid);
                var after = ServicePublishFileSnapshot.Capture(serviceRoot).Files;
                if (after.Count != current.Count ||
                    after.Any(file => file.Path != target.RelativePath["service/".Length..] &&
                        (!current.TryGetValue(file.Path, out var hash) || hash != file.Sha256)))
                    throw new IOException(Invalid);
                _ = ServicePublishDependencyValidator.Validate(serviceRoot, after);
                var relativeServicePath = target.RelativePath["service/".Length..];
                var signedFile = after.SingleOrDefault(file => file.Path == relativeServicePath);
                if (signedFile is null) throw new IOException(Invalid);
                current[relativeServicePath] = signedFile.Sha256;
            }

            RequirePreparedRoot(root);
            using var binding = OpenBinding(root, descriptorBytes,
                descriptor.ReleaseNotesSha256, current, diagnostics);
            foreach (var target in ServiceReleaseV2PeContract.VantrelOwnedPeArtifacts)
            {
                var path = Path.Combine(root, target.RelativePath.Replace('/', '\\'));
                var hash = binding.Hash(target.RelativePath);
                var evidence = _authenticode.Verify(target.RelativePath, path,
                    binding.GetHandle(target.RelativePath));
                if (evidence.RelativePath != target.RelativePath ||
                    evidence.Category != AuthenticodeVerificationCategory.Valid ||
                    evidence.SignerPolicyId != BetaReleaseRecordV2Codec.SigningPolicyId ||
                    evidence.PrimarySignatureCount != PrimarySignatureCountPolicyCategory.ExactlyOne ||
                    evidence.Timestamp != TimestampPolicyCategory.ValidRfc3161 ||
                    binding.Hash(target.RelativePath) != hash) throw new IOException(Invalid);
                signed.Add(evidence);
            }
            binding.Recheck();
            RequirePreparedRoot(root);
            ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(sourceRoot,
                expectedFullCommit, provenance.SourceLockSha256, buildRunner);
            return signed.AsReadOnly();
        }
        catch (TrackedSourceProvenanceException) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or InvalidDataException or CryptographicException or
            NotSupportedException or PlatformNotSupportedException or InvalidOperationException)
        { throw new IOException(Invalid); }
    }

    private static ServiceReleaseV2FinalBinding OpenBinding(string root, byte[] descriptorBytes,
        string notesHash, IReadOnlyDictionary<string, string> service,
        IReadOnlyList<TrustedManifestV2File> diagnostics)
    {
        var expected = new List<ServiceReleaseV2BoundFile>
        {
            new(BetaReleaseDescriptorCodec.FileName,
                Convert.ToHexString(SHA256.HashData(descriptorBytes))),
            new(BetaReleaseLayoutValidator.ReleaseNotesFileName, notesHash)
        };
        expected.AddRange(service.Select(file => new ServiceReleaseV2BoundFile("service/" +
            file.Key, file.Value)));
        expected.AddRange(diagnostics.Select(file => new ServiceReleaseV2BoundFile(
            "diagnostic-symbols/" + file.Path, file.Sha256)));
        expected.Sort((a, b) => StringComparer.Ordinal.Compare(a.RelativePath, b.RelativePath));
        return ServiceReleaseV2FinalBinding.Open(root, expected);
    }

    private static void RequireMatching(IReadOnlyList<TrustedManifestV2File> files,
        IReadOnlyDictionary<string, string> expected)
    {
        if (files.Count != expected.Count || files.Any(file =>
                !expected.TryGetValue(file.Path, out var hash) || hash != file.Sha256))
            throw new IOException(Invalid);
    }

    private static string RequireToolFile(string path, string fileName, bool enforceName = true)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            Path.GetFullPath(path) != path || path.Length < 4 || path[1] != ':' || path[2] != '\\' ||
            (enforceName && !Path.GetFileName(path).Equals(fileName, StringComparison.OrdinalIgnoreCase)))
            throw new IOException(Invalid);
        AzureArtifactSigningMetadataCodec.ValidateSafeAncestors(path, Invalid);
        if (!File.Exists(path) || Directory.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException(Invalid);
        return path;
    }

    private static void RequirePreparedRoot(string root)
    {
        if (Path.Exists(Path.Combine(root, BetaReleaseRecordV2Codec.FileName)))
            throw new IOException(Invalid);
        var actual = Directory.EnumerateFileSystemEntries(root)
            .Select(Path.GetFileName).OrderBy(name => name, StringComparer.Ordinal).ToArray();
        string[] expected = [BetaReleaseDescriptorCodec.FileName,
            ServiceReleaseV2ProductionProjector.DiagnosticDirectoryName,
            BetaReleaseLayoutValidator.ReleaseNotesFileName,
            ServiceReleaseV2ProductionProjector.ServiceDirectoryName];
        if (!actual.SequenceEqual(expected, StringComparer.Ordinal)) throw new IOException(Invalid);
    }
}
