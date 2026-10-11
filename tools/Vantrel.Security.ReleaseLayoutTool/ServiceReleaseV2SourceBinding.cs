using System.Runtime.Versioning;
using System.Security.Cryptography;
using Vantrel.Security.Core;

namespace Vantrel.Security.ReleaseLayoutTool;

internal interface IServiceReleaseV2SourceBinding
{
    void Verify(string outputRoot, BetaReleaseDescriptor descriptor,
        ServiceReleaseV2BuildProvenance provenance,
        IReadOnlyList<TrustedManifestV2File> serviceFiles,
        IReadOnlyList<TrustedManifestV2File> diagnosticSymbols,
        ServiceReleaseV2FinalBinding finalBinding);
}

/// <summary>
/// Reproduces the unsigned Service publish at Record time. An earlier signing-command
/// success cannot be inferred from a clean source lock or from a self-consistent .deps.json.
/// Every non-PE byte must be identical, and every owned PE may differ only by its embedded
/// Authenticode certificate and the two PE header fields changed by signing.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ProductionServiceReleaseV2SourceBinding : IServiceReleaseV2SourceBinding
{
    private const string Invalid = "V2 Service source binding failed.";
    private const int MaximumPeBytes = 1024 * 1024 * 1024;
    private readonly string _sourceRoot;
    private readonly string _expectedCommit;
    private readonly IReleaseV2CommandRunner _runner;

    internal ProductionServiceReleaseV2SourceBinding(string sourceRoot, string expectedCommit,
        IReleaseV2CommandRunner runner)
    {
        _sourceRoot = sourceRoot;
        _expectedCommit = expectedCommit;
        _runner = runner;
    }

    public void Verify(string outputRoot, BetaReleaseDescriptor descriptor,
        ServiceReleaseV2BuildProvenance provenance,
        IReadOnlyList<TrustedManifestV2File> serviceFiles,
        IReadOnlyList<TrustedManifestV2File> diagnosticSymbols,
        ServiceReleaseV2FinalBinding finalBinding)
    {
        try
        {
            if (descriptor.SourceCommit != _expectedCommit ||
                provenance.SourceCommit != _expectedCommit ||
                !OperatingSystem.IsWindows()) throw new IOException(Invalid);
            ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(_sourceRoot,
                _expectedCommit, provenance.SourceLockSha256, _runner);
            var scratch = Path.Combine(Path.GetDirectoryName(outputRoot)!, "." +
                Path.GetFileName(outputRoot) + ".record-input-" + Guid.NewGuid().ToString("N"));
            ServiceReleaseV2FileSystemSecurity.CreateProtectedDirectory(scratch);
            var project = Path.Combine(_sourceRoot, "src", "Vantrel.Security.Service",
                "Vantrel.Security.Service.csproj");
            var published = _runner.Run("dotnet", ["publish", project, "--configuration", "Release",
                "--runtime", "win-x64", "--self-contained", "false", "--no-restore",
                "--output", scratch, "-p:VantrelReleaseVersion=" + descriptor.ReleaseVersion,
                "-p:VantrelSourceCommit=" + descriptor.SourceCommit], _sourceRoot, false);
            if (published.ExitCode != 0 || published.StandardOutput.Length != 0)
                throw new IOException(Invalid);

            var reproduced = ServicePublishDependencyValidator.ValidateSdkPublish(scratch,
                provenance.SourceLockSha256).DeployableFiles;
            var reproducedService = reproduced.Where(file =>
                !file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)).ToArray();
            var reproducedDiagnostics = reproduced.Where(file =>
                file.Path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (reproducedService.Length != serviceFiles.Count ||
                reproducedDiagnostics.Length != diagnosticSymbols.Count ||
                !reproducedService.Select(file => file.Path)
                    .SequenceEqual(serviceFiles.Select(file => file.Path)) ||
                !reproducedDiagnostics.SequenceEqual(diagnosticSymbols))
                throw new IOException(Invalid);

            var pePaths = ServiceReleaseV2PeContract.VantrelOwnedPeArtifacts
                .Select(file => file.RelativePath["service/".Length..])
                .ToHashSet(StringComparer.Ordinal);
            foreach (var (source, final) in reproducedService.Zip(serviceFiles))
            {
                if (pePaths.Contains(source.Path))
                {
                    var unsigned = ReadVerifiedPublishFile(scratch, source, MaximumPeBytes);
                    var signed = finalBinding.ReadBounded("service/" + source.Path,
                        MaximumPeBytes);
                    ServiceReleaseV2PeByteEquivalence.RequireAuthenticodeOnlyChange(
                        unsigned, signed);
                }
                else if (source.Sha256 != final.Sha256)
                    throw new IOException(Invalid);
            }
            // The signed layout must still be the exact retained layout validated before
            // this separate SDK publish. Both source and final state are checked again.
            finalBinding.Recheck();
            ServiceReleaseV2BuildProvenancePreflight.RequireSourceStillBound(_sourceRoot,
                _expectedCommit, provenance.SourceLockSha256, _runner);
        }
        catch (TrackedSourceProvenanceException) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or InvalidDataException or CryptographicException or
            NotSupportedException or OverflowException)
        { throw new IOException(Invalid); }
    }

    private static byte[] ReadVerifiedPublishFile(string scratch,
        TrustedManifestV2File expected, int maximum)
    {
        var path = Path.Combine(scratch, expected.Path.Replace('/', '\\'));
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length <= 0 || stream.Length > maximum) throw new IOException(Invalid);
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        if (Convert.ToHexString(SHA256.HashData(bytes)) != expected.Sha256)
            throw new IOException(Invalid);
        return bytes;
    }
}
