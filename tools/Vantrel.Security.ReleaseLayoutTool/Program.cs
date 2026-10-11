using System.Globalization;
using Vantrel.Security.ReleaseLayoutTool;

try
{
    ReleaseLayoutToolCommand.Execute(args, new SignToolProcessRunner(), Console.Out);
}
catch (TrackedSourceProvenanceException error)
{
    Console.Error.WriteLine(error.Message);
    Environment.ExitCode = 1;
}
catch
{
    Console.Error.WriteLine("Beta release layout operation failed.");
    Environment.ExitCode = 1;
}

public static class ReleaseLayoutToolCommand
{
    public static void Execute(string[] args, IAzureArtifactSigningProcessRunner signingRunner, TextWriter output,
        IReleaseAuthenticodeVerification? authenticode = null) =>
        ExecuteCore(args, signingRunner, output, authenticode, null);

    internal static void ExecuteForV2Tests(string[] args, IAzureArtifactSigningProcessRunner signingRunner,
        TextWriter output, IReleaseV2CommandRunner v2BuildRunner) =>
        ExecuteCore(args, signingRunner, output, null, v2BuildRunner);

    private static void ExecuteCore(string[] args, IAzureArtifactSigningProcessRunner signingRunner,
        TextWriter output, IReleaseAuthenticodeVerification? authenticode,
        IReleaseV2CommandRunner? v2BuildRunner)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(signingRunner);
        ArgumentNullException.ThrowIfNull(output);
        if (args.Length == 0) throw new ArgumentException();
        var command = args[0];
        var values = Parse(args.Skip(1).ToArray());
        if (command == "write-descriptor")
        {
            RequireExactKeys(values, "--output", "--source-commit", "--release-version", "--release-sequence", "--published-at-utc", "--configuration", "--runtime", "--sdk-version", "--release-notes-sha256");
            var descriptor = new BetaReleaseDescriptor(
                Required(values, "--source-commit"),
                Required(values, "--release-version"),
                ulong.Parse(Required(values, "--release-sequence"), CultureInfo.InvariantCulture),
                DateTimeOffset.ParseExact(Required(values, "--published-at-utc"), "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal),
                Required(values, "--configuration"),
                Required(values, "--runtime"),
                Required(values, "--sdk-version"),
                Required(values, "--release-notes-sha256"));
            var outputPath = Required(values, "--output");
            if (File.Exists(outputPath) || Directory.Exists(outputPath)) throw new IOException();
            File.WriteAllBytes(outputPath, BetaReleaseDescriptorCodec.CreateCanonical(descriptor));
        }
        else if (command == "project-service-payload")
        {
            RequireExactKeys(values, "--source", "--destination");
            new ServicePayloadProjector().Project(Required(values, "--source"), Required(values, "--destination"));
        }
        else if (command == "record")
        {
            RequireExactKeys(values, "--output-root", "--signing-profile");
            new BetaReleaseLayoutValidator().ValidateAndWriteRecord(Required(values, "--output-root"), Required(values, "--signing-profile"));
        }
        else if (command == "sign-authenticode-layout")
        {
            RequireExactKeys(values, "--output-root", "--signtool", "--dlib", "--metadata");
            new AzureArtifactSigningOrchestrator(signingRunner, authenticode).SignPreparedLayout(
                ExplicitAbsolutePath(values, "--output-root"), new AzureArtifactSigningToolPaths(
                    ExplicitAbsolutePath(values, "--signtool"), ExplicitAbsolutePath(values, "--dlib"), ExplicitAbsolutePath(values, "--metadata")));
            output.WriteLine("PE signing and Authenticode validation completed. Externally sign the fixed Service manifest and release metadata before Record.");
        }
        else if (command == "prepare-v2-service")
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            RequireExactKeys(values, "--source-root", "--source-commit", "--output-root",
                "--release-notes", "--release-version", "--release-sequence", "--published-at-utc");
            var sequenceText = Required(values, "--release-sequence");
            if (!ulong.TryParse(sequenceText, NumberStyles.None, CultureInfo.InvariantCulture,
                    out var sequence) || sequence == 0 ||
                sequence.ToString(CultureInfo.InvariantCulture) != sequenceText)
                throw new ArgumentException();
            var publishedText = Required(values, "--published-at-utc");
            if (!DateTimeOffset.TryParseExact(publishedText, "yyyy-MM-dd'T'HH:mm:ss'Z'",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var published) ||
                published.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture) !=
                    publishedText) throw new ArgumentException();
            _ = ServiceReleaseV2Preparation.Prepare(
                ExplicitAbsolutePath(values, "--source-root"), Required(values, "--source-commit"),
                ExplicitAbsolutePath(values, "--output-root"),
                ExplicitAbsolutePath(values, "--release-notes"),
                Required(values, "--release-version"), sequence, published,
                v2BuildRunner ?? new SystemReleaseV2CommandRunner());
            output.WriteLine("V2 Service preparation completed. Sign only the four Vantrel-owned Service PEs, then externally sign the v2 trusted manifest and bound release metadata before record-v2-service.");
        }
        else if (command == "sign-v2-service-pes")
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            RequireExactKeys(values, "--source-root", "--source-commit", "--output-root",
                "--signtool", "--dlib", "--metadata");
            _ = new ServiceReleaseV2PeSigningGate(signingRunner).SignPreparedService(
                ExplicitAbsolutePath(values, "--output-root"),
                ExplicitAbsolutePath(values, "--source-root"), Required(values, "--source-commit"),
                new AzureArtifactSigningToolPaths(ExplicitAbsolutePath(values, "--signtool"),
                    ExplicitAbsolutePath(values, "--dlib"),
                    ExplicitAbsolutePath(values, "--metadata")),
                v2BuildRunner ?? new SystemReleaseV2CommandRunner());
            output.WriteLine("Four Service PE signatures validated. Externally sign the final v2 manifest and release metadata before record-v2-service.");
        }
        else if (command == "record-v2-service")
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            RequireExactKeys(values, "--source-root", "--source-commit", "--output-root");
            var sourceRoot = ExplicitAbsolutePath(values, "--source-root");
            var sourceCommit = Required(values, "--source-commit");
            var runner = v2BuildRunner ?? new SystemReleaseV2CommandRunner();
            var provenance = ServiceReleaseV2BuildProvenancePreflight.VerifyAndRestore(
                sourceRoot, sourceCommit, runner);
            _ = new ServiceReleaseV2RecordGate(
                new ProductionServiceReleaseV2SourceBinding(sourceRoot, sourceCommit, runner))
                .ValidateAndWriteRecord(
                ExplicitAbsolutePath(values, "--output-root"), provenance);
            output.WriteLine("V2 Service release evidence recorded. Installer and offline-update consumers remain v1-only.");
        }
        else if (command == "inspect-authenticode")
        {
            RequireExactKeys(values, "--file");
            output.Write(SinglePeAuthenticodeInspectionOutput.Create(new SinglePeAuthenticodeInspector().Inspect(Required(values, "--file"))));
        }
        else if (command == "inspect-msi-authenticode")
        {
            RequireExactKeys(values, "--file");
            output.Write(MsiAuthenticodeInspectionOutput.Create(new SingleMsiAuthenticodeInspector().Inspect(Required(values, "--file"))));
        }
        else throw new ArgumentException();
    }

    private static Dictionary<string, string> Parse(string[] args)
    {
        if (args.Length % 2 != 0) throw new ArgumentException();
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
            if (!args[index].StartsWith("--", StringComparison.Ordinal) || string.IsNullOrEmpty(args[index + 1]) || !result.TryAdd(args[index], args[index + 1])) throw new ArgumentException();
        return result;
    }

    private static string Required(IReadOnlyDictionary<string, string> values, string name) =>
        values.TryGetValue(name, out var value) ? value : throw new ArgumentException();

    private static string ExplicitAbsolutePath(IReadOnlyDictionary<string, string> values, string name)
    {
        var value = Required(values, name);
        if (!Path.IsPathFullyQualified(value)) throw new ArgumentException();
        var full = Path.GetFullPath(value);
        if (!string.Equals(value, full, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException();
        return full;
    }

    private static void RequireExactKeys(IReadOnlyDictionary<string, string> values, params string[] expected)
    {
        if (values.Count != expected.Length || expected.Any(key => !values.ContainsKey(key))) throw new ArgumentException();
    }
}
