using System.Globalization;
using Vantrel.Security.ReleaseLayoutTool;

try
{
    ReleaseLayoutToolCommand.Execute(args, new SignToolProcessRunner(), Console.Out);
}
catch
{
    Console.Error.WriteLine("Beta release layout operation failed.");
    Environment.ExitCode = 1;
}

public static class ReleaseLayoutToolCommand
{
    public static void Execute(string[] args, IAzureArtifactSigningProcessRunner signingRunner, TextWriter output,
        IReleaseAuthenticodeVerification? authenticode = null)
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
