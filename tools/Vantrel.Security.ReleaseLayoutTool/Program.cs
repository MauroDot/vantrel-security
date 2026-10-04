using System.Globalization;
using Vantrel.Security.ReleaseLayoutTool;

try
{
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
        var output = Required(values, "--output");
        if (File.Exists(output) || Directory.Exists(output)) throw new IOException();
        File.WriteAllBytes(output, BetaReleaseDescriptorCodec.CreateCanonical(descriptor));
    }
    else if (command == "project-service-payload")
    {
        RequireExactKeys(values, "--source", "--destination");
        new ServicePayloadProjector().Project(Required(values, "--source"), Required(values, "--destination"));
    }
    else if (command == "record")
    {
        RequireExactKeys(values, "--output-root");
        new BetaReleaseLayoutValidator().ValidateAndWriteRecord(Required(values, "--output-root"));
    }
    else throw new ArgumentException();
}
catch
{
    Console.Error.WriteLine("Beta release layout operation failed.");
    Environment.ExitCode = 1;
}

static Dictionary<string, string> Parse(string[] args)
{
    if (args.Length % 2 != 0) throw new ArgumentException();
    var result = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var index = 0; index < args.Length; index += 2)
        if (!args[index].StartsWith("--", StringComparison.Ordinal) || string.IsNullOrEmpty(args[index + 1]) || !result.TryAdd(args[index], args[index + 1])) throw new ArgumentException();
    return result;
}

static string Required(IReadOnlyDictionary<string, string> values, string name) =>
    values.TryGetValue(name, out var value) ? value : throw new ArgumentException();

static void RequireExactKeys(IReadOnlyDictionary<string, string> values, params string[] expected)
{
    if (values.Count != expected.Length || expected.Any(key => !values.ContainsKey(key))) throw new ArgumentException();
}