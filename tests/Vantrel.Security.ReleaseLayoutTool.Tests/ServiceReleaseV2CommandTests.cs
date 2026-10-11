using System.Runtime.Versioning;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[SupportedOSPlatform("windows")]
public sealed class ServiceReleaseV2CommandTests
{
    [TestMethod]
    public void Explicit_v2_verbs_reject_missing_duplicate_unknown_and_relative_arguments_before_processes()
    {
        string[] prepare = ["prepare-v2-service", "--source-root", "relative",
            "--source-commit", new string('a', 40), "--output-root", "C:\\out",
            "--release-notes", "C:\\notes.md", "--release-version", "0.1.0-beta.1",
            "--release-sequence", "1", "--published-at-utc", "2026-10-10T12:00:00Z"];
        string[] sign = ["sign-v2-service-pes", "--source-root", "relative",
            "--source-commit", new string('a', 40), "--output-root", "C:\\out",
            "--signtool", "C:\\signtool.exe", "--dlib", "C:\\dlib.dll",
            "--metadata", "C:\\metadata.json"];
        string[] record = ["record-v2-service", "--source-root", "relative",
            "--source-commit", new string('a', 40), "--output-root", "C:\\out"];

        foreach (var validShapeWithRelativeSource in new[] { prepare, sign, record })
        {
            Reject(validShapeWithRelativeSource);
            Reject(validShapeWithRelativeSource[..^2]);
            Reject([.. validShapeWithRelativeSource, "--unexpected", "value"]);
            Reject([.. validShapeWithRelativeSource, "--source-root", "C:\\other"]);
        }
    }

    [TestMethod]
    public void Noncanonical_release_sequence_and_publication_time_are_rejected_before_prepare()
    {
        string[] args = ["prepare-v2-service", "--source-root", "C:\\source",
            "--source-commit", new string('a', 40), "--output-root", "C:\\out",
            "--release-notes", "C:\\notes.md", "--release-version", "0.1.0-beta.1",
            "--release-sequence", "01", "--published-at-utc", "2026-10-10T12:00:00Z"];
        Reject(args);
        args[^3] = "1";
        args[^1] = "2026-99-10T12:00:00Z";
        Reject(args);
    }

    [TestMethod]
    public void V2_sidecar_verbs_require_exactly_four_options_and_absolute_paths_before_processes()
    {
        foreach (var verb in new[] { "sign-v2-service-manifest", "sign-v2-release-metadata" })
        {
            string[] validShape = [verb, "--source-root", "C:\\source",
                "--source-commit", new string('a', 40), "--output-root", "C:\\release",
                "--private-key", "C:\\external\\signing.pk8"];

            for (var optionIndex = 1; optionIndex < validShape.Length; optionIndex += 2)
                Reject(validShape.Where((_, index) => index != optionIndex &&
                    index != optionIndex + 1).ToArray());
            Reject(validShape[..^1]);
            Reject([.. validShape, "--unexpected", "value"]);
            Reject([.. validShape, "--private-key", "C:\\other.pk8"]);

            foreach (var pathIndex in new[] { 2, 6, 8 })
            {
                var relativePath = validShape.ToArray();
                relativePath[pathIndex] = "relative";
                Reject(relativePath);
            }
        }
    }

    [TestMethod]
    public void Existing_v1_record_command_retains_strict_argument_parsing()
    {
        Reject(["record", "--output-root", "C:\\release"]);
        Reject(["record", "--output-root", "C:\\release", "--signing-profile"]);
        Reject(["record", "--output-root", "C:\\release", "--signing-profile",
            "vantrel-production", "--unexpected", "value"]);
        Reject(["record", "--output-root", "C:\\release", "--signing-profile",
            "vantrel-production", "--output-root", "C:\\other"]);
    }

    private static void Reject(string[] args)
    {
        var signer = new ForbiddenSigner();
        var builder = new ForbiddenBuilder();
        using var output = new StringWriter();
        Assert.ThrowsException<ArgumentException>(() =>
            ReleaseLayoutToolCommand.ExecuteForV2Tests(args, signer, output, builder));
        Assert.AreEqual(0, signer.Calls);
        Assert.AreEqual(0, builder.Calls);
        Assert.AreEqual(string.Empty, output.ToString());
    }

    private sealed class ForbiddenSigner : IAzureArtifactSigningProcessRunner
    {
        internal int Calls { get; private set; }
        public int Run(string executablePath, IReadOnlyList<string> arguments)
        {
            Calls++;
            throw new AssertFailedException("No signing process is permitted in parsing tests.");
        }
    }

    private sealed class ForbiddenBuilder : IReleaseV2CommandRunner
    {
        internal int Calls { get; private set; }
        public ReleaseV2CommandResult Run(string executable, IReadOnlyList<string> arguments,
            string workingDirectory, bool captureStandardOutput)
        {
            Calls++;
            throw new AssertFailedException("No build process is permitted in parsing tests.");
        }

        public ReleaseV2CommandResult RunWithInput(string executable,
            IReadOnlyList<string> arguments, string workingDirectory, Stream standardInput)
        {
            Calls++;
            throw new AssertFailedException("No build process is permitted in parsing tests.");
        }
    }
}
