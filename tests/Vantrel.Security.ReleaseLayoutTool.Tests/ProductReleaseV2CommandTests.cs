using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
public sealed class ProductReleaseV2CommandTests
{
    [TestMethod]
    public void Product_commands_reject_missing_duplicate_unknown_and_relative_arguments_before_build()
    {
        var runner = new RejectingRunner();
        foreach (var arguments in new[]
        {
            new[] { "project-v2-product", "--source-root", "relative", "--source-commit", "x",
                "--service-release-root", @"C:\service", "--output-root", @"C:\out" },
            new[] { "project-v2-product", "--source-root", @"C:\source", "--source-commit", "x",
                "--service-release-root", @"C:\service" },
            new[] { "record-v2-product", "--source-root", @"C:\source", "--source-commit", "x",
                "--output-root", @"C:\out", "--output-root", @"C:\other" },
            new[] { "record-v2-product", "--source-root", @"C:\source", "--source-commit", "x",
                "--output-root", @"C:\out", "--extra", "x" }
        })
        {
            var output = new StringWriter();
            var errors = new StringWriter();
            Assert.AreEqual(1, ReleaseLayoutToolCommand.RunForV2Tests(arguments,
                new RejectingSigner(), output, errors, runner,
                (_, _, _) => throw new AssertFailedException("No sidecar operation is permitted.")));
            Assert.AreEqual(string.Empty, output.ToString());
            StringAssert.Contains(errors.ToString(), "Beta release layout operation failed.");
        }
        Assert.AreEqual(0, runner.Calls);
    }

    private sealed class RejectingRunner : IReleaseV2CommandRunner
    {
        internal int Calls { get; private set; }
        public ReleaseV2CommandResult Run(string executable, IReadOnlyList<string> arguments,
            string workingDirectory, bool captureStandardOutput)
        { Calls++; throw new AssertFailedException("Malformed CLI reached build runner."); }
        public ReleaseV2CommandResult RunWithInput(string executable,
            IReadOnlyList<string> arguments, string workingDirectory, Stream standardInput)
        { Calls++; throw new AssertFailedException("Malformed CLI reached build runner."); }
    }

    private sealed class RejectingSigner : IAzureArtifactSigningProcessRunner
    {
        public int Run(string executablePath, IReadOnlyList<string> arguments) =>
            throw new AssertFailedException("Product commands must not invoke a signer.");
    }
}
