using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Vantrel.Security.ManifestTool;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
public sealed class AzureArtifactSigningOrchestrationTests
{
    [TestMethod]
    public void Canonical_metadata_accepts_only_the_fixed_non_secret_schema()
    {
        var metadata = new AzureArtifactSigningMetadata(AzureArtifactSigningMetadataCodec.Endpoint,
            AzureArtifactSigningMetadataCodec.AccountName, AzureArtifactSigningMetadataCodec.CertificateProfileName, "release-7");
        var canonical = AzureArtifactSigningMetadataCodec.CreateCanonical(metadata);

        Assert.IsTrue(AzureArtifactSigningMetadataCodec.TryParse(canonical, out var parsed));
        Assert.AreEqual(metadata, parsed);
        foreach (var malformed in new[]
        {
            "{}\n",
            "{\"Endpoint\":\"https://cus.codesigning.azure.net\",\"CodeSigningAccountName\":\"vantrel-signing\",\"CodeSigningAccountName\":\"other\",\"CertificateProfileName\":\"vantrelpublic\"}\n",
            "{\"Endpoint\":\"\",\"CodeSigningAccountName\":\"vantrel-signing\",\"CertificateProfileName\":\"vantrelpublic\"}\n",
            "{\"CodeSigningAccountName\":\"vantrel-signing\",\"Endpoint\":\"https://cus.codesigning.azure.net\",\"CertificateProfileName\":\"vantrelpublic\"}\n",
            "{\"Endpoint\":\"https://cus.codesigning.azure.net\",\"CodeSigningAccountName\":\"vantrel-signing\",\"CertificateProfileName\":\"vantrelpublic\",\"CorrelationId\":\"C:\\\\local\"}\n",
            "{\"Endpoint\":\"https://cus.codesigning.azure.net\",\"CodeSigningAccountName\":\"vantrel-signing\",\"CertificateProfileName\":\"vantrelpublic\"}\r\n"
        })
            Assert.IsFalse(AzureArtifactSigningMetadataCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(malformed), out _), malformed);

        foreach (var credentialField in new[] { "Token", "Secret", "Password", "Certificate", "PrivateKey", "Thumbprint" })
        {
            var credentialLike = $"{{\"Endpoint\":\"https://cus.codesigning.azure.net\",\"CodeSigningAccountName\":\"vantrel-signing\",\"CertificateProfileName\":\"vantrelpublic\",\"{credentialField}\":\"value\"}}\n";
            Assert.IsFalse(AzureArtifactSigningMetadataCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(credentialLike), out _), credentialField);
        }
    }

    [TestMethod]
    public void Orchestrator_invokes_only_the_canonical_thirteen_targets_in_order()
    {
        using var scope = new PreparedLayoutScope();
        var runner = new CapturingRunner();

        CreateOrchestrator(runner).SignPreparedLayout(scope.Root, scope.Tools);

        CollectionAssert.AreEqual(ReleaseSigningContract.VantrelOwnedPeArtifacts.Select(item => item.RelativePath).ToArray(),
            runner.Calls.Select(item => Path.GetRelativePath(scope.Root, item.Arguments[^1]).Replace('\\', '/')).ToArray());
        Assert.IsTrue(runner.Calls.All(item => item.Arguments.Take(11).SequenceEqual(["sign", "/v", "/fd", "SHA256", "/tr", AzureArtifactSigningOrchestrator.TimestampEndpoint, "/td", "SHA256", "/dlib", Path.GetFullPath(scope.Tools.DlibPath), "/dmdf"])));
        Assert.IsTrue(runner.Calls.All(item => item.Arguments[11] == Path.GetFullPath(scope.Tools.MetadataPath)));
        Assert.IsFalse(File.Exists(Path.Combine(scope.Root, BetaReleaseLayoutValidator.RecordFileName)));
    }

    [TestMethod]
    public void Missing_unsafe_or_post_preflight_modified_targets_fail_closed_without_record()
    {
        using (var missing = new PreparedLayoutScope())
        {
            File.Delete(Path.Combine(missing.Root, "desktop", "Vantrel.Security.Desktop.dll"));
            var runner = new CapturingRunner();
            Assert.ThrowsException<IOException>(() => CreateOrchestrator(runner).SignPreparedLayout(missing.Root, missing.Tools));
            Assert.AreEqual(0, runner.Calls.Count);
        }

        using (var changed = new PreparedLayoutScope())
        {
            var later = Path.Combine(changed.Root, "service", "Vantrel.Security.Service.dll");
            var runner = new CapturingRunner(call => { if (call == 1) File.AppendAllText(later, "changed"); return 0; });
            Assert.ThrowsException<IOException>(() => CreateOrchestrator(runner).SignPreparedLayout(changed.Root, changed.Tools));
            Assert.AreEqual(1, runner.Calls.Count);
            Assert.IsFalse(File.Exists(Path.Combine(changed.Root, BetaReleaseLayoutValidator.RecordFileName)));
        }
    }

    [TestMethod]
    public void Signer_failure_stops_the_sequence_and_never_emits_tool_output()
    {
        using var scope = new PreparedLayoutScope();
        var runner = new CapturingRunner(call => call == 3 ? 1 : 0);

        Assert.ThrowsException<IOException>(() => CreateOrchestrator(runner).SignPreparedLayout(scope.Root, scope.Tools));

        Assert.AreEqual(3, runner.Calls.Count);
        Assert.IsFalse(File.Exists(Path.Combine(scope.Root, BetaReleaseLayoutValidator.RecordFileName)));
    }

    [TestMethod]
    public void Extra_files_are_not_signing_targets_and_reparse_targets_fail_closed_when_permitted()
    {
        using (var scope = new PreparedLayoutScope())
        {
            File.WriteAllText(Path.Combine(scope.Root, "desktop", "unapproved.exe"), "not-a-target");
            var runner = new CapturingRunner();
            CreateOrchestrator(runner).SignPreparedLayout(scope.Root, scope.Tools);
            Assert.AreEqual(ReleaseSigningContract.VantrelOwnedPeArtifacts.Count, runner.Calls.Count);
        }

        using var reparse = new PreparedLayoutScope();
        var target = Path.Combine(reparse.Root, "replacement.dll");
        File.WriteAllText(target, "replacement");
        var artifact = Path.Combine(reparse.Root, "desktop", "Vantrel.Security.Desktop.dll");
        File.Delete(artifact);
        try { File.CreateSymbolicLink(artifact, target); }
        catch (Exception error) when (error.HResult == unchecked((int)0x80070522)) { Assert.Inconclusive("Symbolic-link privilege unavailable."); return; }
        var blocked = new CapturingRunner();
        Assert.ThrowsException<IOException>(() => CreateOrchestrator(blocked).SignPreparedLayout(reparse.Root, reparse.Tools));
        Assert.AreEqual(0, blocked.Calls.Count);
    }

    [TestMethod]
    public void Checked_in_template_is_canonical_and_local_metadata_is_ignored()
    {
        var root = FindRepositoryRoot();
        var template = File.ReadAllBytes(Path.Combine(root, "scripts", AzureArtifactSigningMetadataCodec.TemplateFileName));
        var ignore = File.ReadAllText(Path.Combine(root, ".gitignore"));

        Assert.IsTrue(AzureArtifactSigningMetadataCodec.TryParse(template, out _));
        StringAssert.Contains(ignore, "scripts/" + AzureArtifactSigningMetadataCodec.LocalMetadataFileName);
    }

    [TestMethod]
    public void Interactive_browser_only_metadata_requires_the_exact_documented_exclusion_list()
    {
        var metadata = new AzureArtifactSigningMetadata(AzureArtifactSigningMetadataCodec.Endpoint,
            AzureArtifactSigningMetadataCodec.AccountName, AzureArtifactSigningMetadataCodec.CertificateProfileName, null, true);
        var canonical = AzureArtifactSigningMetadataCodec.CreateCanonical(metadata);
        Assert.IsTrue(AzureArtifactSigningMetadataCodec.TryParse(canonical, out var parsed));
        Assert.IsTrue(parsed!.InteractiveBrowserOnly);

        var text = System.Text.Encoding.UTF8.GetString(canonical);
        foreach (var altered in new[]
        {
            text.Replace("\"AzureCliCredential\",", string.Empty, StringComparison.Ordinal),
            text.Replace("\"EnvironmentCredential\",", "\"UnexpectedCredential\",", StringComparison.Ordinal),
            text.Replace("\"AzureDeveloperCliCredential\"", "\"InteractiveBrowserCredential\"", StringComparison.Ordinal),
            text.Replace("\"EnvironmentCredential\",\"ManagedIdentityCredential\"", "\"ManagedIdentityCredential\",\"EnvironmentCredential\"", StringComparison.Ordinal)
        })
            Assert.IsFalse(AzureArtifactSigningMetadataCodec.TryParse(System.Text.Encoding.UTF8.GetBytes(altered), out _));
    }

    [TestMethod]
    public void Explicit_sign_command_rejects_relative_duplicate_unknown_and_existing_record_inputs_without_invoking_signer()
    {
        using var scope = new PreparedLayoutScope();
        var runner = new CapturingRunner();
        var output = new StringWriter();
        var absolute = new[] { "sign-authenticode-layout", "--output-root", scope.Root, "--signtool", scope.Tools.SignToolPath,
            "--dlib", scope.Tools.DlibPath, "--metadata", scope.Tools.MetadataPath };
        ReleaseLayoutToolCommand.Execute(absolute, runner, output, new CapturingAuthenticodeVerifier(AuthenticodeVerificationCategory.Valid));
        Assert.AreEqual(ReleaseSigningContract.VantrelOwnedPeArtifacts.Count, runner.Calls.Count);
        StringAssert.Contains(output.ToString(), "Externally sign");

        foreach (var invalid in new[]
        {
            new[] { "sign-authenticode-layout", "--output-root", ".", "--signtool", scope.Tools.SignToolPath, "--dlib", scope.Tools.DlibPath, "--metadata", scope.Tools.MetadataPath },
            absolute.Append("--unknown").Append("value").ToArray(),
            absolute.Append("--metadata").Append(scope.Tools.MetadataPath).ToArray()
        })
            Assert.ThrowsException<ArgumentException>(() => ReleaseLayoutToolCommand.Execute(invalid, new CapturingRunner(), TextWriter.Null));

        File.WriteAllText(Path.Combine(scope.Root, BetaReleaseLayoutValidator.RecordFileName), "record");
        Assert.ThrowsException<IOException>(() => ReleaseLayoutToolCommand.Execute(absolute, new CapturingRunner(), TextWriter.Null));
    }

    [TestMethod]
    public void Post_sign_policy_failure_blocks_completion_without_record()
    {
        using var scope = new PreparedLayoutScope();
        var runner = new CapturingRunner();
        var verifier = new CapturingAuthenticodeVerifier(AuthenticodeVerificationCategory.WrongPublisherPolicy);
        Assert.ThrowsException<IOException>(() => new AzureArtifactSigningOrchestrator(runner, verifier).SignPreparedLayout(scope.Root, scope.Tools));
        Assert.AreEqual(ReleaseSigningContract.VantrelOwnedPeArtifacts.Count, runner.Calls.Count);
        Assert.AreEqual(1, verifier.Calls.Count);
        Assert.IsFalse(File.Exists(Path.Combine(scope.Root, BetaReleaseLayoutValidator.RecordFileName)));
    }

    private static AzureArtifactSigningOrchestrator CreateOrchestrator(IAzureArtifactSigningProcessRunner runner) =>
        new(runner, new CapturingAuthenticodeVerifier(AuthenticodeVerificationCategory.Valid));
    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "Directory.Build.props"))) return directory.FullName;
        throw new InvalidOperationException("Repository root is unavailable.");
    }

    private sealed class CapturingRunner(Func<int, int>? behavior = null) : IAzureArtifactSigningProcessRunner
    {
        internal List<(string Executable, IReadOnlyList<string> Arguments)> Calls { get; } = [];
        public int Run(string executablePath, IReadOnlyList<string> arguments)
        {
            Calls.Add((executablePath, arguments));
            return behavior?.Invoke(Calls.Count) ?? 0;
        }
    }

    private sealed class CapturingAuthenticodeVerifier(AuthenticodeVerificationCategory category) : IReleaseAuthenticodeVerification
    {
        internal List<string> Calls { get; } = [];
        public AuthenticodeReleaseEvidence Verify(string relativePath, string absolutePath, string profileAlias)
        {
            Calls.Add(relativePath);
            return new(relativePath, category, "vantrel-azure-artifact-signing-durable-eku-v1",
                PrimarySignatureCountPolicyCategory.ExactlyOne, TimestampPolicyCategory.ValidRfc3161);
        }
    }
    private sealed class PreparedLayoutScope : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-azure-signing-" + Guid.NewGuid().ToString("N"));
        private string ToolRoot { get; } = Path.Combine(Path.GetTempPath(), "vantrel-azure-signing-tools-" + Guid.NewGuid().ToString("N"));
        internal AzureArtifactSigningToolPaths Tools { get; }

        internal PreparedLayoutScope()
        {
            Directory.CreateDirectory(Root);
            Directory.CreateDirectory(ToolRoot);
            Write(BetaReleaseLayoutValidator.ReleaseNotesFileName, "notes\n");
            var notesHash = Hash(Path.Combine(Root, BetaReleaseLayoutValidator.ReleaseNotesFileName));
            var descriptor = new BetaReleaseDescriptor(new string('a', 40), "0.1.0-beta.1", 7,
                new DateTimeOffset(2026, 10, 7, 0, 0, 0, TimeSpan.Zero), "Release", "win-x64", "10.0.401", notesHash);
            File.WriteAllBytes(Path.Combine(Root, BetaReleaseDescriptorCodec.FileName), BetaReleaseDescriptorCodec.CreateCanonical(descriptor));
            foreach (var component in ReleasePayloadVerifier.ServiceComponentFileNames) Write(Path.Combine("service", component), component);
            foreach (var artifact in ReleaseSigningContract.VantrelOwnedPeArtifacts)
                if (!File.Exists(Path.Combine(Root, artifact.RelativePath.Replace('/', Path.DirectorySeparatorChar)))) Write(artifact.RelativePath, artifact.RelativePath);
            var signTool = Path.Combine(ToolRoot, "signtool.exe");
            var dlib = Path.Combine(ToolRoot, "Azure.CodeSigning.Dlib.dll");
            File.WriteAllText(signTool, "tool");
            File.WriteAllText(dlib, "dlib");
            var metadata = Path.Combine(ToolRoot, AzureArtifactSigningMetadataCodec.LocalMetadataFileName);
            File.WriteAllBytes(metadata, AzureArtifactSigningMetadataCodec.CreateCanonical(new(
                AzureArtifactSigningMetadataCodec.Endpoint, AzureArtifactSigningMetadataCodec.AccountName,
                AzureArtifactSigningMetadataCodec.CertificateProfileName, null)));
            Tools = new(signTool, dlib, metadata);
        }

        private void Write(string relativePath, string contents)
        {
            var path = Path.Combine(Root, relativePath.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, contents);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
            if (Directory.Exists(ToolRoot)) Directory.Delete(ToolRoot, recursive: true);
        }

        private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    }
}
