using System.Diagnostics;
using System.Text;

namespace Vantrel.Security.InstallerAuthoring.Tests;

[TestClass]
public sealed class SignedSandboxMsiBindingTests
{
    [TestMethod]
    public void Private_msi_binding_hashes_retained_bytes_blocks_mutation_and_releases_on_failure()
    {
        using var fixture = new ProbeFixture();
        var result = fixture.Run("""
            $binding = [VantrelSandboxMsiBinding]::Open($filePath)
            try {
                if ($binding.Sha256() -cne $expectedHash) { throw 'Hash mismatch.' }
                $binding.RequireUnchanged()
                $blocked = 0
                try { $writer = [IO.File]::Open($filePath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite); $writer.Dispose() } catch [IO.IOException] { $blocked++ }
                try { [IO.File]::Move($filePath, $filePath + '.moved') } catch [IO.IOException] { $blocked++ }
                try { [IO.File]::Delete($filePath) } catch [IO.IOException] { $blocked++ }
                if ($blocked -ne 3) { throw 'The binding allowed mutation.' }
                $binding.RequireUnchanged()
                if ($binding.Sha256() -cne $expectedHash) { throw 'Retained bytes changed.' }
                throw 'Simulated installer failure.'
            } catch {
                if ($_.Exception.Message -cne 'Simulated installer failure.') { throw }
            } finally { $binding.Dispose() }
            $writer = [IO.File]::Open($filePath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $writer.Dispose()
            'PASS'
            """);
        Assert.AreEqual(0, result.ExitCode, result.Error);
        Assert.AreEqual("PASS", result.Output.Trim());
    }

    [TestMethod]
    public void Private_msi_binding_fails_closed_when_read_sharing_is_incompatible()
    {
        using var fixture = new ProbeFixture();
        var result = fixture.Run("""
            $writer = [IO.File]::Open($filePath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $accepted = $false
                try { $binding = [VantrelSandboxMsiBinding]::Open($filePath); $accepted = $true; $binding.Dispose() }
                catch { if ($_.Exception.ToString() -notmatch 'Sandbox MSI copy binding failed') { throw } }
                if ($accepted) { throw 'Incompatible sharing was accepted.' }
            } finally { $writer.Dispose() }
            $binding = [VantrelSandboxMsiBinding]::Open($filePath)
            try { if ($binding.Sha256() -cne $expectedHash) { throw 'Hash mismatch.' } }
            finally { $binding.Dispose() }
            'PASS'
            """);
        Assert.AreEqual(0, result.ExitCode, result.Error);
        Assert.AreEqual("PASS", result.Output.Trim());
    }

    [TestMethod]
    public void Private_msi_binding_rejects_missing_and_directory_inputs()
    {
        using var fixture = new ProbeFixture();
        AssertRejected(fixture, fixture.FilePath + ".missing");
        AssertRejected(fixture, fixture.Root);
    }

    [TestMethod]
    public void Private_msi_binding_rejects_reparse_input()
    {
        using var fixture = new ProbeFixture();
        var link = Path.Combine(fixture.Root, "linked.msi");
        try { File.CreateSymbolicLink(link, fixture.FilePath); }
        catch (Exception error) when (error.HResult == unchecked((int)0x80070522))
        {
            Assert.Inconclusive("Symbolic-link creation requires privilege 0x80070522.");
            return;
        }
        AssertRejected(fixture, link);
    }

    private static void AssertRejected(ProbeFixture fixture, string path)
    {
        var result = fixture.Run("""
            $accepted = $false
            try { $binding = [VantrelSandboxMsiBinding]::Open($filePath); $accepted = $true; $binding.Dispose() }
            catch { if ($_.Exception.ToString() -notmatch 'Sandbox MSI copy binding failed') { throw } }
            if ($accepted) { throw 'Unsafe input was accepted.' }
            'PASS'
            """, path);
        Assert.AreEqual(0, result.ExitCode, result.Error);
        Assert.AreEqual("PASS", result.Output.Trim());
    }

    private sealed class ProbeFixture : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "vantrel-signed-msi-binding-" + Guid.NewGuid().ToString("N"));
        public string FilePath => Path.Combine(Root, "synthetic.msi");

        public ProbeFixture()
        {
            Directory.CreateDirectory(Root);
            File.WriteAllBytes(FilePath, [0x4D, 0x5A, 0x01, 0x02, 0x03]);
        }

        public (int ExitCode, string Output, string Error) Run(string body, string? target = null)
        {
            var validator = File.ReadAllText(Path.Combine(RepositoryRoot(), "sandbox", "Validate-VantrelSignedCandidateSandbox.ps1"));
            var start = validator.IndexOf("Add-Type -TypeDefinition @'", StringComparison.Ordinal);
            Assert.IsGreaterThanOrEqualTo(0, start);
            var marker = validator.IndexOf("'@ -ErrorAction Stop", start, StringComparison.Ordinal);
            Assert.IsGreaterThan(start, marker);
            var end = marker + "'@ -ErrorAction Stop".Length;
            var definitions = validator[start..end];
            var pathBytes = Convert.ToBase64String(Encoding.Unicode.GetBytes(target ?? FilePath));
            var expectedHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(FilePath)));
            var script = """
                $ErrorActionPreference = 'Stop'
                if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'Windows PowerShell 5.1 is required for this probe.' }
                """ + "\n" + definitions + "\n" +
                "$filePath=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" + pathBytes + "'))\n" +
                "$expectedHash='" + expectedHash + "'\n" + body;
            var scriptPath = Path.Combine(Root, "probe-" + Guid.NewGuid().ToString("N") + ".ps1");
            File.WriteAllText(scriptPath, script);
            using var process = Process.Start(new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                ArgumentList = { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath }
            })!;
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            Assert.IsTrue(process.WaitForExit(30000), "PowerShell binding probe did not finish.");
            return (process.ExitCode, output, error);
        }

        public void Dispose() => Directory.Delete(Root, true);
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "Vantrel.Security.sln"))) return directory.FullName;
        throw new InvalidOperationException("Repository root is unavailable.");
    }
}
