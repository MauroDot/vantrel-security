using System.Diagnostics;
using System.Text.Json;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
[DoNotParallelize]
public sealed class LocalServiceHarnessPublishFreshnessTests
{
    private const string HarnessAssembly = "Kestermere.Security.LocalServiceAclHarness";
    private const string MessageAssembly = "System.Diagnostics.EventLog.Messages.dll";
    private static readonly string[] ExpectedFiles =
    [
        HarnessAssembly + ".exe",
        HarnessAssembly + ".dll",
        HarnessAssembly + ".deps.json",
        HarnessAssembly + ".runtimeconfig.json",
        "System.Diagnostics.EventLog.dll",
        MessageAssembly,
        "System.ServiceProcess.ServiceController.dll"
    ];

    private sealed record PublishFile(string Name, string Source, string Destination,
        byte[] OriginalBytes, DateTime OriginalWriteTimeUtc);

    [TestMethod]
    public void Fixed_publish_replaces_future_dated_stale_package_and_apphost_bytes()
    {
        var (repository, configuration) = ResolveCurrentBuild();
        var harnessDirectory = Path.Combine(repository, "tests", "Vantrel.Security.LocalServiceAclHarness");
        var publishDirectory = Path.Combine(harnessDirectory, "bin", configuration,
            "net10.0-windows", "win-x64", "publish");
        RequireNormalDirectoryChain(harnessDirectory, publishDirectory);

        var sources = new[]
        {
            (Name: MessageAssembly, Path: ResolveMessagePackageAsset(harnessDirectory)),
            (Name: HarnessAssembly + ".dll", Path: Path.Combine(harnessDirectory, "bin",
                configuration, "net10.0-windows", "win-x64", HarnessAssembly + ".dll")),
            (Name: HarnessAssembly + ".exe", Path: Path.Combine(harnessDirectory, "obj",
                configuration, "net10.0-windows", "win-x64", "apphost.exe"))
        };
        var files = sources.Select(source =>
        {
            var destination = Path.Combine(publishDirectory, source.Name);
            Assert.IsTrue(File.Exists(source.Path), "Authoritative publish source is missing: " + source.Name);
            Assert.IsTrue(File.Exists(destination), "Prepared publish file is missing: " + source.Name);
            Assert.IsFalse((File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0,
                "Prepared publish file is a reparse point: " + source.Name);
            var original = File.ReadAllBytes(destination);
            Assert.IsTrue(original.AsSpan().SequenceEqual(File.ReadAllBytes(source.Path)),
                "Prepared publish bytes differ from their source: " + source.Name);
            return new PublishFile(source.Name, source.Path, destination, original,
                File.GetLastWriteTimeUtc(destination));
        }).ToArray();

        var verified = false;
        try
        {
            foreach (var file in files)
            {
                var stale = (byte[])file.OriginalBytes.Clone();
                stale[0] ^= 1;
                File.WriteAllBytes(file.Destination, stale);
                var future = DateTime.UtcNow.AddYears(5);
                Assert.IsTrue(future > File.GetLastWriteTimeUtc(file.Source));
                File.SetLastWriteTimeUtc(file.Destination, future);
                Assert.AreEqual((long)stale.Length, new FileInfo(file.Source).Length);
                Assert.IsTrue(File.GetLastWriteTimeUtc(file.Destination) >
                              File.GetLastWriteTimeUtc(file.Source));
            }

            RunFixedPublishTarget(repository, configuration);

            foreach (var file in files)
                Assert.IsTrue(File.ReadAllBytes(file.Destination).AsSpan()
                        .SequenceEqual(File.ReadAllBytes(file.Source)),
                    "Fixed publish retained future-dated stale bytes: " + file.Name);
            CollectionAssert.AreEquivalent(ExpectedFiles,
                Directory.GetFileSystemEntries(publishDirectory).Select(path => Path.GetFileName(path)!).ToArray());
            verified = true;
        }
        finally
        {
            // The publish output is generated test data. Restore it if preparation or
            // verification fails so no stale executable/package bytes remain for later tests.
            if (!verified)
                foreach (var file in files)
                {
                    File.WriteAllBytes(file.Destination, file.OriginalBytes);
                    File.SetLastWriteTimeUtc(file.Destination, file.OriginalWriteTimeUtc);
                }
        }
    }

    private static (string Repository, string Configuration) ResolveCurrentBuild()
    {
        var assemblyDirectory = new DirectoryInfo(Path.GetDirectoryName(
            typeof(LocalServiceHarnessPublishFreshnessTests).Assembly.Location)!);
        var configurationDirectory = assemblyDirectory.Parent;
        var testProject = configurationDirectory?.Parent?.Parent;
        var testsDirectory = testProject?.Parent;
        var repository = testsDirectory?.Parent;
        if (assemblyDirectory.Name != "net10.0-windows" ||
            configurationDirectory?.Name is not ("Debug" or "Release") ||
            configurationDirectory?.Parent?.Name != "bin" ||
            testProject?.Name != "Vantrel.Security.Ipc.Tests" ||
            testsDirectory?.Name != "tests" || repository is null ||
            !File.Exists(Path.Combine(repository.FullName, "Vantrel.Security.sln")) ||
            !File.Exists(Path.Combine(testProject.FullName, "Vantrel.Security.Ipc.Tests.csproj")) ||
            !File.Exists(Path.Combine(repository.FullName, "tests", "Vantrel.Security.LocalServiceAclHarness",
                "Vantrel.Security.LocalServiceAclHarness.csproj")))
            throw new IOException("Fixed harness repository and configuration are unavailable.");
        return (repository.FullName, configurationDirectory.Name);
    }

    private static string ResolveMessagePackageAsset(string harnessDirectory)
    {
        var assetsFile = Path.Combine(harnessDirectory, "obj", "project.assets.json");
        using var assets = JsonDocument.Parse(File.ReadAllBytes(assetsFile));
        var libraries = assets.RootElement.GetProperty("libraries").EnumerateObject()
            .Where(library => library.Name.StartsWith("System.Diagnostics.EventLog/", StringComparison.Ordinal))
            .ToArray();
        Assert.AreEqual(1, libraries.Length);
        var version = libraries[0].Name["System.Diagnostics.EventLog/".Length..];
        Assert.IsFalse(version.Contains('/') || version.Contains('\\'));
        var packagePath = libraries[0].Value.GetProperty("path").GetString();
        Assert.AreEqual("system.diagnostics.eventlog/" + version, packagePath);
        var candidates = assets.RootElement.GetProperty("packageFolders").EnumerateObject()
            .Select(folder => Path.Combine(folder.Name, "system.diagnostics.eventlog", version,
                "runtimes", "win", "lib", "net10.0", MessageAssembly))
            .Where(File.Exists).ToArray();
        Assert.AreEqual(1, candidates.Length);
        return candidates[0];
    }

    private static void RequireNormalDirectoryChain(string harnessDirectory, string publishDirectory)
    {
        for (var current = new DirectoryInfo(publishDirectory); ; current = current.Parent!)
        {
            Assert.IsTrue(current.Exists, "Harness publish directory is missing: " + current.FullName);
            Assert.IsFalse((current.Attributes & FileAttributes.ReparsePoint) != 0,
                "Harness publish directory contains a reparse point: " + current.FullName);
            if (string.Equals(current.FullName, harnessDirectory, StringComparison.OrdinalIgnoreCase))
                break;
            Assert.IsNotNull(current.Parent);
        }
    }

    private static void RunFixedPublishTarget(string repository, string configuration)
    {
        var runtimeDirectory = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        var dotnet = Path.GetFullPath(Path.Combine(runtimeDirectory, "..", "..", "..", "dotnet.exe"));
        Assert.IsTrue(File.Exists(dotnet), "The dotnet host for the current runtime is missing.");
        var project = Path.Combine(repository, "tests", "Vantrel.Security.Ipc.Tests",
            "Vantrel.Security.Ipc.Tests.csproj");
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(dotnet)
        {
            WorkingDirectory = repository,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        process.StartInfo.ArgumentList.Add("msbuild");
        process.StartInfo.ArgumentList.Add(project);
        process.StartInfo.ArgumentList.Add("-target:PrepareLocalServiceHarnessPublish");
        process.StartInfo.ArgumentList.Add("-property:Configuration=" + configuration);
        process.StartInfo.ArgumentList.Add("-property:Restore=false");
        process.StartInfo.ArgumentList.Add("-verbosity:quiet");
        Assert.IsTrue(process.Start());
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(120_000))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            Assert.Fail("Fixed harness publish timed out.");
        }
        _ = output.GetAwaiter().GetResult();
        _ = error.GetAwaiter().GetResult();
        Assert.AreEqual(0, process.ExitCode, "Fixed harness publish failed.");
    }
}
