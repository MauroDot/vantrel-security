using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
public sealed class ServicePublishDependencyValidatorTests
{
    private const int PrivilegeNotHeld = unchecked((int)0x80070522);
    private const string HostingAsset = "Microsoft.Extensions.Hosting.dll";
    private const string Target = ".NETCoreApp,Version=v10.0/win-x64";
    private const string RuntimeConfig = """
        {"runtimeOptions":{"tfm":"net10.0","framework":{"name":"Microsoft.NETCore.App","version":"10.0.0"}}}
        """;
    private const string Dependencies = """
        {"runtimeTarget":{"name":".NETCoreApp,Version=v10.0/win-x64","signature":""},"compilationOptions":{},"targets":{".NETCoreApp,Version=v10.0/win-x64":{
        "Vantrel.Security.Service/0.1.0":{"dependencies":{"Microsoft.Extensions.Hosting.WindowsServices":"10.0.12","System.ServiceProcess.ServiceController":"10.0.12","Vantrel.Security.Core":"0.1.0","Vantrel.Security.Infrastructure":"0.1.0"},"runtime":{"Vantrel.Security.Service.dll":{}}},
        "Microsoft.Extensions.Hosting.WindowsServices/10.0.12":{"dependencies":{"Microsoft.Extensions.Hosting":"10.0.12"},"runtime":{"lib/net10.0/Microsoft.Extensions.Hosting.WindowsServices.dll":{}}},
        "Microsoft.Extensions.Hosting/10.0.12":{"runtime":{"lib/net10.0/Microsoft.Extensions.Hosting.dll":{}}},
        "System.ServiceProcess.ServiceController/10.0.12":{"runtime":{"runtimes/win/lib/net10.0/System.ServiceProcess.ServiceController.dll":{}}},
        "Vantrel.Security.Core/0.1.0":{"runtime":{"Vantrel.Security.Core.dll":{}}},
        "Vantrel.Security.Infrastructure/0.1.0":{"runtime":{"Vantrel.Security.Infrastructure.dll":{}}}
        }},"libraries":{"Vantrel.Security.Service/0.1.0":{"type":"project"},"Microsoft.Extensions.Hosting.WindowsServices/10.0.12":{"type":"package"},"Microsoft.Extensions.Hosting/10.0.12":{"type":"package"},"System.ServiceProcess.ServiceController/10.0.12":{"type":"package"},"Vantrel.Security.Core/0.1.0":{"type":"project"},"Vantrel.Security.Infrastructure/0.1.0":{"type":"project"}}}
        """;

    [TestMethod]
    public void Complete_publish_has_canonical_immutable_inventory_and_detects_known_missing_dependency()
    {
        using var fixture = new PublishFixture();
        var inventory = ServicePublishDependencyValidator.Validate(fixture.Root);
        Assert.IsFalse(inventory is TrustedManifestV2File[]);
        Assert.AreEqual(10, inventory.Count);
        CollectionAssert.AreEqual(inventory.Select(item => item.Path).OrderBy(path => path, StringComparer.Ordinal).ToArray(),
            inventory.Select(item => item.Path).ToArray());
        Assert.IsTrue(inventory.Any(item => item.Path == HostingAsset));
        Assert.IsTrue(inventory.All(item => item.Sha256.Length == 64));
        CollectionAssert.AreEqual(inventory.ToArray(), ServicePublishDependencyValidator.Validate(fixture.Root, inventory).ToArray());

        File.Delete(fixture.Path(HostingAsset));
        Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
    }

    [TestMethod]
    public void Any_required_dependency_or_support_file_missing_fails_closed()
    {
        foreach (var missing in new[]
        {
            "Microsoft.Extensions.Hosting.WindowsServices.dll", "System.ServiceProcess.ServiceController.dll",
            "Vantrel.Security.Core.dll", "Vantrel.Security.Service.exe", "appsettings.json",
            ServicePublishFileSnapshot.DepsFileName, ServicePublishFileSnapshot.RuntimeConfigFileName
        })
        {
            using var fixture = new PublishFixture();
            File.Delete(fixture.Path(missing));
            AssertClosed(() => ServicePublishDependencyValidator.Validate(fixture.Root), missing);
        }
    }

    [TestMethod]
    public void Extra_and_case_colliding_assets_and_unsafe_metadata_fail_closed()
    {
        using (var fixture = new PublishFixture())
        {
            fixture.File("unexpected.dll");
            Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
        }
        using (var fixture = new PublishFixture())
        {
            fixture.ReplaceDeps(Dependencies.Replace("lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}",
                "lib/net10.0/Microsoft.Extensions.Hosting.dll\":{},\"lib/net10.0/microsoft.extensions.hosting.dll\":{}", StringComparison.Ordinal));
            Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
        }
        using (var fixture = new PublishFixture())
        {
            fixture.ReplaceDeps(Dependencies.Replace("lib/net10.0/Microsoft.Extensions.Hosting.dll",
                "../Microsoft.Extensions.Hosting.dll", StringComparison.Ordinal));
            Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
        }
        using (var fixture = new PublishFixture())
        {
            fixture.ReplaceDeps(Dependencies.Replace("\"runtimeTarget\":", "\"runtimeTarget\":{},\"runtimeTarget\":", StringComparison.Ordinal));
            Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
        }
    }

    [TestMethod]
    public void Only_the_hash_approved_root_source_lock_copy_is_excluded_from_deployable_files()
    {
        using var fixture = new PublishFixture();
        fixture.File("packages.lock.json");
        var approvedHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fixture.Path("packages.lock.json"))));
        Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
        Assert.ThrowsException<InvalidDataException>(() =>
            ServicePublishDependencyValidator.ValidateSdkPublish(fixture.Root, new string('0', 64)));

        var validation = ServicePublishDependencyValidator.ValidateSdkPublish(fixture.Root, approvedHash);
        Assert.AreEqual(10, validation.DeployableFiles.Count);
        Assert.IsFalse(validation.DeployableFiles.Any(item => item.Path == "packages.lock.json"));
        Assert.AreEqual(1, validation.ExcludedBuildArtifacts.Count);
        Assert.AreEqual("packages.lock.json", validation.ExcludedBuildArtifacts[0].RelativePath);
        Assert.AreEqual(approvedHash, validation.ExcludedBuildArtifacts[0].Sha256);
        Assert.IsFalse(validation.DeployableFiles is TrustedManifestV2File[]);
        Assert.IsFalse(validation.ExcludedBuildArtifacts is ServicePublishExcludedBuildArtifact[]);

        File.AppendAllText(fixture.Path("packages.lock.json"), "changed");
        Assert.ThrowsException<InvalidDataException>(() =>
            ServicePublishDependencyValidator.ValidateSdkPublish(fixture.Root, approvedHash));
    }

    [TestMethod]
    public void Nested_lock_copy_and_other_unknown_files_are_never_residue()
    {
        foreach (var unexpected in new[] { "nested/packages.lock.json", "packages.lock.json.bak", "unexpected.dll" })
        {
            using var fixture = new PublishFixture();
            fixture.File(unexpected);
            Assert.ThrowsException<InvalidDataException>(() =>
                ServicePublishDependencyValidator.ValidateSdkPublish(fixture.Root, new string('0', 64)));
        }
    }

    [TestMethod]
    public void Wrong_runtime_identity_and_consistently_truncated_root_graph_are_rejected()
    {
        using (var fixture = new PublishFixture())
        {
            fixture.ReplaceRuntimeConfig(RuntimeConfig.Replace("net10.0", "net9.0", StringComparison.Ordinal));
            Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
        }
        using (var fixture = new PublishFixture())
        {
            fixture.ReplaceDeps(Dependencies.Replace(Target, ".NETCoreApp,Version=v10.0/linux-x64", StringComparison.Ordinal));
            Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
        }
        using (var fixture = new PublishFixture())
        {
            fixture.ReplaceDeps(Dependencies.Replace("\"Microsoft.Extensions.Hosting.WindowsServices\":\"10.0.12\",", "", StringComparison.Ordinal));
            File.Delete(fixture.Path("Microsoft.Extensions.Hosting.WindowsServices.dll"));
            Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
        }
    }

    [TestMethod]
    public void Native_resource_and_rid_specific_assets_are_mapped_and_required()
    {
        using var fixture = new PublishFixture();
        var enriched = Dependencies.Replace("\"Microsoft.Extensions.Hosting/10.0.12\":{\"runtime\":{\"lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}}}",
            "\"Microsoft.Extensions.Hosting/10.0.12\":{\"runtime\":{\"lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}}," +
            "\"native\":{\"runtimes/win/native/nativehelper.dll\":{}}," +
            "\"resources\":{\"lib/net10.0/fr/Hosting.resources.dll\":{\"locale\":\"fr\"}}," +
            "\"runtimeTargets\":{\"runtimes/win-x64/native/ridhelper.dll\":{\"rid\":\"win-x64\",\"assetType\":\"native\"}," +
            "\"runtimes/win/native/other.dll\":{\"rid\":\"win\",\"assetType\":\"native\"}}}",
            StringComparison.Ordinal);
        Assert.AreNotEqual(Dependencies, enriched);
        fixture.ReplaceDeps(enriched);
        fixture.File("fr/Hosting.resources.dll");
        fixture.File("runtimes/win-x64/native/ridhelper.dll");
        Assert.AreEqual(12, ServicePublishDependencyValidator.Validate(fixture.Root).Count);
        var nativeBytes = File.ReadAllBytes(fixture.Path("runtimes/win-x64/native/ridhelper.dll"));
        File.Delete(fixture.Path("runtimes/win-x64/native/ridhelper.dll"));
        AssertClosed(() => ServicePublishDependencyValidator.Validate(fixture.Root), "selected RID-native asset");
        File.WriteAllBytes(fixture.Path("runtimes/win-x64/native/ridhelper.dll"), nativeBytes);
        File.Delete(fixture.Path("fr/Hosting.resources.dll"));
        AssertClosed(() => ServicePublishDependencyValidator.Validate(fixture.Root), "satellite resource asset");
    }

    [TestMethod]
    public void Unsupported_or_ambiguous_rid_mappings_fail_closed()
    {
        using (var fixture = new PublishFixture())
        {
            fixture.ReplaceDeps(Dependencies.Replace(
                "\"Microsoft.Extensions.Hosting/10.0.12\":{\"runtime\":{\"lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}}}",
                "\"Microsoft.Extensions.Hosting/10.0.12\":{\"runtime\":{\"lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}}," +
                "\"runtimeTargets\":{\"runtimes/win-x64/lib/net10.0/Hosting.resources.dll\":{\"rid\":\"win-x64\",\"assetType\":\"resources\"}}}",
                StringComparison.Ordinal));
            Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
        }
        using (var fixture = new PublishFixture())
        {
            fixture.ReplaceDeps(Dependencies.Replace(
                "\"Microsoft.Extensions.Hosting/10.0.12\":{\"runtime\":{\"lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}}}",
                "\"Microsoft.Extensions.Hosting/10.0.12\":{\"runtime\":{\"lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}}," +
                "\"runtimeTargets\":{\"runtimes/win-x64/lib/net10.0/one.dll\":{\"rid\":\"win-x64\",\"assetType\":\"runtime\"}," +
                "\"runtimes/win-x64/lib/net9.0/one.dll\":{\"rid\":\"win-x64\",\"assetType\":\"runtime\"}}}",
                StringComparison.Ordinal));
            Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
        }
    }

    [TestMethod]
    public void Rid_selection_is_per_asset_type_and_includes_base_fallback()
    {
        using var fixture = new PublishFixture();
        var enriched = Dependencies.Replace("\"Microsoft.Extensions.Hosting/10.0.12\":{\"runtime\":{\"lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}}}",
            "\"Microsoft.Extensions.Hosting/10.0.12\":{\"runtime\":{\"lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}}," +
            "\"native\":{\"runtimes/win/native/genericnative.dll\":{}}," +
            "\"resources\":{\"lib/net10.0/fr/Hosting.resources.dll\":{\"locale\":\"fr\"}}," +
            "\"runtimeTargets\":{\"runtimes/win-x64/lib/net10.0/Microsoft.Extensions.Hosting.dll\":{\"rid\":\"win-x64\",\"assetType\":\"runtime\"}," +
            "\"runtimes/win/native/winhelper.dll\":{\"rid\":\"win\",\"assetType\":\"native\"}," +
            "\"runtimes/base/native/basehelper.dll\":{\"rid\":\"base\",\"assetType\":\"native\"}," +
            "\"runtimes/linux/native/foreign.dll\":{\"rid\":\"linux\",\"assetType\":\"native\"}}}",
            StringComparison.Ordinal);
        Assert.AreNotEqual(Dependencies, enriched);
        fixture.ReplaceDeps(enriched);
        File.Delete(fixture.Path(HostingAsset));
        fixture.File("runtimes/win-x64/lib/net10.0/Microsoft.Extensions.Hosting.dll");
        fixture.File("runtimes/win/native/winhelper.dll");
        fixture.File("fr/Hosting.resources.dll");
        var paths = ServicePublishDependencyValidator.Validate(fixture.Root).Select(item => item.Path).ToArray();
        Assert.IsTrue(paths.Contains("runtimes/win-x64/lib/net10.0/Microsoft.Extensions.Hosting.dll"));
        Assert.IsTrue(paths.Contains("runtimes/win/native/winhelper.dll"));
        Assert.IsTrue(paths.Contains("fr/Hosting.resources.dll"));
        Assert.IsFalse(paths.Contains("runtimes/base/native/basehelper.dll"));
        File.Delete(fixture.Path("runtimes/win/native/winhelper.dll"));
        AssertClosed(() => ServicePublishDependencyValidator.Validate(fixture.Root), "selected win RID-native asset");

        using var baseFixture = new PublishFixture();
        var baseOnly = Dependencies.Replace("\"Microsoft.Extensions.Hosting/10.0.12\":{\"runtime\":{\"lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}}}",
            "\"Microsoft.Extensions.Hosting/10.0.12\":{\"runtime\":{\"lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}}," +
            "\"runtimeTargets\":{\"runtimes/base/native/basehelper.dll\":{\"rid\":\"base\",\"assetType\":\"native\"}}}",
            StringComparison.Ordinal);
        Assert.AreNotEqual(Dependencies, baseOnly);
        baseFixture.ReplaceDeps(baseOnly);
        baseFixture.File("runtimes/base/native/basehelper.dll");
        Assert.IsTrue(ServicePublishDependencyValidator.Validate(baseFixture.Root)
            .Any(item => item.Path == "runtimes/base/native/basehelper.dll"));
        File.Delete(baseFixture.Path("runtimes/base/native/basehelper.dll"));
        AssertClosed(() => ServicePublishDependencyValidator.Validate(baseFixture.Root), "base RID-native asset");
    }

    [TestMethod]
    public void Separately_expected_hashes_reject_content_tampering()
    {
        using var fixture = new PublishFixture();
        var expected = ServicePublishDependencyValidator.Validate(fixture.Root);
        File.AppendAllText(fixture.Path(HostingAsset), "changed");
        Assert.ThrowsException<InvalidDataException>(() => ServicePublishDependencyValidator.Validate(fixture.Root, expected));
        Assert.IsTrue(ServicePublishDependencyValidator.Validate(fixture.Root).Any(item => item.Path == HostingAsset));
    }

    [TestMethod]
    public void Reparse_leaf_and_directory_escape_are_rejected_when_privilege_is_available()
    {
        using var fixture = new PublishFixture();
        using var outside = new DisposableDirectory();
        var target = fixture.Path(HostingAsset);
        File.Delete(target);
        var outsideFile = Path.Combine(outside.Root, "outside.dll");
        File.WriteAllText(outsideFile, "outside");
        try { File.CreateSymbolicLink(target, outsideFile); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeld)
        {
            Assert.Inconclusive("Symbolic-link privilege unavailable.");
            return;
        }
        Assert.ThrowsException<IOException>(() => ServicePublishDependencyValidator.Validate(fixture.Root));
    }

    [TestMethod]
    public void Junction_root_is_rejected_as_a_genuine_reparse_point_without_symlink_privilege()
    {
        using var fixture = new PublishFixture();
        using var outside = new DisposableDirectory();
        var junction = Path.Combine(outside.Root, "publish-junction");
        Assert.IsTrue(ServicePublishFileSnapshot.Capture(fixture.Root).Files.Count > 0);

        var start = new ProcessStartInfo("cmd.exe")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in new[] { "/d", "/c", "mklink", "/J", junction, fixture.Root })
            start.ArgumentList.Add(argument);
        try
        {
            using var process = Process.Start(start);
            Assert.IsNotNull(process);
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(10_000))
            {
                process.Kill(entireProcessTree: true);
                Assert.Fail("Junction creation timed out.");
            }
            Task.WaitAll(output, error);
            Assert.AreEqual(0, process.ExitCode, "Junction creation failed.");
            Assert.IsTrue((File.GetAttributes(junction) & FileAttributes.ReparsePoint) != 0);
            Assert.ThrowsException<IOException>(() => ServicePublishFileSnapshot.Capture(junction));
        }
        finally
        {
            if (Directory.Exists(junction)) Directory.Delete(junction);
        }
    }

    [TestMethod]
    public void Actual_sdk_published_service_has_the_declared_hosting_dependency()
    {
        using var output = new DisposableDirectory();
        var repo = FindRepositoryRoot();
        var project = Path.Combine(repo, "src", "Vantrel.Security.Service", "Vantrel.Security.Service.csproj");
        var process = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = repo, UseShellExecute = false, CreateNoWindow = true
        };
        foreach (var argument in new[] { "publish", project, "--configuration", "Release", "--runtime", "win-x64",
            "--self-contained", "false", "--no-restore", "--verbosity", "quiet", "--output", output.Root })
            process.ArgumentList.Add(argument);
        using var child = Process.Start(process);
        Assert.IsNotNull(child);
        if (!child.WaitForExit(120_000))
        {
            child.Kill(entireProcessTree: true);
            Assert.Fail("Controlled Service publish timed out.");
        }
        Assert.AreEqual(0, child.ExitCode, "Controlled Service publish failed.");

        var sourceLock = Path.Combine(repo, "src", "Vantrel.Security.Service", "packages.lock.json");
        var sourceLockHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(sourceLock)));
        var validation = ServicePublishDependencyValidator.ValidateSdkPublish(output.Root, sourceLockHash);
        var inventory = validation.DeployableFiles;
        Assert.AreEqual(1, validation.ExcludedBuildArtifacts.Count);
        Assert.AreEqual("packages.lock.json", validation.ExcludedBuildArtifacts[0].RelativePath);
        Assert.AreEqual(sourceLockHash, validation.ExcludedBuildArtifacts[0].Sha256);
        Assert.IsTrue(inventory.Any(item => item.Path == HostingAsset));
        Assert.IsTrue(inventory.Count > 30);
        var copied = Path.Combine(output.Root, HostingAsset);
        var hostingBytes = File.ReadAllBytes(copied);
        File.Delete(copied);
        Assert.ThrowsException<InvalidDataException>(() =>
            ServicePublishDependencyValidator.ValidateSdkPublish(output.Root, sourceLockHash));
        File.WriteAllBytes(copied, hostingBytes);
        var eventLog = Path.Combine(output.Root, "System.Diagnostics.EventLog.dll");
        Assert.IsTrue(File.Exists(eventLog));
        File.Delete(eventLog);
        Assert.ThrowsException<InvalidDataException>(() =>
            ServicePublishDependencyValidator.ValidateSdkPublish(output.Root, sourceLockHash));
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "global.json")) &&
                File.Exists(Path.Combine(directory.FullName, "Vantrel.Security.sln"))) return directory.FullName;
        throw new InvalidOperationException("Repository root unavailable.");
    }

    private static void AssertClosed(Action action, string context)
    {
        try { action(); }
        catch (Exception error) when (error is IOException or InvalidDataException) { return; }
        Assert.Fail("Dependency validation accepted a missing file: " + context);
    }

    private sealed class PublishFixture : IDisposable
    {
        private readonly DisposableDirectory _directory = new();
        internal string Root => _directory.Root;
        internal PublishFixture()
        {
            ReplaceDeps(Dependencies);
            ReplaceRuntimeConfig(RuntimeConfig);
            foreach (var path in new[]
            {
                "Vantrel.Security.Service.exe", "Vantrel.Security.Service.dll", "Vantrel.Security.Core.dll",
                "Vantrel.Security.Infrastructure.dll", "Microsoft.Extensions.Hosting.WindowsServices.dll",
                HostingAsset, "System.ServiceProcess.ServiceController.dll", "appsettings.json"
            }) File(path);
        }
        internal string Path(string relative) => System.IO.Path.Combine(Root, relative.Replace('/', '\\'));
        internal void File(string relative)
        {
            var path = Path(relative);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            System.IO.File.WriteAllBytes(path, Encoding.ASCII.GetBytes(relative));
        }
        internal void ReplaceDeps(string text) => System.IO.File.WriteAllText(Path(ServicePublishFileSnapshot.DepsFileName), text, new UTF8Encoding(false));
        internal void ReplaceRuntimeConfig(string text) => System.IO.File.WriteAllText(Path(ServicePublishFileSnapshot.RuntimeConfigFileName), text, new UTF8Encoding(false));
        public void Dispose() => _directory.Dispose();
    }

    private sealed class DisposableDirectory : IDisposable
    {
        internal string Root { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "vantrel-task071-" + Guid.NewGuid().ToString("N"));
        internal DisposableDirectory() => Directory.CreateDirectory(Root);
        public void Dispose()
        {
            var expectedPrefix = System.IO.Path.GetFullPath(System.IO.Path.GetTempPath());
            var full = System.IO.Path.GetFullPath(Root);
            if (full.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase) &&
                System.IO.Path.GetFileName(full).StartsWith("vantrel-task071-", StringComparison.Ordinal) &&
                Directory.Exists(full) && (System.IO.File.GetAttributes(full) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(full, recursive: true);
        }
    }
}
