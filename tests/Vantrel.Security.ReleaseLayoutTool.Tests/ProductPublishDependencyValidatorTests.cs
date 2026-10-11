using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
public sealed class ProductPublishDependencyValidatorTests
{
    [TestMethod]
    public void Pinned_sdk_publishes_are_dependency_complete_and_fail_on_missing_or_extra_files()
    {
        if (!OperatingSystem.IsWindows()) Assert.Inconclusive("Windows publish inspection is required.");
        var repo = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", ".."));
        var root = Path.Combine(Path.GetTempPath(), "vantrel-product-publish-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var service = Publish(repo, "src/Vantrel.Security.Service/Vantrel.Security.Service.csproj", root, "service");
            var desktop = Publish(repo, "src/Vantrel.Security.Desktop/Vantrel.Security.Desktop.csproj", root, "desktop");
            var tool = Publish(repo, "tools/Vantrel.Security.OfflineUpdateTool/Vantrel.Security.OfflineUpdateTool.csproj", root, "tool");
            var serviceLock = Hash(Path.Combine(repo, "src", "Vantrel.Security.Service", "packages.lock.json"));
            var desktopLock = Hash(Path.Combine(repo, "src", "Vantrel.Security.Desktop", "packages.lock.json"));
            var serviceHost = new[] { "Vantrel.Security.Service.exe", "Vantrel.Security.Service.deps.json",
                "Vantrel.Security.Service.runtimeconfig.json" }.ToDictionary(name => name,
                name => Hash(Path.Combine(service, name)), StringComparer.Ordinal);
            var desktopResult = ProductPublishDependencyValidator.ValidateSdkPublish(desktop,
                ProductPublishKind.Desktop, desktopLock);
            var toolResult = ProductPublishDependencyValidator.ValidateSdkPublish(tool,
                ProductPublishKind.OfflineUpdateTool, serviceLock, serviceHost);
            Assert.IsTrue(desktopResult.Files.Any(file => file.Path == "Microsoft.Extensions.Hosting.dll"));
            Assert.IsTrue(toolResult.Files.Any(file => file.Path == "Vantrel.Security.Service.dll"));
            Assert.IsFalse(toolResult.Files.Any(file => file.Path == "Vantrel.Security.Service.exe"));
            Assert.AreEqual(3, desktopResult.DiagnosticSymbols.Count);
            Assert.AreEqual(4, toolResult.DiagnosticSymbols.Count);
            Assert.AreEqual(4, toolResult.ExcludedBuildArtifacts.Count);
            Assert.IsTrue(toolResult.Files.All(file => !file.Path.EndsWith(".pdb", StringComparison.Ordinal)));
            Assert.AreEqual(34, desktopResult.Files.Count);
            Assert.AreEqual(40, toolResult.Files.Count);
            Assert.AreEqual(0, desktopResult.ExcludedBuildArtifacts.Count);
            Assert.IsTrue(toolResult.Files.Any(file => file.Path == "Microsoft.Extensions.Hosting.dll"));
            AssertOwned(desktopResult, "desktop", 4);
            AssertOwned(toolResult, "offline-update-tool", 5);
            CollectionAssert.AreEquivalent(new[] { "Vantrel.Security.Service.deps.json",
                "Vantrel.Security.Service.exe", "Vantrel.Security.Service.runtimeconfig.json",
                "packages.lock.json" }, toolResult.ExcludedBuildArtifacts
                .Select(file => file.RelativePath).ToArray());

            AssertReachableExtraProjectRejected(desktop, Path.Combine(root, "extra-desktop"),
                ProductPublishKind.Desktop, desktopLock, null);
            AssertReachableExtraProjectRejected(tool, Path.Combine(root, "extra-tool"),
                ProductPublishKind.OfflineUpdateTool, serviceLock, serviceHost);
            AssertMismappedProjectAssemblyRejected(desktop, Path.Combine(root, "mismapped-desktop"),
                desktopLock);
            AssertPackageSuppliedOwnedPeRejected(desktop, Path.Combine(root, "package-owned-desktop"),
                desktopLock);

            var projectedDesktop = Path.Combine(root, "projected-desktop");
            var projectedTool = Path.Combine(root, "projected-tool");
            Project(desktop, desktopResult.Files, projectedDesktop);
            Project(tool, toolResult.Files, projectedTool);
            _ = ProductPublishDependencyValidator.ValidateProjected(projectedDesktop,
                ProductPublishKind.Desktop, desktopResult.Files);
            _ = ProductPublishDependencyValidator.ValidateProjected(projectedTool,
                ProductPublishKind.OfflineUpdateTool, toolResult.Files);
            File.WriteAllText(Path.Combine(projectedDesktop, "Vantrel.Security.Unapproved.exe"), "extra");
            Assert.ThrowsException<InvalidDataException>(() =>
                ProductPublishDependencyValidator.ValidateProjected(projectedDesktop,
                    ProductPublishKind.Desktop, desktopResult.Files));
            File.Delete(Path.Combine(projectedDesktop, "Vantrel.Security.Unapproved.exe"));
            File.WriteAllText(Path.Combine(projectedTool, "Vantrel.Security.Service2.exe"), "extra");
            Assert.ThrowsException<InvalidDataException>(() =>
                ProductPublishDependencyValidator.ValidateProjected(projectedTool,
                    ProductPublishKind.OfflineUpdateTool, toolResult.Files));
            File.Delete(Path.Combine(projectedTool, "Vantrel.Security.Service2.exe"));
            var desktopAssembly = Path.Combine(projectedDesktop, "Vantrel.Security.Desktop.dll");
            var intermediate = Path.Combine(projectedDesktop, "temporary.dll");
            File.Move(desktopAssembly, intermediate);
            File.Move(intermediate, Path.Combine(projectedDesktop, "vantrel.security.desktop.dll"));
            Assert.ThrowsException<InvalidDataException>(() =>
                ProductPublishDependencyValidator.ValidateProjected(projectedDesktop,
                    ProductPublishKind.Desktop, desktopResult.Files));
            File.Move(Path.Combine(projectedDesktop, "vantrel.security.desktop.dll"), desktopAssembly);
            File.WriteAllText(Path.Combine(projectedDesktop, "packages.lock.json"), "residue");
            Assert.ThrowsException<InvalidDataException>(() =>
                ProductPublishDependencyValidator.ValidateProjected(projectedDesktop,
                    ProductPublishKind.Desktop, desktopResult.Files));
            File.Delete(Path.Combine(projectedDesktop, "packages.lock.json"));
            File.Delete(Path.Combine(projectedTool, "Vantrel.Security.Service.dll"));
            Assert.ThrowsException<InvalidDataException>(() =>
                ProductPublishDependencyValidator.ValidateProjected(projectedTool,
                    ProductPublishKind.OfflineUpdateTool, toolResult.Files));

            var lockPath = Path.Combine(desktop, "packages.lock.json");
            File.WriteAllText(lockPath, "unapproved");
            Assert.ThrowsException<InvalidDataException>(() =>
                ProductPublishDependencyValidator.ValidateSdkPublish(desktop,
                    ProductPublishKind.Desktop, desktopLock));
            File.Delete(lockPath);
            var serviceExePath = Path.Combine(tool, "Vantrel.Security.Service.exe");
            File.AppendAllText(serviceExePath, "changed");
            Assert.ThrowsException<InvalidDataException>(() =>
                ProductPublishDependencyValidator.ValidateSdkPublish(tool,
                    ProductPublishKind.OfflineUpdateTool, serviceLock, serviceHost));
            File.Copy(Path.Combine(service, "Vantrel.Security.Service.exe"), serviceExePath, true);
            var serviceHostPath = Path.Combine(tool, "Vantrel.Security.Service.deps.json");
            File.AppendAllText(serviceHostPath, "changed");
            Assert.ThrowsException<InvalidDataException>(() =>
                ProductPublishDependencyValidator.ValidateSdkPublish(tool,
                    ProductPublishKind.OfflineUpdateTool, serviceLock, serviceHost));
            File.Delete(serviceHostPath);

            File.Delete(Path.Combine(desktop, "Microsoft.Extensions.Hosting.dll"));
            Assert.ThrowsException<InvalidDataException>(() =>
                ProductPublishDependencyValidator.ValidateSdkPublish(desktop,
                    ProductPublishKind.Desktop, desktopLock));
            File.WriteAllText(Path.Combine(tool, "unexpected.dll"), "unexpected");
            Assert.ThrowsException<InvalidDataException>(() =>
                ProductPublishDependencyValidator.ValidateSdkPublish(tool,
                    ProductPublishKind.OfflineUpdateTool, serviceLock, serviceHost));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void AssertOwned(ProductPublishValidation validation, string group, int count)
    {
        var prefix = group + "/";
        var expected = ReleaseSigningContract.VantrelOwnedPeArtifacts
            .Where(item => item.RelativePath.StartsWith(prefix, StringComparison.Ordinal))
            .Select(item => item.RelativePath[prefix.Length..]).ToArray();
        Assert.AreEqual(count, expected.Length);
        CollectionAssert.AreEquivalent(expected, validation.Files.Where(file =>
            file.Path.StartsWith("Vantrel.Security.", StringComparison.Ordinal) &&
            (file.Path.EndsWith(".dll", StringComparison.Ordinal) ||
             file.Path.EndsWith(".exe", StringComparison.Ordinal)))
            .Select(file => file.Path).ToArray());
    }

    private static void AssertReachableExtraProjectRejected(string source, string destination,
        ProductPublishKind kind, string copiedLockHash,
        IReadOnlyDictionary<string, string>? serviceHost)
    {
        CopyTree(source, destination);
        var name = kind == ProductPublishKind.Desktop
            ? "Vantrel.Security.Desktop" : "Vantrel.Security.OfflineUpdateTool";
        var depsPath = Path.Combine(destination, name + ".deps.json");
        var document = JsonNode.Parse(File.ReadAllText(depsPath))!.AsObject();
        var target = document["targets"]![".NETCoreApp,Version=v10.0/win-x64"]!.AsObject();
        target["Vantrel.Security.Infrastructure/0.1.0"]!["dependencies"]!
            .AsObject()["Vantrel.Security.FutureComponent"] = "0.1.0";
        target["Vantrel.Security.FutureComponent/0.1.0"] = new JsonObject
        {
            ["runtime"] = new JsonObject { ["Vantrel.Security.FutureComponent.dll"] = new JsonObject() }
        };
        document["libraries"]!.AsObject()["Vantrel.Security.FutureComponent/0.1.0"] =
            new JsonObject { ["type"] = "project" };
        File.WriteAllText(depsPath, document.ToJsonString());
        File.WriteAllText(Path.Combine(destination, "Vantrel.Security.FutureComponent.dll"), "project assembly");

        // Without the closed project-library and owned-PE checks, this complete, reachable
        // dependency graph and its matching physical file pass the shared closure validator.
        var projects = kind == ProductPublishKind.Desktop
            ? new[] { name, "Vantrel.Security.Core", "Vantrel.Security.Infrastructure" }
            : new[] { name, "Vantrel.Security.Service", "Vantrel.Security.Core",
                "Vantrel.Security.Infrastructure" };
        var optional = projects.Select(project => project + ".pdb").ToHashSet(StringComparer.Ordinal);
        if (kind == ProductPublishKind.OfflineUpdateTool) optional.Add("appsettings.Development.json");
        var exclusions = new Dictionary<string, string>(StringComparer.Ordinal)
        { ["packages.lock.json"] = copiedLockHash };
        if (serviceHost is not null)
            foreach (var (path, hash) in serviceHost) exclusions.Add(path, hash);
        var supporting = kind == ProductPublishKind.Desktop
            ? new[] { name + ".exe", name + ".deps.json", name + ".runtimeconfig.json" }
            : new[] { name + ".exe", name + ".deps.json", name + ".runtimeconfig.json",
                "appsettings.json" };
        var contract = new PublishDependencyContract(name, name + ".deps.json",
            name + ".runtimeconfig.json",
            kind == ProductPublishKind.Desktop
                ? new Dictionary<string, string> { ["Microsoft.Extensions.Hosting"] = "10.0.12",
                    ["Vantrel.Security.Core"] = "0.1.0",
                    ["Vantrel.Security.Infrastructure"] = "0.1.0" }
                : new Dictionary<string, string> { ["Vantrel.Security.Service"] = "0.1.0" },
            supporting, optional, projects,
            kind == ProductPublishKind.Desktop
                ? ["Microsoft.NETCore.App", "Microsoft.WindowsDesktop.App"]
                : ["Microsoft.NETCore.App"], exclusions);
        Assert.IsTrue(ServicePublishDependencyValidator.ValidateProductPublish(destination, contract)
            .DeployableFiles.Any(file => file.Path == "Vantrel.Security.FutureComponent.dll"));
        Assert.ThrowsException<InvalidDataException>(() =>
            ProductPublishDependencyValidator.ValidateSdkPublish(destination, kind,
                copiedLockHash, serviceHost));
    }

    private static void CopyTree(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var path in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var target = Path.Combine(destination, Path.GetRelativePath(source, path));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(path, target);
        }
    }

    private static void AssertMismappedProjectAssemblyRejected(string source,
        string destination, string copiedLockHash)
    {
        CopyTree(source, destination);
        var depsPath = Path.Combine(destination, "Vantrel.Security.Desktop.deps.json");
        var document = JsonNode.Parse(File.ReadAllText(depsPath))!.AsObject();
        var runtime = document["targets"]![".NETCoreApp,Version=v10.0/win-x64"]!
            ["Vantrel.Security.Desktop/0.1.0"]!["runtime"]!.AsObject();
        var asset = runtime["Vantrel.Security.Desktop.dll"]!.DeepClone();
        runtime.Remove("Vantrel.Security.Desktop.dll");
        runtime["other/Vantrel.Security.Desktop.dll"] = asset;
        File.WriteAllText(depsPath, document.ToJsonString());
        Assert.ThrowsException<InvalidDataException>(() =>
            ProductPublishDependencyValidator.ValidateSdkPublish(destination,
                ProductPublishKind.Desktop, copiedLockHash));
    }

    private static void AssertPackageSuppliedOwnedPeRejected(string source,
        string destination, string copiedLockHash)
    {
        CopyTree(source, destination);
        var depsPath = Path.Combine(destination, "Vantrel.Security.Desktop.deps.json");
        var document = JsonNode.Parse(File.ReadAllText(depsPath))!.AsObject();
        var runtime = document["targets"]![".NETCoreApp,Version=v10.0/win-x64"]!
            ["Microsoft.Extensions.Hosting/10.0.12"]!["runtime"]!.AsObject();
        runtime["Vantrel.Security.Unapproved.dll"] = new JsonObject();
        File.WriteAllText(depsPath, document.ToJsonString());
        File.WriteAllText(Path.Combine(destination, "Vantrel.Security.Unapproved.dll"), "package asset");
        Assert.ThrowsException<InvalidDataException>(() =>
            ProductPublishDependencyValidator.ValidateSdkPublish(destination,
                ProductPublishKind.Desktop, copiedLockHash));
    }

    private static string Publish(string repo, string project, string root, string name)
    {
        var destination = Path.Combine(root, name);
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = repo, UseShellExecute = false
        };
        foreach (var value in new[] { "publish", Path.Combine(repo, project.Replace('/', Path.DirectorySeparatorChar)),
            "--configuration", "Release", "--runtime", "win-x64", "--self-contained", "false",
            "--no-restore", "--output", destination,
            "-p:VantrelReleaseVersion=0.1.0-beta.1",
            "-p:VantrelSourceCommit=125ce19ffd531a1b1bbd9cacb47da365f6708148" })
            start.ArgumentList.Add(value);
        using var process = Process.Start(start) ?? throw new AssertFailedException("SDK publish did not launch.");
        process.WaitForExit();
        Assert.AreEqual(0, process.ExitCode, "Pinned SDK publish failed.");
        return destination;
    }

    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private static void Project(string source, IReadOnlyList<Vantrel.Security.Core.TrustedManifestV2File> files,
        string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in files)
        {
            var relative = file.Path.Replace('/', Path.DirectorySeparatorChar);
            var target = Path.Combine(destination, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(Path.Combine(source, relative), target);
        }
    }
}
