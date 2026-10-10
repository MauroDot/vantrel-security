using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
[DoNotParallelize]
public sealed class ServiceReleaseV2LayoutTests
{
    private const string Version = "0.1.0-beta.1";
    private const ulong Sequence = 7;
    private const string Hosting = "Microsoft.Extensions.Hosting.dll";
    private const int PrivilegeNotHeld = unchecked((int)0x80070522);
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
    public void Projection_contains_the_complete_deployable_set_and_an_independent_signed_manifest_verifies()
    {
        using var fixture = new PublishFixture();
        var projected = fixture.Project();

        Assert.AreEqual(10, projected.Files.Count);
        Assert.IsTrue(projected.Files.Any(file => file.Path == Hosting));
        Assert.IsTrue(projected.Files.Any(file => file.Path == "System.ServiceProcess.ServiceController.dll"));
        Assert.IsFalse(projected.Files.Any(file => file.Path == "packages.lock.json"));
        Assert.AreEqual(1, projected.ExcludedBuildArtifacts.Count);
        Assert.AreEqual("packages.lock.json", projected.ExcludedBuildArtifacts[0].RelativePath);
        Assert.AreEqual(fixture.LockSha256, projected.ExcludedBuildArtifacts[0].Sha256);
        CollectionAssert.AreEqual(projected.Files.Select(file => file.Path).OrderBy(path => path, StringComparer.Ordinal).ToArray(),
            projected.Files.Select(file => file.Path).ToArray());
        CollectionAssert.AreEqual(TrustedManifestV2Codec.CreateCanonicalPayload(Version, Sequence, projected.Files),
            projected.CanonicalManifestPayload);
        Assert.IsFalse(File.Exists(fixture.DestinationFile("packages.lock.json")));
        Assert.IsFalse(File.Exists(fixture.DestinationFile("Vantrel.Security.TrustedManifest")));

        using var testKey = CreateSyntheticKey();
        var signed = TrustedManifestV2Codec.CreateFile(Version, Sequence, projected.Files, testKey);
        new ServiceReleaseV2Verifier().VerifyWithTestKey(fixture.Destination, signed, Version, Sequence,
            testKey.ExportSubjectPublicKeyInfo());

        // Source content is no longer an authority after projection. The signed, independently
        // measured destination inventory is the authority for this isolated v2 verification.
        File.AppendAllText(fixture.SourceFile(Hosting), "source changed later");
        new ServiceReleaseV2Verifier().VerifyWithTestKey(fixture.Destination, signed, Version, Sequence,
            testKey.ExportSubjectPublicKeyInfo());
    }

    [TestMethod]
    public void Source_missing_dependency_unexpected_file_or_changed_lock_fails_before_projection()
    {
        using (var fixture = new PublishFixture())
        {
            File.Delete(fixture.SourceFile(Hosting));
            AssertProjectionClosed(fixture);
        }
        using (var fixture = new PublishFixture())
        {
            fixture.WriteSource("unexpected.dll", "unexpected");
            AssertProjectionClosed(fixture);
        }
        using (var fixture = new PublishFixture())
        {
            File.AppendAllText(fixture.SourceFile("packages.lock.json"), "changed");
            AssertProjectionClosed(fixture);
        }
        using (var fixture = new PublishFixture())
        {
            fixture.WriteSource("nested/packages.lock.json", "not approved residue");
            AssertProjectionClosed(fixture);
        }
    }

    [TestMethod]
    public void Missing_extra_or_mutated_projected_file_never_matches_the_signed_inventory()
    {
        foreach (var mutation in new Action<PublishFixture>[]
        {
            fixture => File.Delete(fixture.DestinationFile(Hosting)),
            fixture => File.AppendAllText(fixture.DestinationFile(Hosting), "altered"),
            fixture => fixture.WriteDestination("unexpected.dll", "unexpected"),
            fixture => fixture.WriteDestination("nested/extra.dll", "unexpected"),
            fixture => fixture.WriteDestination("packages.lock.json", "unapproved residue"),
            fixture => fixture.WriteDestination("nested/packages.lock.json", "unapproved residue")
        })
        {
            using var fixture = new PublishFixture();
            var projected = fixture.Project();
            using var testKey = CreateSyntheticKey();
            var signed = TrustedManifestV2Codec.CreateFile(Version, Sequence, projected.Files, testKey);
            mutation(fixture);
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2Verifier().VerifyWithTestKey(
                fixture.Destination, signed, Version, Sequence, testKey.ExportSubjectPublicKeyInfo()));
        }
    }

    [TestMethod]
    public void Changed_manifest_inventory_bad_signature_and_wrong_release_identity_fail_closed()
    {
        using var fixture = new PublishFixture();
        var projected = fixture.Project();
        using var goodKey = CreateSyntheticKey();
        using var wrongKey = CreateSyntheticKey(wrong: true);
        var publicKey = goodKey.ExportSubjectPublicKeyInfo();
        var good = TrustedManifestV2Codec.CreateFile(Version, Sequence, projected.Files, goodKey);
        var alteredInventory = projected.Files.Select(file => file.Path == Hosting
            ? new TrustedManifestV2File(file.Path, new string('A', 64)) : file).ToArray();
        var wrongHash = TrustedManifestV2Codec.CreateFile(Version, Sequence, alteredInventory, goodKey);
        var wrongSignature = TrustedManifestV2Codec.CreateFile(Version, Sequence, projected.Files, wrongKey);

        foreach (var signed in new[] { wrongHash, wrongSignature })
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2Verifier().VerifyWithTestKey(
                fixture.Destination, signed, Version, Sequence, publicKey));
        Assert.ThrowsException<IOException>(() => new ServiceReleaseV2Verifier().VerifyWithTestKey(
            fixture.Destination, good, "0.1.1-beta.1", Sequence, publicKey));
        Assert.ThrowsException<IOException>(() => new ServiceReleaseV2Verifier().VerifyWithTestKey(
            fixture.Destination, good, Version, Sequence + 1, publicKey));

        var malformed = Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(good).Replace("signature=", "signature=@@", StringComparison.Ordinal));
        Assert.ThrowsException<IOException>(() => new ServiceReleaseV2Verifier().VerifyWithTestKey(
            fixture.Destination, malformed, Version, Sequence, publicKey));

        foreach (var changedIdentity in new[]
        {
            Encoding.ASCII.GetString(good).Replace("architecture=win-x64\n", "architecture=win-arm64\n", StringComparison.Ordinal),
            Encoding.ASCII.GetString(good).Replace("deployment=framework-dependent\n", "deployment=self-contained\n", StringComparison.Ordinal)
        })
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2Verifier().VerifyWithTestKey(
                fixture.Destination, Encoding.ASCII.GetBytes(changedIdentity), Version, Sequence, publicKey));
    }

    [TestMethod]
    public void Case_collision_and_traversal_in_publish_metadata_are_rejected()
    {
        using (var fixture = new PublishFixture())
        {
            fixture.WriteSource(ServicePublishFileSnapshot.DepsFileName,
                Dependencies.Replace("lib/net10.0/Microsoft.Extensions.Hosting.dll\":{}",
                    "lib/net10.0/Microsoft.Extensions.Hosting.dll\":{},\"lib/net10.0/microsoft.extensions.hosting.dll\":{}",
                    StringComparison.Ordinal));
            AssertProjectionClosed(fixture);
        }
        using (var fixture = new PublishFixture())
        {
            fixture.WriteSource(ServicePublishFileSnapshot.DepsFileName,
                Dependencies.Replace("lib/net10.0/Microsoft.Extensions.Hosting.dll",
                    "../Microsoft.Extensions.Hosting.dll", StringComparison.Ordinal));
            AssertProjectionClosed(fixture);
        }
    }

    [TestMethod]
    public void Reparse_leaf_is_rejected_when_file_symlink_privilege_is_available()
    {
        using var fixture = new PublishFixture();
        using var outside = new DisposableDirectory();
        var leaf = fixture.SourceFile(Hosting);
        var target = System.IO.Path.Combine(outside.Root, "outside.dll");
        File.WriteAllText(target, "outside");
        File.Delete(leaf);
        try { File.CreateSymbolicLink(leaf, target); }
        catch (Exception error) when (error.HResult == PrivilegeNotHeld)
        {
            Assert.Inconclusive("File-symbolic-link privilege unavailable.");
            return;
        }
        AssertProjectionClosed(fixture);
    }

    [TestMethod]
    public void Junction_source_root_is_rejected_without_file_symlink_privilege()
    {
        using var fixture = new PublishFixture();
        using var outside = new DisposableDirectory();
        var junction = System.IO.Path.Combine(outside.Root, "publish-junction");
        var start = new ProcessStartInfo("cmd.exe")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in new[] { "/d", "/c", "mklink", "/J", junction, fixture.Source })
            start.ArgumentList.Add(argument);
        try
        {
            using var process = Process.Start(start);
            Assert.IsNotNull(process);
            var standard = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(10_000))
            {
                process.Kill(entireProcessTree: true);
                Assert.Fail("Junction creation timed out.");
            }
            Task.WaitAll(standard, error);
            Assert.AreEqual(0, process.ExitCode);
            Assert.IsTrue((File.GetAttributes(junction) & FileAttributes.ReparsePoint) != 0);
            AssertProjectionClosed(fixture, junction);
        }
        finally
        {
            if (Directory.Exists(junction)) Directory.Delete(junction);
        }
    }

    [TestMethod]
    public void Junction_final_directory_is_rejected_without_file_symlink_privilege()
    {
        using var fixture = new PublishFixture();
        var projected = fixture.Project();
        using var testKey = CreateSyntheticKey();
        var signed = TrustedManifestV2Codec.CreateFile(Version, Sequence, projected.Files, testKey);
        var original = fixture.Destination + "-original";
        Directory.Move(fixture.Destination, original);
        var start = new ProcessStartInfo("cmd.exe")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in new[] { "/d", "/c", "mklink", "/J", fixture.Destination, original })
            start.ArgumentList.Add(argument);
        try
        {
            using var process = Process.Start(start);
            Assert.IsNotNull(process);
            var standard = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(10_000))
            {
                process.Kill(entireProcessTree: true);
                Assert.Fail("Junction creation timed out.");
            }
            Task.WaitAll(standard, error);
            Assert.AreEqual(0, process.ExitCode);
            Assert.ThrowsException<IOException>(() => new ServiceReleaseV2Verifier().VerifyWithTestKey(
                fixture.Destination, signed, Version, Sequence, testKey.ExportSubjectPublicKeyInfo()));
        }
        finally
        {
            if (Directory.Exists(fixture.Destination)) Directory.Delete(fixture.Destination);
        }
    }

    [TestMethod]
    public void Staging_creation_is_create_new_and_rejects_an_existing_directory()
    {
        using var temporary = new DisposableDirectory();
        var stage = System.IO.Path.Combine(temporary.Root, "stage");
        ServiceReleaseV2Projector.CreateNewStageDirectory(stage);
        Assert.IsTrue(Directory.Exists(stage));
        Assert.ThrowsException<IOException>(() => ServiceReleaseV2Projector.CreateNewStageDirectory(stage));
    }

    [TestMethod]
    public void Actual_pinned_sdk_service_publish_projects_all_forty_two_deployable_files()
    {
        using var temporary = new DisposableDirectory();
        var repo = FindRepositoryRoot();
        var project = System.IO.Path.Combine(repo, "src", "Vantrel.Security.Service", "Vantrel.Security.Service.csproj");
        var raw = System.IO.Path.Combine(temporary.Root, "publish");
        var final = System.IO.Path.Combine(temporary.Root, "service");
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = repo, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in new[] { "publish", project, "--configuration", "Release", "--runtime", "win-x64",
            "--self-contained", "false", "--no-restore", "--verbosity", "quiet", "--output", raw })
            start.ArgumentList.Add(argument);
        using (var process = Process.Start(start))
        {
            Assert.IsNotNull(process);
            var standard = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(180_000))
            {
                process.Kill(entireProcessTree: true);
                Assert.Fail("Controlled Service publish timed out.");
            }
            Task.WaitAll(standard, error);
            Assert.AreEqual(0, process.ExitCode, "Controlled Service publish failed.");
        }

        var sourceLock = System.IO.Path.Combine(repo, "src", "Vantrel.Security.Service", "packages.lock.json");
        var approvedHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(sourceLock)));
        Assert.AreEqual(43, Directory.EnumerateFiles(raw, "*", SearchOption.AllDirectories).Count());
        var projected = new ServiceReleaseV2Projector().Project(raw, final, approvedHash, Version, Sequence);
        Assert.AreEqual(42, projected.Files.Count);
        Assert.AreEqual(34, projected.Files.Count(file => file.Path.EndsWith(".dll", StringComparison.Ordinal)));
        Assert.AreEqual(1, projected.ExcludedBuildArtifacts.Count);
        Assert.AreEqual(approvedHash, projected.ExcludedBuildArtifacts[0].Sha256);
        Assert.IsTrue(projected.Files.Any(file => file.Path == Hosting));
        Assert.IsTrue(projected.Files.Any(file => file.Path == "System.Diagnostics.EventLog.dll"));
        Assert.AreEqual(3, projected.Files.Count(file => file.Path.EndsWith(".pdb", StringComparison.Ordinal)));
        Assert.IsFalse(File.Exists(System.IO.Path.Combine(final, "packages.lock.json")));
        CollectionAssert.AreEqual(projected.Files.Select(file => file.Path).OrderBy(path => path, StringComparer.Ordinal).ToArray(),
            projected.Files.Select(file => file.Path).ToArray());
        using var testKey = CreateSyntheticKey();
        var signed = TrustedManifestV2Codec.CreateFile(Version, Sequence, projected.Files, testKey);
        new ServiceReleaseV2Verifier().VerifyWithTestKey(final, signed, Version, Sequence,
            testKey.ExportSubjectPublicKeyInfo());
        File.Delete(System.IO.Path.Combine(final, Hosting));
        Assert.ThrowsException<IOException>(() => new ServiceReleaseV2Verifier().VerifyWithTestKey(
            final, signed, Version, Sequence, testKey.ExportSubjectPublicKeyInfo()));
    }

    private static void AssertProjectionClosed(PublishFixture fixture, string? source = null)
    {
        try { new ServiceReleaseV2Projector().Project(source ?? fixture.Source, fixture.Destination,
            fixture.LockSha256, Version, Sequence); }
        catch (Exception error) when (error is IOException or InvalidDataException)
        {
            Assert.IsFalse(Directory.Exists(fixture.Destination));
            return;
        }
        Assert.Fail("Unsafe Service publish was projected.");
    }

    // Deliberately public NIST P-256 generator points with tiny test-only scalars. These
    // synthetic keys must never be used as release keys or enter production source.
    private static ECDsa CreateSyntheticKey(bool wrong = false)
    {
        var scalar = new byte[32];
        scalar[^1] = wrong ? (byte)2 : (byte)1;
        var point = wrong
            ? new ECPoint
            {
                X = Convert.FromHexString("7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978"),
                Y = Convert.FromHexString("07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1")
            }
            : new ECPoint
            {
                X = Convert.FromHexString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
                Y = Convert.FromHexString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
            };
        return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = point, D = scalar });
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(System.IO.Path.Combine(directory.FullName, "global.json")) &&
                File.Exists(System.IO.Path.Combine(directory.FullName, "Vantrel.Security.sln"))) return directory.FullName;
        throw new InvalidOperationException("Repository root unavailable.");
    }

    private sealed class PublishFixture : IDisposable
    {
        private readonly DisposableDirectory _directory = new();
        internal string Source { get; }
        internal string Destination { get; }
        internal string LockSha256 { get; }

        internal PublishFixture()
        {
            Source = System.IO.Path.Combine(_directory.Root, "publish");
            Destination = System.IO.Path.Combine(_directory.Root, "service");
            Directory.CreateDirectory(Source);
            WriteSource(ServicePublishFileSnapshot.DepsFileName, Dependencies);
            WriteSource(ServicePublishFileSnapshot.RuntimeConfigFileName, RuntimeConfig);
            foreach (var path in new[]
            {
                "Vantrel.Security.Service.exe", "Vantrel.Security.Service.dll", "Vantrel.Security.Core.dll",
                "Vantrel.Security.Infrastructure.dll", "Microsoft.Extensions.Hosting.WindowsServices.dll",
                Hosting, "System.ServiceProcess.ServiceController.dll", "appsettings.json"
            }) WriteSource(path, path);
            WriteSource("packages.lock.json", "approved source lock graph");
            LockSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(SourceFile("packages.lock.json"))));
        }

        internal string SourceFile(string relative) => System.IO.Path.Combine(Source, relative.Replace('/', '\\'));
        internal string DestinationFile(string relative) => System.IO.Path.Combine(Destination, relative.Replace('/', '\\'));

        internal void WriteSource(string relative, string content)
        {
            var path = SourceFile(relative);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content, new UTF8Encoding(false));
        }

        internal void WriteDestination(string relative, string content)
        {
            var path = DestinationFile(relative);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content, new UTF8Encoding(false));
        }

        internal ServiceReleaseV2Projection Project() => new ServiceReleaseV2Projector().Project(
            Source, Destination, LockSha256, Version, Sequence);

        public void Dispose() => _directory.Dispose();
    }

    private sealed class DisposableDirectory : IDisposable
    {
        internal string Root { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "vantrel-task072-v2-" + Guid.NewGuid().ToString("N"));

        internal DisposableDirectory() => Directory.CreateDirectory(Root);

        public void Dispose()
        {
            var temp = System.IO.Path.GetFullPath(System.IO.Path.GetTempPath());
            var root = System.IO.Path.GetFullPath(Root);
            if (root.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                System.IO.Path.GetFileName(root).StartsWith("vantrel-task072-v2-", StringComparison.Ordinal) &&
                Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(root, recursive: true);
        }
    }
}
