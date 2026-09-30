using System.Security.Cryptography;
using Vantrel.Security.Core;
using Vantrel.Security.Service;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class FixedReleaseFileReplacerTests
{
    [DataTestMethod]
    [DataRow(1)]
    [DataRow(4)]
    [DataRow(8)]
    [DataRow(9)]
    public async Task Mixed_nine_file_installation_is_restored_as_complete_verified_predecessor(int changedCount)
    {
        await using var scope = new ReleaseScope();
        await scope.WriteReleaseAsync(scope.Installed, "prior");
        await scope.WriteReleaseAsync(scope.Backup, "prior");
        await scope.WriteReleaseAsync(scope.Target, "target");
        foreach (var name in FixedServiceReleaseFiles.AllNames.Take(changedCount))
            File.Copy(Path.Combine(scope.Target, name), Path.Combine(scope.Installed, name), true);

        await FixedReleaseFileReplacer.ReplaceExactAsync(scope.Backup, scope.Installed, CancellationToken.None);
        foreach (var name in FixedServiceReleaseFiles.AllNames)
            Assert.AreEqual(await HashAsync(Path.Combine(scope.Backup, name)), await HashAsync(Path.Combine(scope.Installed, name)), name);
        OfflineReleaseVerifier.ValidateExactSet(scope.Installed);

        // A second recovery pass is idempotent and does not merge target content back in.
        await FixedReleaseFileReplacer.ReplaceExactAsync(scope.Backup, scope.Installed, CancellationToken.None);
        foreach (var name in FixedServiceReleaseFiles.AllNames)
            Assert.AreEqual(await HashAsync(Path.Combine(scope.Backup, name)), await HashAsync(Path.Combine(scope.Installed, name)), name);
    }

    [TestMethod]
    public async Task Fixed_replacer_preserves_unchanged_locked_file_and_rejects_fixed_set_escape()
    {
        await using var scope = new ReleaseScope();
        await scope.WriteReleaseAsync(scope.Installed, "prior");
        await scope.WriteReleaseAsync(scope.Backup, "prior");
        using var locked = new FileStream(Path.Combine(scope.Installed, FixedServiceReleaseFiles.AllNames[0]), FileMode.Open, FileAccess.Read, FileShare.Read);
        await FixedReleaseFileReplacer.ReplaceExactAsync(scope.Backup, scope.Installed, CancellationToken.None);
        await File.WriteAllTextAsync(Path.Combine(scope.Backup, "extra"), "x");
        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => FixedReleaseFileReplacer.ReplaceExactAsync(scope.Backup, scope.Installed, CancellationToken.None));
    }

    private static async Task<string> HashAsync(string path) { await using var stream = File.OpenRead(path); return Convert.ToHexString(await SHA256.HashDataAsync(stream)); }
    private sealed class ReleaseScope : IAsyncDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "kestermere-task016-" + Guid.NewGuid().ToString("N"));
        internal string Installed => Path.Combine(Root, "installed"); internal string Backup => Path.Combine(Root, "backup"); internal string Target => Path.Combine(Root, "target");
        internal async Task WriteReleaseAsync(string root, string value)
        {
            Directory.CreateDirectory(root);
            foreach (var name in FixedServiceReleaseFiles.AllNames) await File.WriteAllTextAsync(Path.Combine(root, name), value + name);
        }
        public ValueTask DisposeAsync() { if (Directory.Exists(Root)) Directory.Delete(Root, true); return ValueTask.CompletedTask; }
    }
}
