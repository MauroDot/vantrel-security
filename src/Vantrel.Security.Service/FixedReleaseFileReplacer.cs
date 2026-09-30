using System.Security.Cryptography;
using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>Fixed nine-file Program Files replacement primitive. It is invoked only by the offline transaction engine after SCM stop.</summary>
internal sealed class FixedReleaseFileReplacer
{
    internal async Task ReplaceFromPrivateCandidateAsync(string transactionId, CancellationToken token) =>
        await ReplaceExactAsync(new OfflineUpdateStorage().PrivateCandidate(transactionId), FixedUpdatePaths.InstalledServiceRoot, token);

    internal async Task RestoreFromBackupAsync(string backupId, CancellationToken token) =>
        await ReplaceExactAsync(new OfflineUpdateStorage().Backup(backupId), FixedUpdatePaths.InstalledServiceRoot, token);

    internal static async Task ReplaceExactAsync(string verifiedSource, string installedRoot, CancellationToken token)
    {
        OfflineReleaseVerifier.ValidateExactSet(verifiedSource);
        installedRoot = Path.GetFullPath(installedRoot); RejectReparse(installedRoot);
        foreach (var name in FixedServiceReleaseFiles.AllNames)
        {
            token.ThrowIfCancellationRequested();
            var source = Path.Combine(verifiedSource, name); var destination = Path.Combine(installedRoot, name);
            Contained(verifiedSource, source); Contained(installedRoot, destination); RejectReparse(source); RejectReparse(destination);
            var expected = await HashAsync(source, token);
            if (string.Equals(expected, await HashAsync(destination, token), StringComparison.Ordinal)) continue;
            var temporary = Path.Combine(installedRoot, ".vantrel-update-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                await CopyAndFlushAsync(source, temporary, token); RejectReparse(temporary);
                if (!string.Equals(expected, await HashAsync(temporary, token), StringComparison.Ordinal)) throw new IOException("Fixed replacement temporary hash mismatch.");
                File.Replace(temporary, destination, null); RejectReparse(destination);
                if (!string.Equals(expected, await HashAsync(destination, token), StringComparison.Ordinal)) throw new IOException("Fixed replacement final hash mismatch.");
            }
            finally { if (File.Exists(temporary)) { try { RejectReparse(temporary); File.Delete(temporary); } catch { } } }
        }
    }
    private static async Task CopyAndFlushAsync(string source, string destination, CancellationToken token)
    {
        await using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough);
        await input.CopyToAsync(output, 65536, token); await output.FlushAsync(token); output.Flush(flushToDisk: true);
    }
    private static async Task<string> HashAsync(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = new byte[65536]; int read;
        while ((read = await stream.ReadAsync(buffer, token)) != 0) hash.AppendData(buffer, 0, read);
        return Convert.ToHexString(hash.GetHashAndReset());
    }
    private static void Contained(string root, string path)
    {
        root = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!Path.GetFullPath(path).StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new IOException("Fixed release containment rejected.");
    }
    private static void RejectReparse(string path) { if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Fixed release reparse point rejected."); }
}