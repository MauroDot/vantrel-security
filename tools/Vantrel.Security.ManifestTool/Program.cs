using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;
using Vantrel.Security.ManifestTool;

try
{
    var arguments = args.ToList();
    if (arguments.Count == 0 || arguments[0] is not ("sign" or "verify" or "sign-release-metadata" or "verify-release-metadata"))
        throw new ArgumentException("Use sign, verify, sign-release-metadata, or verify-release-metadata.");
    var command = arguments[0];

    string Required(string name)
    {
        var index = arguments.IndexOf(name);
        if (index < 0 || index + 1 >= arguments.Count) throw new ArgumentException($"Missing {name}.");
        return arguments[index + 1];
    }

    string Optional(string name, string fallback)
    {
        var index = arguments.IndexOf(name);
        if (index < 0) return fallback;
        if (index + 1 >= arguments.Count) throw new ArgumentException($"Missing {name}.");
        return arguments[index + 1];
    }

    var payload = Path.GetFullPath(Required("--payload"));
    if (!Directory.Exists(payload)) throw new DirectoryNotFoundException(payload);
    var manifestPath = Path.Combine(payload, "Vantrel.Security.TrustedManifest");
    var metadataPath = Path.Combine(payload, "Vantrel.Security.ReleaseMetadata");
    var files = ReleasePayloadVerifier.ServiceComponents;

    foreach (var file in files)
        if (!File.Exists(Path.Combine(payload, file.FileName))) throw new FileNotFoundException("Missing payload component.", file.FileName);
    RejectPrivateKeyMaterial(payload);

    byte[] VerifyManifestAndComponents()
    {
        var manifestBytes = File.ReadAllBytes(manifestPath);
        var trustedKey = OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo;
        if (!TrustedManifestCodec.TryParse(manifestBytes, out var manifest, out _)) throw new InvalidDataException("Manifest parse failed.");
        if (!TrustedManifestCodec.Verify(manifest!, trustedKey)) throw new CryptographicException("Manifest signature is invalid.");
        foreach (var file in files)
        {
            var observed = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(payload, file.FileName))));
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(observed), Encoding.ASCII.GetBytes(manifest!.Hashes[file.Component])))
                throw new InvalidDataException("Payload hash mismatch.");
        }
        return manifestBytes;
    }

    void SignTrustedManifest()
    {
        if (File.Exists(manifestPath)) throw new InvalidOperationException("Refusing to overwrite an existing signed manifest.");
        var releaseVersion = CanonicalReleaseVersion.Resolve(Optional("--release-version", CanonicalReleaseVersion.Default));
        var privateKeyPath = Path.GetFullPath(Required("--private-key"));
        var hashes = files.ToDictionary(item => item.Component, item => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(payload, item.FileName)))));
        var canonical = TrustedManifestCodec.CreateCanonicalPayload(releaseVersion, hashes);
        using var signingKey = ImportFixedKey(privateKeyPath, OfflineReleasePublicKeys.TrustedManifestSubjectPublicKeyInfo);
        var signature = signingKey.SignData(canonical, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        File.WriteAllBytes(manifestPath, Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(canonical) + "signature=" + Convert.ToBase64String(signature) + "\n"));
        Console.WriteLine("Signed fixed trusted manifest written.");
    }

    void SignReleaseMetadata()
    {
        if (File.Exists(metadataPath)) throw new InvalidOperationException("Refusing to overwrite existing release metadata.");
        var privateKeyPath = Path.GetFullPath(Required("--private-key"));
        var sequenceText = Required("--release-sequence");
        if (!ulong.TryParse(sequenceText, NumberStyles.None, CultureInfo.InvariantCulture, out var sequence) || sequence == 0)
            throw new ArgumentException("Release sequence must be a positive canonical integer.");
        var displayVersion = Required("--display-version");
        var publishedText = Required("--published-at-utc");
        if (!DateTimeOffset.TryParseExact(publishedText, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var publishedAtUtc) ||
            publishedAtUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture) != publishedText)
            throw new ArgumentException("Published time must be canonical UTC whole-second text.");
        var manifestBytes = VerifyManifestAndComponents();
        var manifestHash = Convert.ToHexString(SHA256.HashData(manifestBytes));
        using var signingKey = ImportFixedKey(privateKeyPath, OfflineReleasePublicKeys.ReleaseMetadataSubjectPublicKeyInfo);
        File.WriteAllBytes(metadataPath, ReleaseMetadataCodec.CreateFile(sequence, manifestHash, displayVersion, publishedAtUtc, signingKey));
        Console.WriteLine("Signed fixed release metadata written.");
    }

    void VerifyReleaseMetadata()
    {
        Vantrel.Security.ManifestTool.ReleasePayloadVerifier.Verify(payload);
        Console.WriteLine("Release metadata signature, manifest binding, and all seven payload hashes verified.");
    }


    switch (command)
    {
        case "sign": SignTrustedManifest(); break;
        case "verify": VerifyManifestAndComponents(); Console.WriteLine("Trusted manifest signature and all seven payload hashes verified."); break;
        case "sign-release-metadata": SignReleaseMetadata(); break;
        case "verify-release-metadata": VerifyReleaseMetadata(); break;
    }
}
catch
{
    Console.Error.WriteLine("Trusted release operation failed.");
    Environment.ExitCode = 1;
}

static ECDsa ImportFixedKey(string privateKeyPath, byte[] expectedPublicKey)
{
    var privateBytes = File.ReadAllBytes(privateKeyPath);
    using var candidate = ECDsa.Create();
    candidate.ImportPkcs8PrivateKey(privateBytes, out var consumed);
    if (consumed != privateBytes.Length || candidate.KeySize != 256 ||
        !CryptographicOperations.FixedTimeEquals(candidate.ExportSubjectPublicKeyInfo(), expectedPublicKey))
        throw new CryptographicException("The external PKCS#8 key does not match the fixed production P-256 public key.");
    var signingKey = ECDsa.Create();
    signingKey.ImportPkcs8PrivateKey(privateBytes, out _);
    return signingKey;
}

static void RejectPrivateKeyMaterial(string payload)
{
    if (Directory.EnumerateFiles(payload).Any(path => Path.GetExtension(path) is ".pem" or ".pfx" or ".pk8" or ".key"))
        throw new InvalidDataException("Private key material must not be in the payload.");
}
