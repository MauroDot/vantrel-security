using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;

try
{
    const string TrustedManifestPublicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQB/yA4nU8K0EkKlqELYb3Udxsek/UWTa/8VqNeLQj+brJ4dHCB/0LaJAPdrK5tLICfT4XrBZFJkJEtEEiHj9BQ==";
    const string ReleaseMetadataPublicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErjlbxAQm0yHNOBzbAQ2JMsT3R+fEbwEi+D8BM90klSrAfqhSf4SkJ5b8Y9oFbiItIeoDlRSZsAHD/EchoRgkLw==";
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

    var payload = Path.GetFullPath(Required("--payload"));
    if (!Directory.Exists(payload)) throw new DirectoryNotFoundException(payload);
    var manifestPath = Path.Combine(payload, "Vantrel.Security.TrustedManifest");
    var metadataPath = Path.Combine(payload, "Vantrel.Security.ReleaseMetadata");
    var files = new (TrustedManifestComponent Component, string FileName)[]
    {
        (TrustedManifestComponent.ServiceExe, "Vantrel.Security.Service.exe"),
        (TrustedManifestComponent.ServiceAssembly, "Vantrel.Security.Service.dll"),
        (TrustedManifestComponent.InfrastructureAssembly, "Vantrel.Security.Infrastructure.dll"),
        (TrustedManifestComponent.CoreAssembly, "Vantrel.Security.Core.dll"),
        (TrustedManifestComponent.Deps, "Vantrel.Security.Service.deps.json"),
        (TrustedManifestComponent.RuntimeConfig, "Vantrel.Security.Service.runtimeconfig.json"),
        (TrustedManifestComponent.EventLogResource, "System.Diagnostics.EventLog.Messages.dll")
    };

    foreach (var (_, name) in files)
        if (!File.Exists(Path.Combine(payload, name))) throw new FileNotFoundException("Missing payload component.", name);
    RejectPrivateKeyMaterial(payload);

    byte[] VerifyManifestAndComponents()
    {
        var manifestBytes = File.ReadAllBytes(manifestPath);
        var trustedKey = Convert.FromBase64String(TrustedManifestPublicKeyBase64);
        if (!TrustedManifestCodec.TryParse(manifestBytes, out var manifest, out _)) throw new InvalidDataException("Manifest parse failed.");
        if (!TrustedManifestCodec.Verify(manifest!, trustedKey)) throw new CryptographicException("Manifest signature is invalid.");
        foreach (var (component, name) in files)
        {
            var observed = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(payload, name))));
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(observed), Encoding.ASCII.GetBytes(manifest!.Hashes[component])))
                throw new InvalidDataException("Payload hash mismatch.");
        }
        return manifestBytes;
    }

    void SignTrustedManifest()
    {
        if (File.Exists(manifestPath)) throw new InvalidOperationException("Refusing to overwrite an existing signed manifest.");
        var privateKeyPath = Path.GetFullPath(Required("--private-key"));
        var hashes = files.ToDictionary(item => item.Component, item => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(payload, item.FileName)))));
        var canonical = TrustedManifestCodec.CreateCanonicalPayload("0.1.0", hashes);
        using var signingKey = ImportFixedKey(privateKeyPath, Convert.FromBase64String(TrustedManifestPublicKeyBase64));
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
        using var signingKey = ImportFixedKey(privateKeyPath, Convert.FromBase64String(ReleaseMetadataPublicKeyBase64));
        File.WriteAllBytes(metadataPath, ReleaseMetadataCodec.CreateFile(sequence, manifestHash, displayVersion, publishedAtUtc, signingKey));
        Console.WriteLine("Signed fixed release metadata written.");
    }

    void VerifyReleaseMetadata()
    {
        VerifyExactReleaseSet();
        var manifestBytes = VerifyManifestAndComponents();
        var metadataBytes = File.ReadAllBytes(metadataPath);
        if (!ReleaseMetadataCodec.TryParse(metadataBytes, out var metadata, out _)) throw new InvalidDataException("Release metadata parse failed.");
        if (!ReleaseMetadataCodec.Verify(metadata!, Convert.FromBase64String(ReleaseMetadataPublicKeyBase64)))
            throw new CryptographicException("Release metadata signature is invalid.");
        var manifestHash = Convert.ToHexString(SHA256.HashData(manifestBytes));
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(manifestHash), Encoding.ASCII.GetBytes(metadata!.ManifestSha256)))
            throw new InvalidDataException("Release metadata manifest binding is invalid.");
        Console.WriteLine("Release metadata signature, manifest binding, and all seven payload hashes verified.");
    }

    void VerifyExactReleaseSet()
    {
        var required = files.Select(item => item.FileName)
            .Append("Vantrel.Security.TrustedManifest")
            .Append("Vantrel.Security.ReleaseMetadata")
            .ToHashSet(StringComparer.Ordinal);
        if ((File.GetAttributes(payload) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Release payload root must not be a reparse point.");
        var entries = Directory.EnumerateFileSystemEntries(payload).ToArray();
        if (entries.Length != required.Count || entries.Any(path =>
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 ||
            !File.Exists(path) || !required.Remove(Path.GetFileName(path))))
            throw new InvalidDataException("Release payload must contain exactly the fixed signed service release files.");
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
