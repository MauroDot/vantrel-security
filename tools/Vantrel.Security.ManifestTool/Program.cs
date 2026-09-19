using System.Security.Cryptography;
using System.Text;
using Vantrel.Security.Core;

try
{
const string ProductionPublicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQB/yA4nU8K0EkKlqELYb3Udxsek/UWTa/8VqNeLQj+brJ4dHCB/0LaJAPdrK5tLICfT4XrBZFJkJEtEEiHj9BQ==";
var arguments = args.ToList();
if (arguments.Count == 0 || arguments[0] is not ("sign" or "verify")) throw new ArgumentException("Use sign or verify.");
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
foreach (var (_, name) in files) if (!File.Exists(Path.Combine(payload, name))) throw new FileNotFoundException("Missing payload component.", name);
var publicKey = Convert.FromBase64String(ProductionPublicKeyBase64);

if (command == "sign")
{
    if (File.Exists(manifestPath)) throw new InvalidOperationException("Refusing to overwrite an existing signed manifest.");
    var privateKeyPath = Path.GetFullPath(Required("--private-key"));
    var hashes = files.ToDictionary(item => item.Component, item => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(payload, item.FileName)))));
    var canonical = TrustedManifestCodec.CreateCanonicalPayload("0.1.0", hashes);
    using var signingKey = ECDsa.Create();
    signingKey.ImportPkcs8PrivateKey(File.ReadAllBytes(privateKeyPath), out var consumed);
    if (consumed != new FileInfo(privateKeyPath).Length || signingKey.KeySize != 256 || !CryptographicOperations.FixedTimeEquals(signingKey.ExportSubjectPublicKeyInfo(), publicKey))
        throw new CryptographicException("The external PKCS#8 key is not the fixed production P-256 key.");
    var signature = signingKey.SignData(canonical, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    File.WriteAllBytes(manifestPath, Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(canonical) + "signature=" + Convert.ToBase64String(signature) + "\n"));
    Console.WriteLine("Signed fixed trusted manifest written.");
}
else
{
    var manifestBytes = File.ReadAllBytes(manifestPath);
    if (!TrustedManifestCodec.TryParse(manifestBytes, out var manifest, out var failure)) throw new InvalidDataException($"Manifest parse failed: {failure}.");
    if (!TrustedManifestCodec.Verify(manifest!, publicKey)) throw new CryptographicException("Manifest signature is invalid.");
    foreach (var (component, name) in files)
    {
        var observed = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(payload, name))));
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(observed), Encoding.ASCII.GetBytes(manifest!.Hashes[component])))
            throw new InvalidDataException($"Payload hash mismatch: {name}.");
    }
    if (Directory.EnumerateFiles(payload).Any(path => Path.GetExtension(path) is ".pem" or ".pfx" or ".pk8" or ".key")) throw new InvalidDataException("Private key material must not be in the payload.");
    Console.WriteLine("Trusted manifest signature and all seven payload hashes verified.");
}
}
catch
{
    Console.Error.WriteLine("Trusted manifest operation failed.");
    Environment.ExitCode = 1;
}
