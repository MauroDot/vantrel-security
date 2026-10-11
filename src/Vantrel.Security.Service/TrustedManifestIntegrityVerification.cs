using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

public sealed partial class TrustedManifestIntegritySource
{
    // Internal per-instance seams let dispatch tests observe the selected verifier.
    // Production instances retain the strict generation-specific codec defaults.
    internal Func<TrustedManifest, byte[], bool> VerifyV1Signature { get; init; } =
        static (manifest, key) => TrustedManifestCodec.Verify(manifest, key);

    internal Func<TrustedManifestV2, byte[], bool> VerifyV2Signature { get; init; } =
        static (manifest, key) => TrustedManifestV2Codec.Verify(manifest, key);
}
