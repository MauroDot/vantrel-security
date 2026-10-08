namespace Vantrel.Security.Core;

/// <summary>Separate fixed public roots for fresh-start offline release evidence.</summary>
public static class OfflineReleasePublicKeys
{
    private const string TrustedManifestSpkiBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEig5PJkX4MBkELOAmA1ma0/lM8EWdnb0kn5ihu5mt1zAViAH6F/+w7eZHrvn8iV+zd96iFliY8NaPaekcH2g2Rw==";
    private const string ReleaseMetadataSpkiBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEG0xq6x1KNmoUiNfwxiPThVFNuJp91HMYpPtLIs0GOXirfcX9ubbxaq3ZMvBBUmAp+LNWuE5QFzITAU/OPKe78A==";

    // Each access returns a new array so callers cannot change a shared verifier key.
    public static byte[] TrustedManifestSubjectPublicKeyInfo => Convert.FromBase64String(TrustedManifestSpkiBase64);
    public static byte[] ReleaseMetadataSubjectPublicKeyInfo => Convert.FromBase64String(ReleaseMetadataSpkiBase64);
}