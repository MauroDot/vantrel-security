using System.Text.RegularExpressions;

namespace Vantrel.Security.ManifestTool;

/// <summary>Canonical build-time release version contract shared with beta release descriptors.</summary>
public static partial class CanonicalReleaseVersion
{
    public const string Default = "0.1.0";

    public static string Resolve(string? value)
    {
        var resolved = value ?? Default;
        if (!IsValid(resolved)) throw new ArgumentException("Release version is not canonical.", nameof(value));
        return resolved;
    }

    public static bool IsValid(string? value) => value is { Length: > 0 and <= 64 } && VersionPattern().IsMatch(value);

    [GeneratedRegex("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\\.[0-9A-Za-z]+)*)?$")]
    private static partial Regex VersionPattern();
}
