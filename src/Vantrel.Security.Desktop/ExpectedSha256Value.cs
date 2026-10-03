namespace Vantrel.Security.Desktop;

internal readonly record struct ExpectedSha256Value
{
    private ExpectedSha256Value(string value) => Value = value;

    internal string Value { get; }

    internal static bool TryParse(string? value, out ExpectedSha256Value expected)
    {
        expected = default;
        if (value is null || value.Length != 64) return false;
        foreach (var character in value)
        {
            if ((character is < '0' or > '9') &&
                (character is < 'A' or > 'F') &&
                (character is < 'a' or > 'f'))
            {
                return false;
            }
        }

        expected = new ExpectedSha256Value(value);
        return true;
    }

    internal bool Matches(string computedSha256) =>
        string.Equals(Value, computedSha256, StringComparison.OrdinalIgnoreCase);
}
