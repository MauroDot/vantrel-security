using System.Text.RegularExpressions;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class FileFingerprintComparisonPresentationTests
{
    [TestMethod]
    public void Match_and_mismatch_use_only_the_required_truthful_outcomes()
    {
        Assert.AreEqual("Fingerprint matches the value you supplied.",
            FileFingerprintComparisonPresentation.Create(FileFingerprintComparisonResult.From(FileFingerprintComparisonOutcome.Match)).StateText);
        Assert.AreEqual("Fingerprint does not match the value you supplied.",
            FileFingerprintComparisonPresentation.Create(FileFingerprintComparisonResult.From(FileFingerprintComparisonOutcome.Mismatch)).StateText);
    }

    [TestMethod]
    public void Presentation_retains_no_path_hash_or_supplied_value_and_makes_no_security_verdict()
    {
        var presentation = FileFingerprintComparisonPresentation.Create(
            FileFingerprintComparisonResult.From(FileFingerprintComparisonOutcome.Mismatch));
        var text = string.Join(' ', presentation.NoticeText, presentation.StateText);

        Assert.IsFalse(text.Contains("C:\\", StringComparison.Ordinal));
        Assert.IsFalse(Regex.IsMatch(text, "[0-9A-Fa-f]{64}"));
        Assert.IsFalse(Regex.IsMatch(presentation.StateText, "\\b(Protected|Clean|Trusted|Malware|Safe)\\b", RegexOptions.IgnoreCase));
    }
}
