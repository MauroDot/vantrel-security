using System.Text.RegularExpressions;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class FileFingerprintInspectionPresentationTests
{
    [TestMethod]
    public void Completed_presentation_keeps_only_transient_file_name_byte_count_and_fingerprint()
    {
        var presentation = FileFingerprintInspectionPresentation.Create(
            FileFingerprintInspectionResult.Completed("sample.bin", 3,
                "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));

        Assert.IsTrue(presentation.HasCompletedFingerprint);
        Assert.AreEqual("sample.bin", presentation.FileName);
        Assert.AreEqual(3L, presentation.ByteLength);
        Assert.IsFalse(string.Join(' ', presentation.NoticeText, presentation.StateText, presentation.FileName,
            presentation.ByteLength, presentation.Sha256).Contains("C:\\", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Notice_is_explicit_and_no_result_asserts_a_security_or_malware_verdict()
    {
        var unavailable = FileFingerprintInspectionPresentation.Create(
            FileFingerprintInspectionResult.WithoutFile(FileFingerprintInspectionOutcome.Unavailable));

        Assert.AreEqual(
            "File inspection creates a SHA-256 fingerprint. It does not scan, classify, or determine whether a file is safe.",
            unavailable.NoticeText);
        Assert.IsFalse(unavailable.HasCompletedFingerprint);
        Assert.IsFalse(Regex.IsMatch(string.Join(' ', unavailable.NoticeText, unavailable.StateText),
            "\\b(Protected|Clean|Malware|Detection|Remediation|Safe file)\\b", RegexOptions.IgnoreCase));
    }
}
