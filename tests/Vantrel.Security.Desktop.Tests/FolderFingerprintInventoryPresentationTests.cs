using System.Text.RegularExpressions;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class FolderFingerprintInventoryPresentationTests
{
    [TestMethod]
    public void Completed_inventory_shows_only_relative_observed_entry_data()
    {
        var presentation = FolderFingerprintInventoryPresentation.Create(new FolderFingerprintInventoryResult(
            FolderFingerprintInventoryOutcome.Completed,
            [new FolderFingerprintInventoryEntry("sample.bin", FolderFingerprintEntryOutcome.Fingerprinted, 3,
                "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]));

        Assert.AreEqual("Inventory completed; listed files were observed.", presentation.StateText);
        Assert.AreEqual(1, presentation.EntryText.Count);
        Assert.AreEqual("sample.bin — 3 bytes — SHA-256: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", presentation.EntryText[0]);
        Assert.IsFalse(string.Join(' ', presentation.EntryText).Contains("C:\\", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Incomplete_inventory_uses_the_required_scope_statement_and_never_makes_a_security_verdict()
    {
        var presentation = FolderFingerprintInventoryPresentation.Create(new FolderFingerprintInventoryResult(
            FolderFingerprintInventoryOutcome.Incomplete, []));

        Assert.AreEqual("Inventory incomplete; only listed files were observed.", presentation.StateText);
        Assert.IsFalse(Regex.IsMatch(presentation.StateText, "\\b(Verified|Safe|Clean|Trusted|Protected|Malware)\\b", RegexOptions.IgnoreCase));
        Assert.IsTrue(presentation.NoticeText.Contains("does not scan, detect, classify", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Root_failure_drops_all_active_entries()
    {
        var presentation = FolderFingerprintInventoryPresentation.Create(new FolderFingerprintInventoryResult(
            FolderFingerprintInventoryOutcome.Declined,
            [new FolderFingerprintInventoryEntry("should-not-show.bin", FolderFingerprintEntryOutcome.Fingerprinted, 1, "AA")]));

        Assert.AreEqual(0, presentation.EntryText.Count);
    }
}
