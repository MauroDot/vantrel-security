using System.Buffers.Binary;
using System.Formats.Asn1;
using Vantrel.Security.ReleaseLayoutTool;

namespace Vantrel.Security.ReleaseLayoutTool.Tests;

[TestClass]
public sealed class ServiceReleaseV2PeByteEquivalenceTests
{
    [TestMethod]
    public void Pe32_and_pe32plus_allow_only_checksum_security_directory_and_one_appended_certificate()
    {
        foreach (var pe32Plus in new[] { false, true })
        foreach (var overlayLength in Enumerable.Range(0, 8))
        {
            var original = Unsigned(pe32Plus, overlayLength);
            var signed = Signed(original, pe32Plus);
            ServiceReleaseV2PeByteEquivalence.RequireAuthenticodeOnlyChange(original, signed);
        }
    }

    [TestMethod]
    public void One_syntactically_valid_SignedData_object_accepts_each_zero_alignment_length()
    {
        var paddingLengths = new HashSet<int>();
        for (var contentLength = 0; contentLength < 64; contentLength++)
        {
            var original = Unsigned(pe32Plus: true, overlayLength: contentLength % 8);
            var pkcs7 = Pkcs7SignedData(contentLength);
            var padding = Align8(8 + pkcs7.Length) - 8 - pkcs7.Length;
            paddingLengths.Add(padding);
            ServiceReleaseV2PeByteEquivalence.RequireAuthenticodeOnlyChange(
                original, Signed(original, pe32Plus: true, contentLength));
        }
        CollectionAssert.AreEquivalent(Enumerable.Range(0, 8).ToArray(),
            paddingLengths.Order().ToArray());
    }

    [TestMethod]
    public void Any_original_section_overlay_or_other_header_mutation_is_rejected()
    {
        var original = Unsigned(pe32Plus: true, overlayLength: 3);
        var signed = Signed(original, pe32Plus: true);
        foreach (var offset in new[] { 20, 0x80 + 8, 420, original.Length - 1 })
        {
            var changed = (byte[])signed.Clone();
            changed[offset] ^= 1;
            Reject(original, changed);
        }
    }

    [TestMethod]
    public void Certificate_must_be_single_well_formed_pkcs7_entry_at_aligned_eof()
    {
        var original = Unsigned(pe32Plus: true, overlayLength: 3);
        var signed = Signed(original, pe32Plus: true);
        var certOffset = Align8(original.Length);
        var directoryOffset = CertificateDirectoryOffset(pe32Plus: true);
        var certificateLength = signed.Length - certOffset;

        var badOffset = (byte[])signed.Clone();
        Write32(badOffset, directoryOffset, (uint)(certOffset - 8));
        Reject(original, badOffset);

        var extraTail = new byte[signed.Length + 1];
        signed.CopyTo(extraTail, 0);
        Reject(original, extraTail);

        var secondEntry = new byte[signed.Length + certificateLength];
        signed.CopyTo(secondEntry, 0);
        signed.AsSpan(certOffset, certificateLength).CopyTo(secondEntry.AsSpan(signed.Length));
        Write32(secondEntry, directoryOffset + 4, (uint)(2 * certificateLength));
        Reject(original, secondEntry);

        var wrongLength = (byte[])signed.Clone();
        Write32(wrongLength, certOffset, 0);
        Reject(original, wrongLength);

        var wrongRevision = (byte[])signed.Clone();
        Write16(wrongRevision, certOffset + 4, 0x0100);
        Reject(original, wrongRevision);

        var wrongType = (byte[])signed.Clone();
        Write16(wrongType, certOffset + 6, 0x0001);
        Reject(original, wrongType);

        var padded = SignedWithPadding(original, pe32Plus: true, minimumPadding: 1);
        var nonzeroCertificatePadding = (byte[])padded.Clone();
        nonzeroCertificatePadding[^1] = 1;
        Reject(original, nonzeroCertificatePadding);

        var nonzeroAlignmentPadding = (byte[])signed.Clone();
        nonzeroAlignmentPadding[original.Length] = 1;
        Reject(original, nonzeroAlignmentPadding);

        var wrongDirectorySize = (byte[])signed.Clone();
        Write32(wrongDirectorySize, directoryOffset + 4, (uint)(certificateLength - 8));
        Reject(original, wrongDirectorySize);

        var malformedLength = (byte[])signed.Clone();
        malformedLength[certOffset + 9] = 0xFF;
        Reject(original, malformedLength);

        var malformedNestedLength = (byte[])signed.Clone();
        var octetString = FindBytes(malformedNestedLength,
            certOffset + 8, [0x04, 0x00]);
        malformedNestedLength[octetString + 1] = 0x7F;
        Reject(original, malformedNestedLength);

        var truncatedPkcs7 = (byte[])signed.Clone();
        truncatedPkcs7[certOffset + 9] = 0x7F;
        Reject(original, truncatedPkcs7);

        var impossibleLength = (byte[])signed.Clone();
        Write32(impossibleLength, certOffset, uint.MaxValue);
        Reject(original, impossibleLength);

        var impossibleDirectorySize = (byte[])signed.Clone();
        Write32(impossibleDirectorySize, directoryOffset + 4, uint.MaxValue);
        Reject(original, impossibleDirectorySize);
    }

    [TestMethod]
    public void Enlarged_dwLength_cannot_hide_nonzero_content_after_the_PKCS7_object()
    {
        var original = Unsigned(pe32Plus: true, overlayLength: 3);
        var signed = SignedWithPadding(original, pe32Plus: true, minimumPadding: 1);
        var certOffset = Align8(original.Length);
        var objectLength = Pkcs7ObjectLength(signed, certOffset);
        var alignedEntryLength = signed.Length - certOffset;

        // This reproduces the reviewed bypass: the old comparator accepted a larger
        // dwLength and checked only bytes after it, leaving nonzero slack inside it.
        var shorter = (byte[])signed.Clone();
        Write32(shorter, certOffset, (uint)(8 + objectLength));
        var enlarged = (byte[])shorter.Clone();
        Write32(enlarged, certOffset, (uint)alignedEntryLength);
        enlarged[certOffset + 8 + objectLength] = 0xA5;
        Reject(original, enlarged);
    }

    [TestMethod]
    public void Second_Asn1_object_and_certificate_overlay_are_rejected()
    {
        var original = Unsigned(pe32Plus: true, overlayLength: 0);
        var signed = SignedWithPadding(original, pe32Plus: true, minimumPadding: 2);
        var certOffset = Align8(original.Length);
        var objectEnd = certOffset + 8 + Pkcs7ObjectLength(signed, certOffset);

        var secondObject = (byte[])signed.Clone();
        secondObject[objectEnd] = 0x05; // ASN.1 NULL, followed by its zero length.
        secondObject[objectEnd + 1] = 0;
        Reject(original, secondObject);

        var overlay = new byte[signed.Length + 8];
        signed.CopyTo(overlay, 0);
        Reject(original, overlay);
    }

    [TestMethod]
    public void Existing_certificate_directory_or_invalid_pe_structure_is_rejected()
    {
        var original = Unsigned(pe32Plus: true, overlayLength: 0);
        var signed = Signed(original, pe32Plus: true);
        var directoryOffset = CertificateDirectoryOffset(pe32Plus: true);

        var presignedOriginal = (byte[])original.Clone();
        Write32(presignedOriginal, directoryOffset, 512);
        Reject(presignedOriginal, signed);

        var badDos = (byte[])original.Clone();
        badDos[0] = 0;
        Reject(badDos, signed);

        var badPeOffset = (byte[])original.Clone();
        Write32(badPeOffset, 0x3C, uint.MaxValue);
        Reject(badPeOffset, signed);

        var truncatedSection = (byte[])original.Clone();
        Write32(truncatedSection, SectionHeaderOffset(pe32Plus: true) + 16, 512);
        Reject(truncatedSection, signed);

        var missingSecurityDirectory = (byte[])original.Clone();
        Write32(missingSecurityDirectory, NumberOfDirectoriesOffset(pe32Plus: true), 4);
        Reject(missingSecurityDirectory, signed);
    }

    private static void Reject(byte[] original, byte[] signed) =>
        Assert.ThrowsException<IOException>(() =>
            ServiceReleaseV2PeByteEquivalence.RequireAuthenticodeOnlyChange(original, signed));

    internal static byte[] Unsigned(bool pe32Plus, int overlayLength)
    {
        var bytes = new byte[512 + overlayLength];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        Write32(bytes, 0x3C, 0x80);
        bytes[0x80] = (byte)'P';
        bytes[0x81] = (byte)'E';
        Write16(bytes, 0x84, pe32Plus ? (ushort)0x8664 : (ushort)0x014C);
        Write16(bytes, 0x86, 1);
        Write16(bytes, 0x94, pe32Plus ? (ushort)240 : (ushort)224);
        Write16(bytes, 0x98, pe32Plus ? (ushort)0x20B : (ushort)0x10B);
        Write32(bytes, NumberOfDirectoriesOffset(pe32Plus), 16);
        Write32(bytes, SectionHeaderOffset(pe32Plus) + 16, 64);
        Write32(bytes, SectionHeaderOffset(pe32Plus) + 20, 416);
        for (var index = 416; index < 480; index++) bytes[index] = (byte)(index * 31);
        for (var index = 512; index < bytes.Length; index++) bytes[index] = (byte)(index * 17);
        return bytes;
    }

    internal static byte[] Signed(byte[] original, bool pe32Plus, int contentLength = 0)
    {
        var pkcs7 = Pkcs7SignedData(contentLength);
        var certificateOffset = Align8(original.Length);
        var certificateLength = Align8(8 + pkcs7.Length);
        var bytes = new byte[certificateOffset + certificateLength];
        original.CopyTo(bytes, 0);
        Write32(bytes, 0x98 + 64, 0x12345678);
        var directoryOffset = CertificateDirectoryOffset(pe32Plus);
        Write32(bytes, directoryOffset, (uint)certificateOffset);
        Write32(bytes, directoryOffset + 4, (uint)certificateLength);
        Write32(bytes, certificateOffset, (uint)certificateLength);
        Write16(bytes, certificateOffset + 4, 0x0200);
        Write16(bytes, certificateOffset + 6, 0x0002);
        pkcs7.CopyTo(bytes, certificateOffset + 8);
        return bytes;
    }

    private static byte[] SignedWithPadding(byte[] original, bool pe32Plus, int minimumPadding)
    {
        for (var length = 0; length < 64; length++)
        {
            var cms = Pkcs7SignedData(length);
            if (Align8(8 + cms.Length) - 8 - cms.Length >= minimumPadding)
                return Signed(original, pe32Plus, length);
        }
        throw new AssertFailedException("Could not construct synthetic alignment padding.");
    }

    private static int Pkcs7ObjectLength(byte[] signed, int certificateOffset)
    {
        AsnDecoder.ReadEncodedValue(signed.AsSpan(certificateOffset + 8),
            AsnEncodingRules.BER, out _, out _, out var length);
        return length;
    }

    private static int FindBytes(byte[] source, int start, byte[] expected)
    {
        for (var index = start; index <= source.Length - expected.Length; index++)
            if (source.AsSpan(index, expected.Length).SequenceEqual(expected)) return index;
        throw new AssertFailedException("Missing synthetic ASN.1 test element.");
    }

    private static byte[] Pkcs7SignedData(int contentLength)
    {
        // This is a syntactically valid CMS SignedData envelope with no signer. It tests
        // byte equivalence only; it is deliberately not an Authenticode trust fixture.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
        var explicitTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        writer.PushSequence(explicitTag);
        writer.PushSequence();
        writer.WriteInteger(1);
        writer.PushSetOf();
        writer.PopSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.7.1");
        writer.PushSequence(explicitTag);
        writer.WriteOctetString(new byte[contentLength]);
        writer.PopSequence(explicitTag);
        writer.PopSequence();
        writer.PushSetOf();
        writer.PopSetOf();
        writer.PopSequence();
        writer.PopSequence(explicitTag);
        writer.PopSequence();
        return writer.Encode();
    }

    private static int Align8(int length) => (length + 7) & ~7;
    private static int CertificateDirectoryOffset(bool pe32Plus) => 0x98 + (pe32Plus ? 144 : 128);
    private static int NumberOfDirectoriesOffset(bool pe32Plus) => 0x98 + (pe32Plus ? 108 : 92);
    private static int SectionHeaderOffset(bool pe32Plus) => 0x98 + (pe32Plus ? 240 : 224);
    private static void Write16(byte[] bytes, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset, 2), value);
    private static void Write32(byte[] bytes, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset, 4), value);
}
