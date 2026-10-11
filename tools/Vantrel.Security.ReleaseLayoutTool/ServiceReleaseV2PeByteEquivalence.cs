using System.Buffers.Binary;
using System.Formats.Asn1;

namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>
/// Compares a deterministic unsigned publish PE with its signed counterpart. This is an
/// additional source-byte binding, not a signature verifier: the caller must still require
/// WinTrust, the exact publisher policy, digest, and timestamp on the final signed handle.
/// </summary>
internal static class ServiceReleaseV2PeByteEquivalence
{
    private const string Invalid = "Signed Service PE does not match the deterministic publish.";
    private const ushort Pe32 = 0x10B;
    private const ushort Pe32Plus = 0x20B;
    private const ushort WinCertificateRevision20 = 0x0200;
    private const ushort WinCertificateTypePkcsSignedData = 0x0002;
    private const string SignedDataOid = "1.2.840.113549.1.7.2";
    private const int MaximumCertificateBytes = 16 * 1024 * 1024;
    private const int MaximumAsnDepth = 64;
    private const int MaximumAsnElements = 100_000;

    internal static void RequireAuthenticodeOnlyChange(
        ReadOnlySpan<byte> unsignedBytes, ReadOnlySpan<byte> signedBytes)
    {
        if (!TryHeaders(unsignedBytes, out var source) ||
            !TryHeaders(signedBytes, out var signed) ||
            source.ChecksumOffset != signed.ChecksumOffset ||
            source.CertificateDirectoryOffset != signed.CertificateDirectoryOffset ||
            source.CertificateOffset != 0 || source.CertificateSize != 0 ||
            signed.CertificateOffset == 0 || signed.CertificateSize == 0 ||
            signedBytes.Length <= unsignedBytes.Length)
            throw new IOException(Invalid);

        // A signer may append a certificate table after at most seven zero alignment bytes.
        // It may not change any original byte apart from the documented PE checksum and
        // Certificate Table data-directory entry. Comparing the complete original file also
        // binds overlays, debug data, and every section byte omitted by an Authenticode hash.
        var expectedCertificateOffset = ((ulong)unsignedBytes.Length + 7UL) & ~7UL;
        if (signed.CertificateOffset != expectedCertificateOffset ||
            expectedCertificateOffset + signed.CertificateSize != (ulong)signedBytes.Length)
            throw new IOException(Invalid);

        for (var index = 0; index < unsignedBytes.Length; index++)
        {
            if (IsMutableHeaderByte(index, source)) continue;
            if (unsignedBytes[index] != signedBytes[index]) throw new IOException(Invalid);
        }

        for (var index = unsignedBytes.Length; (ulong)index < expectedCertificateOffset; index++)
        {
            if (signedBytes[index] != 0) throw new IOException(Invalid);
        }

        var certificate = signedBytes.Slice((int)signed.CertificateOffset, (int)signed.CertificateSize);
        if (certificate.Length < 16 || certificate.Length > MaximumCertificateBytes ||
            (certificate.Length & 7) != 0 ||
            !TryReadUInt32(certificate, 0, out var entryLength) ||
            entryLength != certificate.Length ||
            !TryReadUInt16(certificate, 4, out var revision) ||
            revision != WinCertificateRevision20 ||
            !TryReadUInt16(certificate, 6, out var type) ||
            type != WinCertificateTypePkcsSignedData)
            throw new IOException(Invalid);

        var pkcs7 = certificate[8..];
        var encodedLength = RequireOneSignedDataObject(pkcs7);
        // dwLength includes the quadword alignment padding. Its size is entirely fixed by
        // the encoded object, so enlarging dwLength cannot authorize another entry, ASN.1
        // object, or opaque data after a valid signature.
        if (certificate.Length != ((8 + encodedLength + 7) & ~7))
            throw new IOException(Invalid);
        for (var index = encodedLength; index < pkcs7.Length; index++)
        {
            if (pkcs7[index] != 0) throw new IOException(Invalid);
        }
    }

    private static int RequireOneSignedDataObject(ReadOnlySpan<byte> pkcs7)
    {
        try
        {
            var tag = AsnDecoder.ReadEncodedValue(pkcs7, AsnEncodingRules.BER,
                out _, out _, out var encodedLength);
            if (!tag.HasSameClassAndValue(Asn1Tag.Sequence) || !tag.IsConstructed ||
                encodedLength <= 0)
                throw new IOException(Invalid);

            // ReadEncodedValue establishes the exact ASN.1 boundary, but by itself does
            // not inspect the contents of definite-length constructed values. Validate the
            // whole bounded encoding before checking the SignedData field order and OID.
            var elementCount = 0;
            RequireWellFormedAsnTree(pkcs7[..encodedLength], 0, ref elementCount);
            var reader = new AsnReader(pkcs7[..encodedLength].ToArray(), AsnEncodingRules.BER);
            var contentInfo = reader.ReadSequence();
            if (contentInfo.ReadObjectIdentifier() != SignedDataOid)
                throw new IOException(Invalid);
            var explicitContent = contentInfo.ReadSequence(
                new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
            var signedData = explicitContent.ReadSequence();
            if (!signedData.TryReadInt32(out var version) || version < 1 || version > 5)
                throw new IOException(Invalid);
            var algorithms = signedData.ReadSetOf();
            while (algorithms.HasData)
            {
                var algorithm = algorithms.ReadSequence();
                _ = algorithm.ReadObjectIdentifier();
                if (algorithm.HasData) _ = algorithm.ReadEncodedValue();
                algorithm.ThrowIfNotEmpty();
            }
            var encapsulated = signedData.ReadSequence();
            _ = encapsulated.ReadObjectIdentifier();
            if (encapsulated.HasData)
            {
                var content = encapsulated.ReadSequence(
                    new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
                _ = content.ReadEncodedValue();
                content.ThrowIfNotEmpty();
            }
            encapsulated.ThrowIfNotEmpty();
            if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(
                    new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                var certificates = signedData.ReadSetOf(
                    new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
                while (certificates.HasData) _ = certificates.ReadEncodedValue();
            }
            if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(
                    new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                var revocations = signedData.ReadSetOf(
                    new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
                while (revocations.HasData) _ = revocations.ReadEncodedValue();
            }
            var signers = signedData.ReadSetOf();
            while (signers.HasData)
            {
                var signer = signers.ReadSequence();
                while (signer.HasData) _ = signer.ReadEncodedValue();
            }
            signedData.ThrowIfNotEmpty();
            explicitContent.ThrowIfNotEmpty();
            contentInfo.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            return encodedLength;
        }
        catch (AsnContentException)
        {
            throw new IOException(Invalid);
        }
    }

    private static void RequireWellFormedAsnTree(ReadOnlySpan<byte> values, int depth,
        ref int elementCount)
    {
        if (depth > MaximumAsnDepth) throw new IOException(Invalid);
        while (!values.IsEmpty)
        {
            var tag = AsnDecoder.ReadEncodedValue(values, AsnEncodingRules.BER,
                out var contentOffset, out var contentLength, out var consumed);
            if (consumed <= 0 || ++elementCount > MaximumAsnElements)
                throw new IOException(Invalid);
            if (tag.IsConstructed)
                RequireWellFormedAsnTree(values.Slice(contentOffset, contentLength),
                    depth + 1, ref elementCount);
            values = values[consumed..];
        }
    }

    private static bool IsMutableHeaderByte(int offset, Header header) =>
        (offset >= header.ChecksumOffset && offset < header.ChecksumOffset + 4) ||
        (offset >= header.CertificateDirectoryOffset &&
         offset < header.CertificateDirectoryOffset + 8);

    private static bool TryHeaders(ReadOnlySpan<byte> bytes, out Header header)
    {
        header = default;
        if (bytes.Length < 0x40 || bytes[0] != (byte)'M' || bytes[1] != (byte)'Z' ||
            !TryReadUInt32(bytes, 0x3C, out var peOffsetValue) ||
            peOffsetValue > int.MaxValue) return false;

        var peOffset = (int)peOffsetValue;
        if (!Contains(bytes, peOffset, 24) ||
            bytes[peOffset] != (byte)'P' || bytes[peOffset + 1] != (byte)'E' ||
            bytes[peOffset + 2] != 0 || bytes[peOffset + 3] != 0 ||
            !TryReadUInt16(bytes, peOffset + 6, out var sectionCount) ||
            sectionCount == 0 ||
            !TryReadUInt16(bytes, peOffset + 20, out var optionalSize)) return false;

        var optional = peOffset + 24;
        if (!Contains(bytes, optional, optionalSize) ||
            !TryReadUInt16(bytes, optional, out var magic)) return false;
        var isPe32 = magic == Pe32;
        if (!isPe32 && magic != Pe32Plus) return false;
        var directoryOffset = optional + (isPe32 ? 96 : 112);
        var numberOfDirectoriesOffset = optional + (isPe32 ? 92 : 108);
        var certificateDirectoryOffset = directoryOffset + 4 * 8;
        var checksumOffset = optional + 64;
        if (!Contains(bytes, optional, isPe32 ? 136 : 152) ||
            certificateDirectoryOffset + 8 > optional + optionalSize ||
            !TryReadUInt32(bytes, numberOfDirectoriesOffset, out var directoryCount) ||
            directoryCount < 5 ||
            !TryReadUInt32(bytes, certificateDirectoryOffset, out var certificateOffset) ||
            !TryReadUInt32(bytes, certificateDirectoryOffset + 4, out var certificateSize))
            return false;

        // A section must already be entirely present in the unsigned publish. In particular,
        // the signer must not make a previously truncated section valid by appending a table.
        var sectionHeaders = (ulong)optional + optionalSize;
        if (sectionHeaders + (ulong)sectionCount * 40UL > (ulong)bytes.Length) return false;
        for (var index = 0; index < sectionCount; index++)
        {
            var section = (int)sectionHeaders + index * 40;
            if (!TryReadUInt32(bytes, section + 16, out var rawSize) ||
                !TryReadUInt32(bytes, section + 20, out var rawOffset) ||
                (rawSize != 0 && (rawOffset == 0 ||
                    (ulong)rawOffset + rawSize > (ulong)bytes.Length))) return false;
        }

        header = new Header(checksumOffset, certificateDirectoryOffset,
            certificateOffset, certificateSize);
        return true;
    }

    private static bool Contains(ReadOnlySpan<byte> bytes, int offset, int length) =>
        offset >= 0 && length >= 0 && offset <= bytes.Length && length <= bytes.Length - offset;

    private static bool TryReadUInt16(ReadOnlySpan<byte> bytes, int offset, out ushort value)
    {
        value = 0;
        if (!Contains(bytes, offset, 2)) return false;
        value = BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(offset, 2));
        return true;
    }

    private static bool TryReadUInt32(ReadOnlySpan<byte> bytes, int offset, out uint value)
    {
        value = 0;
        if (!Contains(bytes, offset, 4)) return false;
        value = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(offset, 4));
        return true;
    }

    private readonly record struct Header(int ChecksumOffset, int CertificateDirectoryOffset,
        uint CertificateOffset, uint CertificateSize);
}
