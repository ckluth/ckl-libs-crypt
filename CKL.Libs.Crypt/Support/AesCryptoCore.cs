using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Framed AES-256-GCM building blocks shared by the byte-array, file, and folder paths (ADR 0011).
/// The per-encryption 12-byte nonce base and the plaintext chunk size live in the
/// <see cref="CryptoHeader"/> that prefixes every container; this type writes/reads that header and
/// wraps the destination/source in a <see cref="GcmChunkWriteStream"/>/<see cref="GcmChunkReadStream"/>
/// so large inputs stay streaming, and it owns the per-chunk nonce-derivation and associated-data
/// rules that make the framing tamper- and corruption-evident.
/// </summary>
internal static class AesCryptoCore
{
    /// <summary>Generates a fresh random 12-byte AES-GCM nonce base for one encryption.</summary>
    internal static byte[] GenerateNonceBase()
    {
        var nonceBase = new byte[CryptoHeader.NonceBaseLength];
        RandomNumberGenerator.Fill(nonceBase);
        return nonceBase;
    }

    /// <summary>
    /// Writes <paramref name="header"/> to <paramref name="destination"/> and returns a write-only
    /// stream that frames everything written to it into authenticated GCM chunks. Dispose the
    /// returned stream to flush the final chunk.
    /// </summary>
    internal static GcmChunkWriteStream CreateEncryptor(Stream destination, byte[] key, CryptoHeader header, bool leaveOpen = false)
    {
        var headerBytes = header.ToBytes();
        destination.Write(headerBytes, 0, headerBytes.Length);
        return new GcmChunkWriteStream(destination, key, headerBytes, header.NonceBase, header.ChunkSize, leaveOpen);
    }

    /// <summary>
    /// Reads and validates the header from <paramref name="source"/>, resolves the key from it, and
    /// returns the parsed header plus a read-only stream yielding the authenticated plaintext.
    /// </summary>
    internal static (CryptoHeader Header, GcmChunkReadStream Plaintext) CreateDecryptor(Stream source, Func<CryptoHeader, byte[]> resolveKey, bool leaveOpen = false)
    {
        var header = CryptoHeader.ReadFrom(source, out var headerBytes);
        var key = resolveKey(header);
        var plaintext = new GcmChunkReadStream(source, key, headerBytes, header.NonceBase, header.ChunkSize, leaveOpen);
        return (header, plaintext);
    }

    /// <summary>Writes <paramref name="header"/> then the framed GCM ciphertext of <paramref name="plainBytes"/>.</summary>
    internal static byte[] EncryptWithHeader(byte[] plainBytes, byte[] key, CryptoHeader header)
    {
        using var output = new MemoryStream();
        using (var encryptor = CreateEncryptor(output, key, header, leaveOpen: true))
        {
            encryptor.Write(plainBytes, 0, plainBytes.Length);
        }

        return output.ToArray();
    }

    /// <summary>
    /// Reads and validates the header, resolves the key from it (raw-key callers ignore the header;
    /// password callers re-derive), then decrypts and authenticates the framed chunks.
    /// </summary>
    internal static byte[] DecryptWithHeader(byte[] inputBytes, Func<CryptoHeader, byte[]> resolveKey)
    {
        using var source = new MemoryStream(inputBytes);
        var (_, plaintext) = CreateDecryptor(source, resolveKey, leaveOpen: true);
        using (plaintext)
        {
            using var output = new MemoryStream();
            plaintext.CopyTo(output);
            return output.ToArray();
        }
    }

    /// <summary>
    /// Derives the per-chunk nonce by XORing the low 8 bytes of the nonce base with the big-endian
    /// chunk index. Distinct indices yield distinct nonces within one encryption; a fresh random
    /// base per encryption keeps them distinct across encryptions.
    /// </summary>
    internal static byte[] DeriveNonce(byte[] nonceBase, long index)
    {
        var nonce = (byte[])nonceBase.Clone();

        Span<byte> indexBytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(indexBytes, (ulong)index);

        var offset = CryptoHeader.NonceBaseLength - sizeof(ulong);
        for (var i = 0; i < sizeof(ulong); i++)
            nonce[offset + i] ^= indexBytes[i];

        return nonce;
    }

    /// <summary>
    /// Builds the per-chunk associated data: the exact header bytes, the big-endian chunk index, and
    /// a final-chunk marker. Binding all three makes header-field tampering, chunk reordering or
    /// duplication, and whole-chunk truncation or extension fail the tag.
    /// </summary>
    internal static byte[] BuildAad(byte[] headerBytes, long index, bool isFinal)
    {
        var aad = new byte[headerBytes.Length + sizeof(ulong) + 1];
        Buffer.BlockCopy(headerBytes, 0, aad, 0, headerBytes.Length);
        BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(headerBytes.Length, sizeof(ulong)), (ulong)index);
        aad[^1] = (byte)(isFinal ? 0x01 : 0x00);
        return aad;
    }
}
