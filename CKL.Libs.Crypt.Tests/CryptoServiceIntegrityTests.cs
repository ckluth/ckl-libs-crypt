using System.Security.Cryptography;
using CKL.Libs.ResultPattern;
using NUnit.Framework;

namespace CKL.Libs.Crypt.Tests;

/// <summary>
/// The integrity tests that are the whole point of the v3 (authenticated AES-256-GCM) format:
/// tampering and corruption — a flipped byte, chunk reorder/duplicate/truncate/append, and a
/// stripped payload — all surface as a clean, failed <see cref="Result"/>, never wrong plaintext.
/// Raw-key containers are used so the header is a fixed 24 bytes and chunk boundaries are known:
/// header(24) then framed chunks of (64 KiB ciphertext + 16-byte tag) = 65552 bytes each.
/// </summary>
public class CryptoServiceIntegrityTests
{
    private const int HeaderLength = 24;      // magic4+version1+cipher1+flags1+chunkSize4+kdfId1(none)+nonceBase12
    private const int ChunkSize = 64 * 1024;
    private const int TagLength = 16;
    private const int CipherChunkLength = ChunkSize + TagLength;

    private static byte[] NewKey() => RandomNumberGenerator.GetBytes(32);

    private static byte[] EncryptTwoChunks(byte[] key) =>
        CryptoService.Encrypt(RandomNumberGenerator.GetBytes(2 * ChunkSize), key).Value!;

    [Test]
    public void Decrypt_SingleFlippedCiphertextByte_ReturnsFailedResult()
    {
        var key = NewKey();
        var output = CryptoService.Encrypt(RandomNumberGenerator.GetBytes(1000), key).Value!;
        output[HeaderLength + 10] ^= 0xFF; // flip a byte inside the first (only) chunk's ciphertext

        Assert.That(CryptoService.Decrypt(output, key).Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_FlippedTagByte_ReturnsFailedResult()
    {
        var key = NewKey();
        var output = CryptoService.Encrypt(RandomNumberGenerator.GetBytes(1000), key).Value!;
        output[^1] ^= 0xFF; // flip a byte inside the final chunk's authentication tag

        Assert.That(CryptoService.Decrypt(output, key).Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_ReorderedChunks_ReturnsFailedResult()
    {
        var key = NewKey();
        var output = EncryptTwoChunks(key);
        var tampered = (byte[])output.Clone();

        // Swap chunk 0 and chunk 1 (each CipherChunkLength bytes, right after the header).
        Array.Copy(output, HeaderLength + CipherChunkLength, tampered, HeaderLength, CipherChunkLength);
        Array.Copy(output, HeaderLength, tampered, HeaderLength + CipherChunkLength, CipherChunkLength);

        Assert.That(CryptoService.Decrypt(tampered, key).Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_DuplicatedChunk_ReturnsFailedResult()
    {
        var key = NewKey();
        var output = EncryptTwoChunks(key);
        var tampered = (byte[])output.Clone();

        // Overwrite chunk 1 with a copy of chunk 0.
        Array.Copy(output, HeaderLength, tampered, HeaderLength + CipherChunkLength, CipherChunkLength);

        Assert.That(CryptoService.Decrypt(tampered, key).Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_TruncatedFinalChunk_ReturnsFailedResult()
    {
        var key = NewKey();
        var output = EncryptTwoChunks(key);
        var truncated = output.AsSpan(0, output.Length - 100).ToArray();

        Assert.That(CryptoService.Decrypt(truncated, key).Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_DroppedFinalChunk_ReturnsFailedResult()
    {
        var key = NewKey();
        var output = EncryptTwoChunks(key);
        var truncated = output.AsSpan(0, HeaderLength + CipherChunkLength).ToArray(); // keep header + chunk 0 only

        Assert.That(CryptoService.Decrypt(truncated, key).Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_AppendedChunk_ReturnsFailedResult()
    {
        var key = NewKey();
        var output = EncryptTwoChunks(key);
        var extended = new byte[output.Length + CipherChunkLength];
        Array.Copy(output, extended, output.Length);
        Array.Copy(output, HeaderLength, extended, output.Length, CipherChunkLength); // append a copy of chunk 0

        Assert.That(CryptoService.Decrypt(extended, key).Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_HeaderOnlyNoChunks_ReturnsFailedResult()
    {
        var key = NewKey();
        var output = CryptoService.Encrypt([1, 2, 3], key).Value!;
        var headerOnly = output.AsSpan(0, HeaderLength).ToArray(); // strip every framed chunk

        Assert.That(CryptoService.Decrypt(headerOnly, key).Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_EmptyPlaintext_RoundTripsAndStaysAuthenticated()
    {
        var key = NewKey();
        var output = CryptoService.Encrypt([], key).Value!;

        // An empty payload is still one authenticated final chunk (16-byte tag), so it round-trips
        // to empty but any corruption of that tag fails.
        Assert.That(CryptoService.Decrypt(output, key).Value, Is.EqualTo(Array.Empty<byte>()));

        var tampered = (byte[])output.Clone();
        tampered[^1] ^= 0xFF;
        Assert.That(CryptoService.Decrypt(tampered, key).Succeeded, Is.False);
    }
}
