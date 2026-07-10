using System.Buffers.Binary;
using System.Security.Cryptography;
using CKL.Libs.ResultPattern;
using NUnit.Framework;

namespace CKL.Libs.Crypt.Tests;

/// <summary>
/// Validates the v3 container header on the produced ciphertext (parsed directly from the output
/// bytes) and that a corrupted header decrypts to a failed <see cref="Result"/>. Field offsets
/// mirror <c>CryptoHeader</c>'s v3 layout: magic(4), version(1), cipher-id(1), flags(1),
/// chunk-size(4), kdf-id(1), [pbkdf2 params], nonce-base(12), [timestamp block], framed chunks.
/// </summary>
public class CryptoServiceContainerFormatTests
{
    private static readonly byte[] Magic = "CKLC"u8.ToArray();

    private const int ExpectedChunkSize = 64 * 1024;

    [Test]
    public void Encrypt_WithPassword_WritesExpectedPbkdf2Header()
    {
        var output = CryptoService.Encrypt([1, 2, 3], "pw").Value!;

        Assert.That(output.AsSpan(0, 4).SequenceEqual(Magic), Is.True);
        Assert.That(output[4], Is.EqualTo(0x03));                                          // version
        Assert.That(output[5], Is.EqualTo(0x01));                                          // cipher-id = AES-256-GCM
        Assert.That(output[6], Is.EqualTo(0x00));                                          // flags = none (byte-array path captures no timestamps)
        Assert.That(BinaryPrimitives.ReadUInt32BigEndian(output.AsSpan(7, 4)), Is.EqualTo((uint)ExpectedChunkSize));
        Assert.That(output[11], Is.EqualTo(0x01));                                         // kdf-id = PBKDF2
        Assert.That(BinaryPrimitives.ReadUInt32BigEndian(output.AsSpan(12, 4)), Is.EqualTo(600_000u));
        Assert.That(output[16], Is.EqualTo(32));                                           // key size
        Assert.That(output[17], Is.EqualTo(16));                                           // salt length
    }

    [Test]
    public void Encrypt_WithRawKey_WritesNoneKdfHeader()
    {
        var output = CryptoService.Encrypt([1, 2, 3], RandomNumberGenerator.GetBytes(32)).Value!;

        Assert.That(output.AsSpan(0, 4).SequenceEqual(Magic), Is.True);
        Assert.That(output[4], Is.EqualTo(0x03));                                          // version
        Assert.That(output[5], Is.EqualTo(0x01));                                          // cipher-id = AES-256-GCM
        Assert.That(output[6], Is.EqualTo(0x00));                                          // flags = none
        Assert.That(BinaryPrimitives.ReadUInt32BigEndian(output.AsSpan(7, 4)), Is.EqualTo((uint)ExpectedChunkSize));
        Assert.That(output[11], Is.EqualTo(0x00));                                         // kdf-id = none (raw key)
    }

    [Test]
    public void Decrypt_BadMagic_ReturnsFailedResult()
    {
        var output = CryptoService.Encrypt([1, 2, 3], "pw").Value!;
        output[0] ^= 0xFF;

        var decryptResult = CryptoService.Decrypt(output, "pw");

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_UnsupportedVersion_ReturnsFailedResult()
    {
        var output = CryptoService.Encrypt([1, 2, 3], "pw").Value!;
        output[4] = 0x99;

        var decryptResult = CryptoService.Decrypt(output, "pw");

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_UnsupportedCipherId_ReturnsFailedResult()
    {
        var output = CryptoService.Encrypt([1, 2, 3], "pw").Value!;
        output[5] = 0x00; // retired CBC id — must be rejected, never decrypted

        var decryptResult = CryptoService.Decrypt(output, "pw");

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_UnknownKdfId_ReturnsFailedResult()
    {
        var output = CryptoService.Encrypt([1, 2, 3], "pw").Value!;
        output[11] = 0x77;

        var decryptResult = CryptoService.Decrypt(output, "pw");

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_TamperedHeaderField_ReturnsFailedResult()
    {
        // The header is cleartext but authenticated (bound as associated data into every chunk), so
        // a silent header-field swap must fail the chunk tag rather than decrypt. Flip a chunk-size
        // byte and expect a clean failure.
        var key = RandomNumberGenerator.GetBytes(32);
        var output = CryptoService.Encrypt([1, 2, 3], key).Value!;
        output[7] ^= 0x01;

        var decryptResult = CryptoService.Decrypt(output, key);

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_TruncatedTimestampBlock_ReturnsFailedResult()
    {
        // A container whose flags claim a timestamp block, but the bytes are missing —
        // simulates truncation inside the header (see ADR 0010).
        var output = CryptoService.Encrypt([1, 2, 3], RandomNumberGenerator.GetBytes(32)).Value!;
        output[6] = 0x01; // set TimestampsPresent, but no timestamp bytes actually follow

        var decryptResult = CryptoService.Decrypt(output, RandomNumberGenerator.GetBytes(32));

        Assert.That(decryptResult.Succeeded, Is.False);
    }
}
