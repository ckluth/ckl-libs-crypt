using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CKL.Libs.ResultPattern;
using NUnit.Framework;

namespace CKL.Libs.Crypt.Tests;

/// <summary>
/// Validates the v2 container header on the produced ciphertext (parsed directly from the output
/// bytes) and that a corrupted header decrypts to a failed <see cref="Result"/>.
/// </summary>
public class CryptoServiceContainerFormatTests
{
    private static readonly byte[] Magic = "CKLC"u8.ToArray();

    [Test]
    public void Encrypt_WithPassword_WritesExpectedPbkdf2Header()
    {
        var output = CryptoService.Encrypt([1, 2, 3], "pw").Value!;

        Assert.That(output.AsSpan(0, 4).SequenceEqual(Magic), Is.True);
        Assert.That(output[4], Is.EqualTo(0x02));                                    // version
        Assert.That(output[5], Is.EqualTo(0x00));                                    // flags = none (byte-array path captures no timestamps)
        Assert.That(output[6], Is.EqualTo(0x01));                                    // kdf-id = PBKDF2
        Assert.That(BinaryPrimitives.ReadUInt32BigEndian(output.AsSpan(7, 4)), Is.EqualTo(600_000u));
        Assert.That(output[11], Is.EqualTo(32));                                     // key size
        Assert.That(output[12], Is.EqualTo(16));                                     // salt length
    }

    [Test]
    public void Encrypt_WithRawKey_WritesNoneKdfHeader()
    {
        var output = CryptoService.Encrypt([1, 2, 3], RandomNumberGenerator.GetBytes(32)).Value!;

        Assert.That(output.AsSpan(0, 4).SequenceEqual(Magic), Is.True);
        Assert.That(output[4], Is.EqualTo(0x02));   // version
        Assert.That(output[5], Is.EqualTo(0x00));   // flags = none
        Assert.That(output[6], Is.EqualTo(0x00));   // kdf-id = none (raw key)
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
    public void Decrypt_UnknownKdfId_ReturnsFailedResult()
    {
        var output = CryptoService.Encrypt([1, 2, 3], "pw").Value!;
        output[6] = 0x77;

        var decryptResult = CryptoService.Decrypt(output, "pw");

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_TruncatedTimestampBlock_ReturnsFailedResult()
    {
        // A container whose flags claim a timestamp block, but the bytes are missing —
        // simulates truncation inside the header (see ADR 0010).
        var output = CryptoService.Encrypt([1, 2, 3], RandomNumberGenerator.GetBytes(32)).Value!;
        output[5] = 0x01; // set TimestampsPresent, but no timestamp bytes actually follow

        var decryptResult = CryptoService.Decrypt(output, RandomNumberGenerator.GetBytes(32));

        Assert.That(decryptResult.Succeeded, Is.False);
    }
}
