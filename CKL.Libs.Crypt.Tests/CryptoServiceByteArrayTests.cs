using System.Security.Cryptography;
using CKL.Libs.ResultPattern;
using NUnit.Framework;

namespace CKL.Libs.Crypt.Tests;

public class CryptoServiceByteArrayTests
{
    private static byte[] NewKey() => RandomNumberGenerator.GetBytes(32);

    [Test]
    public void Encrypt_ThenDecrypt_RoundTripsOriginalBytes()
    {
        var key = NewKey();
        var plainBytes = new byte[] { 1, 2, 3, 4, 5, 250 };

        var encryptResult = CryptoService.Encrypt(plainBytes, key);
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.Decrypt(encryptResult.Value!, key);
        Assert.That(decryptResult.Succeeded, Is.True);
        Assert.That(decryptResult.Value, Is.EqualTo(plainBytes));
    }

    [Test]
    public void Encrypt_EmptyByteArray_RoundTripsToEmptyByteArray()
    {
        var key = NewKey();
        var encryptResult = CryptoService.Encrypt([], key);
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.Decrypt(encryptResult.Value!, key);

        Assert.That(decryptResult.Value, Is.EqualTo(Array.Empty<byte>()));
    }

    [Test]
    public void Decrypt_WrongKey_ReturnsFailedResult()
    {
        var encryptResult = CryptoService.Encrypt([1, 2, 3], NewKey());
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.Decrypt(encryptResult.Value!, NewKey());

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_InputShorterThanHeader_ReturnsFailedResult()
    {
        var decryptResult = CryptoService.Decrypt([1, 2, 3], NewKey());

        Assert.That(decryptResult.Succeeded, Is.False);
    }
}
