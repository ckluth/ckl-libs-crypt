using CKL.Libs.ResultPattern;
using NUnit.Framework;

namespace CKL.Libs.Crypt.Tests;

public class CryptoServiceByteArrayPasswordTests
{
    [Test]
    public void Encrypt_ThenDecrypt_WithPassword_RoundTripsOriginalBytes()
    {
        var plainBytes = new byte[] { 1, 2, 3, 4, 5, 250 };

        var encryptResult = CryptoService.Encrypt(plainBytes, "pw");
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.Decrypt(encryptResult.Value!, "pw");
        Assert.That(decryptResult.Succeeded, Is.True);
        Assert.That(decryptResult.Value, Is.EqualTo(plainBytes));
    }

    [Test]
    public void Encrypt_WithPassword_EmptyByteArray_RoundTripsToEmptyByteArray()
    {
        var encryptResult = CryptoService.Encrypt([], "pw");
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.Decrypt(encryptResult.Value!, "pw");

        Assert.That(decryptResult.Value, Is.EqualTo(Array.Empty<byte>()));
    }

    [Test]
    public void Decrypt_WrongPassword_ReturnsFailedResult()
    {
        var encryptResult = CryptoService.Encrypt([1, 2, 3], "correct-password");
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.Decrypt(encryptResult.Value!, "wrong-password");

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void Decrypt_WithPassword_InputTooShortToContainHeader_ReturnsFailedResult()
    {
        var decryptResult = CryptoService.Decrypt([1, 2, 3], "pw");

        Assert.That(decryptResult.Succeeded, Is.False);
    }
}
