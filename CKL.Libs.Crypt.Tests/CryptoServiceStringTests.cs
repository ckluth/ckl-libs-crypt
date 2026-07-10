using System.Security.Cryptography;
using CKL.Libs.ResultPattern;
using NUnit.Framework;

namespace CKL.Libs.Crypt.Tests;

public class CryptoServiceStringTests
{
    private static byte[] NewKey() => RandomNumberGenerator.GetBytes(32);

    [Test]
    public void EncryptString_ThenDecryptString_RoundTripsOriginalText()
    {
        var key = NewKey();
        var encryptResult = CryptoService.EncryptString("Hello, CKL!", key);

        Assert.That(encryptResult.Succeeded, Is.True);
        var decryptResult = CryptoService.DecryptString(encryptResult.Value!, key);

        Assert.That(decryptResult.Succeeded, Is.True);
        Assert.That(decryptResult.Value, Is.EqualTo("Hello, CKL!"));
    }

    [Test]
    public void EncryptString_EmptyString_RoundTripsToEmptyString()
    {
        var key = NewKey();
        var encryptResult = CryptoService.EncryptString(string.Empty, key);
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptString(encryptResult.Value!, key);

        Assert.That(decryptResult.Value, Is.EqualTo(string.Empty));
    }

    [Test]
    public void DecryptString_WrongKey_ReturnsFailedResult()
    {
        var encryptResult = CryptoService.EncryptString("secret", NewKey());
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptString(encryptResult.Value!, NewKey());

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void DecryptString_NotBase64_ReturnsFailedResult()
    {
        var decryptResult = CryptoService.DecryptString("not-base64!!", NewKey());

        Assert.That(decryptResult.Succeeded, Is.False);
    }
}
