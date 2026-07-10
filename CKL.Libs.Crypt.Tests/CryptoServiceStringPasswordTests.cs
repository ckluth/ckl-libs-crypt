using CKL.Libs.ResultPattern;
using NUnit.Framework;

namespace CKL.Libs.Crypt.Tests;

public class CryptoServiceStringPasswordTests
{
    [Test]
    public void EncryptString_ThenDecryptString_WithPassword_RoundTripsOriginalText()
    {
        var encryptResult = CryptoService.EncryptString("Hello, CKL!", "correct horse battery staple");

        Assert.That(encryptResult.Succeeded, Is.True);
        var decryptResult = CryptoService.DecryptString(encryptResult.Value!, "correct horse battery staple");

        Assert.That(decryptResult.Succeeded, Is.True);
        Assert.That(decryptResult.Value, Is.EqualTo("Hello, CKL!"));
    }

    [Test]
    public void EncryptString_WithPassword_EmptyString_RoundTripsToEmptyString()
    {
        var encryptResult = CryptoService.EncryptString(string.Empty, "pw");
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptString(encryptResult.Value!, "pw");

        Assert.That(decryptResult.Value, Is.EqualTo(string.Empty));
    }

    [Test]
    public void EncryptString_SamePasswordTwice_ProducesDifferentCiphertext()
    {
        var first = CryptoService.EncryptString("payload", "pw");
        var second = CryptoService.EncryptString("payload", "pw");

        Assert.That(first.Succeeded && second.Succeeded, Is.True);
        Assert.That(first.Value, Is.Not.EqualTo(second.Value));
    }

    [Test]
    public void DecryptString_WrongPassword_ReturnsFailedResult()
    {
        var encryptResult = CryptoService.EncryptString("secret", "correct-password");
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptString(encryptResult.Value!, "wrong-password");

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void DecryptString_WithPassword_NotBase64_ReturnsFailedResult()
    {
        var decryptResult = CryptoService.DecryptString("not-base64!!", "pw");

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void DecryptString_WithPassword_TooShortToContainSalt_ReturnsFailedResult()
    {
        var decryptResult = CryptoService.DecryptString(Convert.ToBase64String([1, 2, 3]), "pw");

        Assert.That(decryptResult.Succeeded, Is.False);
    }
}
