using CKL.Libs.ResultPattern;
using NUnit.Framework;

namespace CKL.Libs.Crypt.Tests;

public class CryptoServiceKeyDerivationTests
{
    [Test]
    public void DeriveKeyFromPassword_DefaultKeySize_Returns32ByteKey()
    {
        var result = CryptoService.DeriveKeyFromPassword("correct horse battery staple");

        Assert.That(result.Succeeded, Is.True);
        Assert.That(result.Value!.Key, Has.Length.EqualTo(32));
    }

    [Test]
    public void DeriveKeyFromPassword_SamePasswordTwice_ProducesDifferentSalts()
    {
        var first = CryptoService.DeriveKeyFromPassword("same-password");
        var second = CryptoService.DeriveKeyFromPassword("same-password");

        Assert.That(first.Succeeded && second.Succeeded, Is.True);
        Assert.That(first.Value!.Salt, Is.Not.EqualTo(second.Value!.Salt));
    }

    [Test]
    public void DeriveKeyFromPassword_DerivedKey_EncryptsAndDecryptsRoundTrip()
    {
        var derived = CryptoService.DeriveKeyFromPassword("pw");
        Assert.That(derived.Succeeded, Is.True);

        var encryptResult = CryptoService.EncryptString("payload", derived.Value!.Key);
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptString(encryptResult.Value!, derived.Value!.Key);

        Assert.That(decryptResult.Value, Is.EqualTo("payload"));
    }
}
