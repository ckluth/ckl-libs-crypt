using System.Security.Cryptography;
using CKL.Libs.ResultPattern;
using NUnit.Framework;

namespace CKL.Libs.Crypt.Tests;

/// <summary>
/// Integration tests — touch the filesystem, so kept isolated from the pure
/// byte-array/string unit tests. Each test gets its own temp directory.
/// </summary>
public class CryptoServiceFolderIntegrationTests
{
    private string _tempDirectory = "";
    private string _sourceFolder = "";
    private string _destinationFolder = "";

    [SetUp]
    public void SetUp()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), "ckl-libs-crypt-tests", Guid.NewGuid().ToString("N"));
        _sourceFolder = Path.Combine(_tempDirectory, "source");
        _destinationFolder = Path.Combine(_tempDirectory, "destination");
        Directory.CreateDirectory(_sourceFolder);
    }

    [TearDown]
    public void TearDown()
    {
        if (Directory.Exists(_tempDirectory))
            Directory.Delete(_tempDirectory, recursive: true);
    }

    private void SeedNestedFiles()
    {
        File.WriteAllText(Path.Combine(_sourceFolder, "root.txt"), "root file");
        var subFolder = Path.Combine(_sourceFolder, "sub");
        Directory.CreateDirectory(subFolder);
        File.WriteAllText(Path.Combine(subFolder, "nested.txt"), "nested file");
    }

    [Test]
    public void EncryptFolder_ThenDecryptFolder_RoundTripsNestedStructure()
    {
        SeedNestedFiles();
        var key = RandomNumberGenerator.GetBytes(32);
        var encryptedPath = Path.Combine(_tempDirectory, "folder.enc");

        var encryptResult = CryptoService.EncryptFolder(_sourceFolder, encryptedPath, key);
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptFolder(encryptedPath, _destinationFolder, key);

        Assert.That(decryptResult.Succeeded, Is.True);
        Assert.That(File.ReadAllText(Path.Combine(_destinationFolder, "root.txt")), Is.EqualTo("root file"));
        Assert.That(File.ReadAllText(Path.Combine(_destinationFolder, "sub", "nested.txt")), Is.EqualTo("nested file"));
    }

    [Test]
    public void DecryptFolder_WrongKey_ReturnsFailedResult()
    {
        SeedNestedFiles();
        var encryptedPath = Path.Combine(_tempDirectory, "folder.enc");

        var encryptResult = CryptoService.EncryptFolder(_sourceFolder, encryptedPath, RandomNumberGenerator.GetBytes(32));
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptFolder(encryptedPath, _destinationFolder, RandomNumberGenerator.GetBytes(32));

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void EncryptFolder_NonExistentSource_ReturnsFailedResult()
    {
        var missingFolder = Path.Combine(_tempDirectory, "does-not-exist");
        var encryptedPath = Path.Combine(_tempDirectory, "folder.enc");

        var encryptResult = CryptoService.EncryptFolder(missingFolder, encryptedPath, RandomNumberGenerator.GetBytes(32));

        Assert.That(encryptResult.Succeeded, Is.False);
    }
}
