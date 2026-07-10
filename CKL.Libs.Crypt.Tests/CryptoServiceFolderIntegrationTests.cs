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
    public void EncryptFolder_ThenDecryptFolder_RestoresOriginalTimestamps()
    {
        SeedNestedFiles();
        var key = RandomNumberGenerator.GetBytes(32);
        var encryptedPath = Path.Combine(_tempDirectory, "folder.enc");

        var rootModified = new DateTime(2019, 3, 4, 5, 6, 7, DateTimeKind.Utc);
        var rootFilePath = Path.Combine(_sourceFolder, "root.txt");
        var rootFileModified = new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        var subFolder = Path.Combine(_sourceFolder, "sub");
        var subFolderModified = new DateTime(2020, 5, 6, 7, 8, 9, DateTimeKind.Utc);
        var nestedFilePath = Path.Combine(subFolder, "nested.txt");
        var nestedFileModified = new DateTime(2021, 6, 7, 8, 9, 10, DateTimeKind.Utc);

        Directory.SetLastWriteTimeUtc(_sourceFolder, rootModified);
        File.SetLastWriteTimeUtc(rootFilePath, rootFileModified);
        Directory.SetLastWriteTimeUtc(subFolder, subFolderModified);
        File.SetLastWriteTimeUtc(nestedFilePath, nestedFileModified);

        var encryptResult = CryptoService.EncryptFolder(_sourceFolder, encryptedPath, key);
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptFolder(encryptedPath, _destinationFolder, key);
        Assert.That(decryptResult.Succeeded, Is.True);

        Assert.That(Directory.GetLastWriteTimeUtc(_destinationFolder), Is.EqualTo(rootModified));
        Assert.That(File.GetLastWriteTimeUtc(Path.Combine(_destinationFolder, "root.txt")), Is.EqualTo(rootFileModified));
        Assert.That(Directory.GetLastWriteTimeUtc(Path.Combine(_destinationFolder, "sub")), Is.EqualTo(subFolderModified));
        Assert.That(File.GetLastWriteTimeUtc(Path.Combine(_destinationFolder, "sub", "nested.txt")), Is.EqualTo(nestedFileModified));
    }

    [Test]
    public void EncryptFolder_SourceContainsReservedManifestName_ReturnsFailedResult()
    {
        SeedNestedFiles();
        File.WriteAllText(Path.Combine(_sourceFolder, "__ckl_timestamps.json"), "{}");
        var encryptedPath = Path.Combine(_tempDirectory, "folder.enc");

        var encryptResult = CryptoService.EncryptFolder(_sourceFolder, encryptedPath, RandomNumberGenerator.GetBytes(32));

        Assert.That(encryptResult.Succeeded, Is.False);
    }

    [Test]
    public void DecryptFolder_RestoresContentWithoutLeakingTimestampManifest()
    {
        SeedNestedFiles();
        var key = RandomNumberGenerator.GetBytes(32);
        var encryptedPath = Path.Combine(_tempDirectory, "folder.enc");

        Assert.That(CryptoService.EncryptFolder(_sourceFolder, encryptedPath, key).Succeeded, Is.True);
        Assert.That(CryptoService.DecryptFolder(encryptedPath, _destinationFolder, key).Succeeded, Is.True);

        Assert.That(File.Exists(Path.Combine(_destinationFolder, "__ckl_timestamps.json")), Is.False);
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

    [Test]
    public void EncryptFolder_ThenDecryptFolder_WithPassword_RoundTripsNestedStructure()
    {
        SeedNestedFiles();
        var encryptedPath = Path.Combine(_tempDirectory, "folder.enc");

        var encryptResult = CryptoService.EncryptFolder(_sourceFolder, encryptedPath, "correct horse battery staple");
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptFolder(encryptedPath, _destinationFolder, "correct horse battery staple");

        Assert.That(decryptResult.Succeeded, Is.True);
        Assert.That(File.ReadAllText(Path.Combine(_destinationFolder, "root.txt")), Is.EqualTo("root file"));
        Assert.That(File.ReadAllText(Path.Combine(_destinationFolder, "sub", "nested.txt")), Is.EqualTo("nested file"));
    }

    [Test]
    public void EncryptFolder_ThenDecryptFolder_WithWorkingDirectoryOverride_RoundTripsNestedStructure()
    {
        SeedNestedFiles();
        var key = RandomNumberGenerator.GetBytes(32);
        var encryptedPath = Path.Combine(_tempDirectory, "folder.enc");
        var workingDirectory = Path.Combine(_tempDirectory, "staging");

        var encryptResult = CryptoService.EncryptFolder(_sourceFolder, encryptedPath, key, workingDirectory);
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptFolder(encryptedPath, _destinationFolder, key, workingDirectory);

        Assert.That(decryptResult.Succeeded, Is.True);
        Assert.That(File.ReadAllText(Path.Combine(_destinationFolder, "root.txt")), Is.EqualTo("root file"));
        Assert.That(File.ReadAllText(Path.Combine(_destinationFolder, "sub", "nested.txt")), Is.EqualTo("nested file"));
    }

    [Test]
    public void DecryptFolder_WithPassword_WrongPassword_ReturnsFailedResult()
    {
        SeedNestedFiles();
        var encryptedPath = Path.Combine(_tempDirectory, "folder.enc");

        var encryptResult = CryptoService.EncryptFolder(_sourceFolder, encryptedPath, "correct-password");
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptFolder(encryptedPath, _destinationFolder, "wrong-password");

        Assert.That(decryptResult.Succeeded, Is.False);
    }
}
