using System.Security.Cryptography;
using CKL.Libs.ResultPattern;
using NUnit.Framework;

namespace CKL.Libs.Crypt.Tests;

/// <summary>
/// Integration tests — touch the filesystem, so kept isolated from the pure
/// byte-array/string unit tests. Each test gets its own temp directory.
/// </summary>
public class CryptoServiceFileIntegrationTests
{
    private string _tempDirectory = "";

    [SetUp]
    public void SetUp()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), "ckl-libs-crypt-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDirectory);
    }

    [TearDown]
    public void TearDown()
    {
        if (Directory.Exists(_tempDirectory))
            Directory.Delete(_tempDirectory, recursive: true);
    }

    [Test]
    public void EncryptFile_ThenDecryptFile_RoundTripsOriginalContent()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var sourcePath = Path.Combine(_tempDirectory, "source.txt");
        var encryptedPath = Path.Combine(_tempDirectory, "source.enc");
        var decryptedPath = Path.Combine(_tempDirectory, "source.decrypted.txt");
        var originalContent = "The quick brown fox jumps over the lazy dog. " + new string('x', 10_000);
        File.WriteAllText(sourcePath, originalContent);

        var encryptResult = CryptoService.EncryptFile(sourcePath, encryptedPath, key);
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptFile(encryptedPath, decryptedPath, key);

        Assert.That(decryptResult.Succeeded, Is.True);
        Assert.That(File.ReadAllText(decryptedPath), Is.EqualTo(originalContent));
    }

    [Test]
    public void EncryptFile_ProducesSmallerOrEqualOutputThanUncompressedPlaintext()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var sourcePath = Path.Combine(_tempDirectory, "repetitive.txt");
        var encryptedPath = Path.Combine(_tempDirectory, "repetitive.enc");
        File.WriteAllText(sourcePath, new string('a', 100_000));

        var encryptResult = CryptoService.EncryptFile(sourcePath, encryptedPath, key);

        Assert.That(encryptResult.Succeeded, Is.True);
        Assert.That(new FileInfo(encryptedPath).Length, Is.LessThan(new FileInfo(sourcePath).Length));
    }

    [Test]
    public void DecryptFile_WrongKey_ReturnsFailedResult()
    {
        var sourcePath = Path.Combine(_tempDirectory, "source.txt");
        var encryptedPath = Path.Combine(_tempDirectory, "source.enc");
        var decryptedPath = Path.Combine(_tempDirectory, "source.decrypted.txt");
        File.WriteAllText(sourcePath, "content");

        var encryptResult = CryptoService.EncryptFile(sourcePath, encryptedPath, RandomNumberGenerator.GetBytes(32));
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptFile(encryptedPath, decryptedPath, RandomNumberGenerator.GetBytes(32));

        Assert.That(decryptResult.Succeeded, Is.False);
    }

    [Test]
    public void EncryptFile_NonExistentSource_ReturnsFailedResult()
    {
        var missingPath = Path.Combine(_tempDirectory, "does-not-exist.txt");
        var encryptedPath = Path.Combine(_tempDirectory, "output.enc");

        var encryptResult = CryptoService.EncryptFile(missingPath, encryptedPath, RandomNumberGenerator.GetBytes(32));

        Assert.That(encryptResult.Succeeded, Is.False);
    }

    [Test]
    public void EncryptFile_ThenDecryptFile_RestoresOriginalTimestamps()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var sourcePath = Path.Combine(_tempDirectory, "source.txt");
        var encryptedPath = Path.Combine(_tempDirectory, "source.enc");
        var decryptedPath = Path.Combine(_tempDirectory, "source.decrypted.txt");
        File.WriteAllText(sourcePath, "content");

        var created = new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        var modified = new DateTime(2021, 6, 7, 8, 9, 10, DateTimeKind.Utc);
        var accessed = new DateTime(2022, 11, 12, 13, 14, 15, DateTimeKind.Utc);
        File.SetCreationTimeUtc(sourcePath, created);
        File.SetLastWriteTimeUtc(sourcePath, modified);
        File.SetLastAccessTimeUtc(sourcePath, accessed);

        Assert.That(CryptoService.EncryptFile(sourcePath, encryptedPath, key).Succeeded, Is.True);
        Assert.That(CryptoService.DecryptFile(encryptedPath, decryptedPath, key).Succeeded, Is.True);

        Assert.That(File.GetCreationTimeUtc(decryptedPath), Is.EqualTo(created));
        Assert.That(File.GetLastWriteTimeUtc(decryptedPath), Is.EqualTo(modified));
        Assert.That(File.GetLastAccessTimeUtc(decryptedPath), Is.EqualTo(accessed));
    }

    [Test]
    public void EncryptFile_WithCaptureLastAccessTimeFalse_OmitsLastAccessTimeOnRestore()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var sourcePath = Path.Combine(_tempDirectory, "source.txt");
        var encryptedPath = Path.Combine(_tempDirectory, "source.enc");
        var decryptedPath = Path.Combine(_tempDirectory, "source.decrypted.txt");
        File.WriteAllText(sourcePath, "content");
        File.SetLastAccessTimeUtc(sourcePath, new DateTime(2022, 11, 12, 13, 14, 15, DateTimeKind.Utc));

        Assert.That(CryptoService.EncryptFile(sourcePath, encryptedPath, key, captureLastAccessTime: false).Succeeded, Is.True);
        var lastAccessBeforeDecrypt = DateTime.UtcNow;
        Assert.That(CryptoService.DecryptFile(encryptedPath, decryptedPath, key).Succeeded, Is.True);

        Assert.That(File.GetLastAccessTimeUtc(decryptedPath), Is.Not.EqualTo(new DateTime(2022, 11, 12, 13, 14, 15, DateTimeKind.Utc)));
        Assert.That(File.GetLastAccessTimeUtc(decryptedPath), Is.GreaterThanOrEqualTo(lastAccessBeforeDecrypt.AddSeconds(-1)));
    }

    [Test]
    public void EncryptFile_ThenDecryptFile_WithPassword_RoundTripsOriginalContent()
    {
        var sourcePath = Path.Combine(_tempDirectory, "source.txt");
        var encryptedPath = Path.Combine(_tempDirectory, "source.enc");
        var decryptedPath = Path.Combine(_tempDirectory, "source.decrypted.txt");
        var originalContent = "The quick brown fox jumps over the lazy dog.";
        File.WriteAllText(sourcePath, originalContent);

        var encryptResult = CryptoService.EncryptFile(sourcePath, encryptedPath, "correct horse battery staple");
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptFile(encryptedPath, decryptedPath, "correct horse battery staple");

        Assert.That(decryptResult.Succeeded, Is.True);
        Assert.That(File.ReadAllText(decryptedPath), Is.EqualTo(originalContent));
    }

    [Test]
    public void DecryptFile_WithPassword_WrongPassword_ReturnsFailedResult()
    {
        var sourcePath = Path.Combine(_tempDirectory, "source.txt");
        var encryptedPath = Path.Combine(_tempDirectory, "source.enc");
        var decryptedPath = Path.Combine(_tempDirectory, "source.decrypted.txt");
        File.WriteAllText(sourcePath, "content");

        var encryptResult = CryptoService.EncryptFile(sourcePath, encryptedPath, "correct-password");
        Assert.That(encryptResult.Succeeded, Is.True);

        var decryptResult = CryptoService.DecryptFile(encryptedPath, decryptedPath, "wrong-password");

        Assert.That(decryptResult.Succeeded, Is.False);
    }
}
