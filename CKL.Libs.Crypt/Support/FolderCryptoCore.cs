using System.IO.Compression;
using System.Security.Cryptography;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Zip-then-encrypt / decrypt-then-extract pipeline for a folder, via a temporary zip archive
/// (the archive already compresses; no additional compression pass is applied).
/// </summary>
internal static class FolderCryptoCore
{
    internal static void EncryptFolder(string sourceFolderPath, string destinationFilePath, byte[] key)
    {
        var tempZipPath = Path.GetTempFileName();
        try
        {
            File.Delete(tempZipPath); // ZipFile.CreateFromDirectory requires a non-existent target.
            ZipFile.CreateFromDirectory(sourceFolderPath, tempZipPath, CompressionLevel.Optimal, includeBaseDirectory: false);
            EncryptZipToDestination(tempZipPath, destinationFilePath, key);
        }
        finally
        {
            File.Delete(tempZipPath);
        }
    }

    internal static void DecryptFolder(string sourceFilePath, string destinationFolderPath, byte[] key)
    {
        var tempZipPath = Path.GetTempFileName();
        try
        {
            DecryptSourceToZip(sourceFilePath, tempZipPath, key);
            Directory.CreateDirectory(destinationFolderPath);
            ZipFile.ExtractToDirectory(tempZipPath, destinationFolderPath, overwriteFiles: true);
        }
        finally
        {
            File.Delete(tempZipPath);
        }
    }

    private static void EncryptZipToDestination(string zipPath, string destinationFilePath, byte[] key)
    {
        using var zipStream = File.OpenRead(zipPath);
        using var destinationStream = File.Create(destinationFilePath);
        var iv = AesCryptoCore.GenerateIv();
        destinationStream.Write(iv, 0, iv.Length);
        using var aes = AesCryptoCore.CreateAes(key, iv);
        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(destinationStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        zipStream.CopyTo(cryptoStream);
    }

    private static void DecryptSourceToZip(string sourceFilePath, string zipPath, byte[] key)
    {
        using var sourceStream = File.OpenRead(sourceFilePath);
        var iv = AesCryptoCore.ReadIv(sourceStream);
        using var aes = AesCryptoCore.CreateAes(key, iv);
        using var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(sourceStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        using var zipStream = File.Create(zipPath);
        cryptoStream.CopyTo(zipStream);
    }
}
