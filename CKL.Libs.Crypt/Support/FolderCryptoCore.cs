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
        WithTempZip(tempZipPath =>
        {
            CreateZip(sourceFolderPath, tempZipPath);
            using var destinationStream = File.Create(destinationFilePath);
            EncryptZipToStream(tempZipPath, destinationStream, key);
        });
    }

    internal static void DecryptFolder(string sourceFilePath, string destinationFolderPath, byte[] key)
    {
        WithTempZip(tempZipPath =>
        {
            using (var sourceStream = File.OpenRead(sourceFilePath))
            {
                DecryptStreamToZip(sourceStream, tempZipPath, key);
            }

            ExtractZip(tempZipPath, destinationFolderPath);
        });
    }

    /// <summary>Zips <paramref name="sourceFolderPath"/> into a fresh archive at <paramref name="zipDestinationPath"/>.</summary>
    internal static void CreateZip(string sourceFolderPath, string zipDestinationPath) =>
        ZipFile.CreateFromDirectory(sourceFolderPath, zipDestinationPath, CompressionLevel.Optimal, includeBaseDirectory: false);

    /// <summary>Extracts the archive at <paramref name="zipPath"/> into <paramref name="destinationFolderPath"/>.</summary>
    internal static void ExtractZip(string zipPath, string destinationFolderPath)
    {
        Directory.CreateDirectory(destinationFolderPath);
        ZipFile.ExtractToDirectory(zipPath, destinationFolderPath, overwriteFiles: true);
    }

    /// <summary>
    /// Encrypts the archive at <paramref name="zipPath"/> into an already-open
    /// <paramref name="destinationStream"/> — the password-based overloads use this to write a
    /// salt prefix ahead of the IV/ciphertext.
    /// </summary>
    internal static void EncryptZipToStream(string zipPath, Stream destinationStream, byte[] key)
    {
        using var zipStream = File.OpenRead(zipPath);
        var iv = AesCryptoCore.GenerateIv();
        destinationStream.Write(iv, 0, iv.Length);
        using var aes = AesCryptoCore.CreateAes(key, iv);
        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(destinationStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        zipStream.CopyTo(cryptoStream);
    }

    /// <summary>
    /// Decrypts from an already-positioned <paramref name="sourceStream"/> into the archive at
    /// <paramref name="zipPath"/> — the password-based overloads use this after consuming the
    /// salt prefix.
    /// </summary>
    internal static void DecryptStreamToZip(Stream sourceStream, string zipPath, byte[] key)
    {
        var iv = AesCryptoCore.ReadIv(sourceStream);
        using var aes = AesCryptoCore.CreateAes(key, iv);
        using var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(sourceStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        using var zipStream = File.Create(zipPath);
        cryptoStream.CopyTo(zipStream);
    }

    /// <summary>Runs <paramref name="action"/> with a fresh temp zip path, deleting it afterwards.</summary>
    internal static void WithTempZip(Action<string> action)
    {
        var tempZipPath = Path.GetTempFileName();
        try
        {
            File.Delete(tempZipPath); // ZipFile.CreateFromDirectory requires a non-existent target.
            action(tempZipPath);
        }
        finally
        {
            File.Delete(tempZipPath);
        }
    }
}
