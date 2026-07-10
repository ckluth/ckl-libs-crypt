using System.IO.Compression;
using System.Security.Cryptography;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Zip-then-encrypt / decrypt-then-extract pipeline for a folder, via a temporary zip archive.
/// The intermediate (plaintext) archive is staged in a controlled, per-user restricted-ACL
/// location rather than the shared temp directory — see <see cref="CryptoWorkspace"/>. The
/// <see cref="CryptoHeader"/> is written/read at the front of the destination/source stream.
/// </summary>
internal static class FolderCryptoCore
{
    /// <summary>Encrypts the archive at <paramref name="zipPath"/> into an already-open stream.</summary>
    internal static void EncryptZipToStream(string zipPath, Stream destinationStream, byte[] key, CryptoHeader header)
    {
        header.WriteTo(destinationStream);
        using var zipStream = File.OpenRead(zipPath);
        using var aes = AesCryptoCore.CreateAes(key, header.Iv);
        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(destinationStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        zipStream.CopyTo(cryptoStream);
    }

    /// <summary>
    /// Reads the header from <paramref name="sourceStream"/>, resolves the key, then decrypts into
    /// the archive at <paramref name="zipPath"/>.
    /// </summary>
    internal static void DecryptStreamToZip(Stream sourceStream, string zipPath, Func<CryptoHeader, byte[]> resolveKey)
    {
        var header = CryptoHeader.ReadFrom(sourceStream);
        var key = resolveKey(header);
        using var aes = AesCryptoCore.CreateAes(key, header.Iv);
        using var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(sourceStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        using var zipStream = File.Create(zipPath);
        cryptoStream.CopyTo(zipStream);
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
    /// Runs <paramref name="action"/> with a fresh temp zip path inside the controlled workspace
    /// (<paramref name="workingDirectoryOverride"/> when supplied, else the default per-user
    /// restricted-ACL directory), deleting the archive afterwards.
    /// </summary>
    internal static void WithTempZip(Action<string> action, string? workingDirectoryOverride = null)
    {
        var tempZipPath = CryptoWorkspace.NewZipPath(workingDirectoryOverride);
        try
        {
            action(tempZipPath);
        }
        finally
        {
            if (File.Exists(tempZipPath))
                File.Delete(tempZipPath);
        }
    }
}
