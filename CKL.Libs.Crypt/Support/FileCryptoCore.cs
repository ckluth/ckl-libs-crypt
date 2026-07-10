using System.IO.Compression;
using System.Security.Cryptography;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Streaming compress-then-encrypt / decrypt-then-decompress pipeline for a single file.
/// Neither direction buffers the whole file in memory.
/// </summary>
internal static class FileCryptoCore
{
    internal static void EncryptFile(string sourceFilePath, string destinationFilePath, byte[] key)
    {
        using var destinationStream = File.Create(destinationFilePath);
        EncryptFileToStream(sourceFilePath, destinationStream, key);
    }

    internal static void DecryptFile(string sourceFilePath, string destinationFilePath, byte[] key)
    {
        using var sourceStream = File.OpenRead(sourceFilePath);
        DecryptStreamToFile(sourceStream, destinationFilePath, key);
    }

    /// <summary>
    /// Compresses then encrypts into an already-open <paramref name="destinationStream"/> — the
    /// password-based overloads use this to write a salt prefix ahead of the IV/ciphertext.
    /// </summary>
    internal static void EncryptFileToStream(string sourceFilePath, Stream destinationStream, byte[] key)
    {
        using var sourceStream = File.OpenRead(sourceFilePath);
        using var aes = PrepareEncryptingAes(destinationStream, key);
        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(destinationStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        using var gzipStream = new GZipStream(cryptoStream, CompressionMode.Compress);
        sourceStream.CopyTo(gzipStream);
    }

    /// <summary>
    /// Decrypts then decompresses from an already-positioned <paramref name="sourceStream"/> —
    /// the password-based overloads use this after consuming the salt prefix.
    /// </summary>
    internal static void DecryptStreamToFile(Stream sourceStream, string destinationFilePath, byte[] key)
    {
        using var aes = PrepareDecryptingAes(sourceStream, key);
        using var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(sourceStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        using var gzipStream = new GZipStream(cryptoStream, CompressionMode.Decompress);
        using var destinationStream = File.Create(destinationFilePath);
        gzipStream.CopyTo(destinationStream);
    }

    private static Aes PrepareEncryptingAes(Stream destinationStream, byte[] key)
    {
        var iv = AesCryptoCore.GenerateIv();
        destinationStream.Write(iv, 0, iv.Length);
        return AesCryptoCore.CreateAes(key, iv);
    }

    private static Aes PrepareDecryptingAes(Stream sourceStream, byte[] key)
    {
        var iv = AesCryptoCore.ReadIv(sourceStream);
        return AesCryptoCore.CreateAes(key, iv);
    }
}
