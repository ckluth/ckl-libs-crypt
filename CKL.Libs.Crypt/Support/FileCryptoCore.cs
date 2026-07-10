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
        using var sourceStream = File.OpenRead(sourceFilePath);
        using var destinationStream = File.Create(destinationFilePath);
        using var aes = PrepareEncryptingAes(destinationStream, key);
        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(destinationStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        using var gzipStream = new GZipStream(cryptoStream, CompressionMode.Compress);
        sourceStream.CopyTo(gzipStream);
    }

    internal static void DecryptFile(string sourceFilePath, string destinationFilePath, byte[] key)
    {
        using var sourceStream = File.OpenRead(sourceFilePath);
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
