using System.IO.Compression;
using System.Security.Cryptography;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Streaming compress-then-encrypt / decrypt-then-decompress pipeline for a single file.
/// The <see cref="CryptoHeader"/> is written/read at the front of the destination/source stream;
/// neither direction buffers the whole file in memory.
/// </summary>
internal static class FileCryptoCore
{
    /// <summary>
    /// Compresses then encrypts <paramref name="sourceFilePath"/> into an already-open stream. The
    /// source file's <c>CreationTime</c>/<c>LastWriteTime</c>/<c>LastAccessTime</c> are captured into
    /// the header (see ADR 0010) unless <paramref name="captureLastAccessTime"/> is <c>false</c>.
    /// </summary>
    internal static void EncryptFileToStream(string sourceFilePath, Stream destinationStream, byte[] key, CryptoHeader header, bool captureLastAccessTime = true)
    {
        var info = new FileInfo(sourceFilePath);
        header = header.WithTimestamps(info.CreationTimeUtc, info.LastWriteTimeUtc, captureLastAccessTime ? info.LastAccessTimeUtc : null);
        header.WriteTo(destinationStream);
        using var sourceStream = File.OpenRead(sourceFilePath);
        using var aes = AesCryptoCore.CreateAes(key, header.Iv);
        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(destinationStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        using var gzipStream = new GZipStream(cryptoStream, CompressionMode.Compress);
        sourceStream.CopyTo(gzipStream);
    }

    /// <summary>
    /// Reads the header from <paramref name="sourceStream"/>, resolves the key, then decrypts and
    /// decompresses into <paramref name="destinationFilePath"/>. When the header carries timestamps
    /// (see ADR 0010) they are re-applied to the restored file after it is fully written and closed.
    /// </summary>
    internal static void DecryptStreamToFile(Stream sourceStream, string destinationFilePath, Func<CryptoHeader, byte[]> resolveKey)
    {
        var header = CryptoHeader.ReadFrom(sourceStream);
        var key = resolveKey(header);
        using (var aes = AesCryptoCore.CreateAes(key, header.Iv))
        using (var decryptor = aes.CreateDecryptor())
        using (var cryptoStream = new CryptoStream(sourceStream, decryptor, CryptoStreamMode.Read, leaveOpen: true))
        using (var gzipStream = new GZipStream(cryptoStream, CompressionMode.Decompress))
        using (var destinationStream = File.Create(destinationFilePath))
        {
            gzipStream.CopyTo(destinationStream);
        }

        TimestampRestorer.Apply(destinationFilePath, header);
    }
}
