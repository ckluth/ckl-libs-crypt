using System.IO.Compression;

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

        using var sourceStream = File.OpenRead(sourceFilePath);
        using var encryptor = AesCryptoCore.CreateEncryptor(destinationStream, key, header, leaveOpen: true);
        using (var gzipStream = new GZipStream(encryptor, CompressionMode.Compress, leaveOpen: true))
        {
            sourceStream.CopyTo(gzipStream);
        }
    }

    /// <summary>
    /// Reads the header from <paramref name="sourceStream"/>, resolves the key, then decrypts and
    /// decompresses into <paramref name="destinationFilePath"/>. When the header carries timestamps
    /// (see ADR 0010) they are re-applied to the restored file after it is fully written and closed.
    /// </summary>
    internal static void DecryptStreamToFile(Stream sourceStream, string destinationFilePath, Func<CryptoHeader, byte[]> resolveKey)
    {
        var (header, plaintext) = AesCryptoCore.CreateDecryptor(sourceStream, resolveKey, leaveOpen: true);
        try
        {
            using (var gzipStream = new GZipStream(plaintext, CompressionMode.Decompress, leaveOpen: true))
            using (var destinationStream = File.Create(destinationFilePath))
            {
                gzipStream.CopyTo(destinationStream);
            }

            // Drain any framed chunks the decompressor didn't pull, so the final chunk's tag is verified.
            plaintext.CopyTo(Stream.Null);
        }
        finally
        {
            plaintext.Dispose();
        }

        TimestampRestorer.Apply(destinationFilePath, header);
    }
}
