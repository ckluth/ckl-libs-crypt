using System.IO.Compression;

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
        using var zipStream = File.OpenRead(zipPath);
        using var encryptor = AesCryptoCore.CreateEncryptor(destinationStream, key, header, leaveOpen: true);
        zipStream.CopyTo(encryptor);
    }

    /// <summary>
    /// Reads the header from <paramref name="sourceStream"/>, resolves the key, then decrypts into
    /// the archive at <paramref name="zipPath"/>.
    /// </summary>
    internal static void DecryptStreamToZip(Stream sourceStream, string zipPath, Func<CryptoHeader, byte[]> resolveKey)
    {
        var (_, plaintext) = AesCryptoCore.CreateDecryptor(sourceStream, resolveKey, leaveOpen: true);
        using (plaintext)
        using (var zipStream = File.Create(zipPath))
        {
            plaintext.CopyTo(zipStream);
        }
    }

    /// <summary>
    /// Zips <paramref name="sourceFolderPath"/> into a fresh archive at <paramref name="zipDestinationPath"/>.
    /// A <c>__ckl_timestamps.json</c> manifest (see ADR 0010, <see cref="FolderTimestamps"/>) is
    /// written as the first entry, capturing the original <c>CreationTime</c>/<c>LastWriteTime</c>/
    /// <c>LastAccessTime</c> of the root folder, every subdirectory, and every file.
    /// </summary>
    internal static void CreateZip(string sourceFolderPath, string zipDestinationPath, bool captureLastAccessTime = true)
    {
        var manifestJson = FolderTimestamps.BuildManifestJson(sourceFolderPath, captureLastAccessTime);

        using var zip = ZipFile.Open(zipDestinationPath, ZipArchiveMode.Create);

        var manifestEntry = zip.CreateEntry(FolderTimestamps.ManifestEntryName, CompressionLevel.Optimal);
        using (var writer = new StreamWriter(manifestEntry.Open()))
        {
            writer.Write(manifestJson);
        }

        foreach (var directoryPath in Directory.EnumerateDirectories(sourceFolderPath, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(sourceFolderPath, directoryPath).Replace(Path.DirectorySeparatorChar, '/') + "/";
            zip.CreateEntry(relativePath);
        }

        foreach (var filePath in Directory.EnumerateFiles(sourceFolderPath, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(sourceFolderPath, filePath).Replace(Path.DirectorySeparatorChar, '/');
            zip.CreateEntryFromFile(filePath, relativePath, CompressionLevel.Optimal);
        }
    }

    /// <summary>
    /// Extracts the archive at <paramref name="zipPath"/> into <paramref name="destinationFolderPath"/>,
    /// then applies and removes the <c>__ckl_timestamps.json</c> manifest (see ADR 0010) if present.
    /// </summary>
    internal static void ExtractZip(string zipPath, string destinationFolderPath)
    {
        Directory.CreateDirectory(destinationFolderPath);
        ZipFile.ExtractToDirectory(zipPath, destinationFolderPath, overwriteFiles: true);

        var manifestPath = Path.Combine(destinationFolderPath, FolderTimestamps.ManifestEntryName);
        FolderTimestamps.ApplyAndRemoveManifest(destinationFolderPath, manifestPath);
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
