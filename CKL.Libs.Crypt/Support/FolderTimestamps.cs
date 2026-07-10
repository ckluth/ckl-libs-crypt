using System.Text.Json;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Captures and restores per-entry file-system timestamps for a folder encrypted via the zip
/// pipeline (see ADR 0010). ZIP has no <c>CreationTime</c> field and the root folder itself is not
/// a zip entry at all, so timestamps travel as a small JSON manifest written as the <b>first</b>
/// entry of the archive (<see cref="ManifestEntryName"/>), stripped and applied again after
/// extraction.
/// </summary>
internal static class FolderTimestamps
{
    internal const string ManifestEntryName = "__ckl_timestamps.json";

    private const string RootKey = ".";

    private sealed record Entry(bool IsDirectory, long CreatedTicks, long ModifiedTicks, long? AccessedTicks);

    /// <summary>
    /// Builds the timestamp manifest for <paramref name="sourceFolderPath"/> (every file, every
    /// subdirectory, and the root itself) as JSON, ready to be written as the manifest zip entry.
    /// Throws <see cref="InvalidOperationException"/> if the source tree already contains a
    /// reserved-name entry (<see cref="ManifestEntryName"/>).
    /// </summary>
    internal static string BuildManifestJson(string sourceFolderPath, bool captureLastAccessTime)
    {
        var entries = new Dictionary<string, Entry>
        {
            [RootKey] = ReadEntry(sourceFolderPath, isDirectory: true, captureLastAccessTime)
        };

        foreach (var path in Directory.EnumerateFileSystemEntries(sourceFolderPath, "*", SearchOption.AllDirectories))
        {
            var name = Path.GetFileName(path);
            if (string.Equals(name, ManifestEntryName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    $"Source folder contains a reserved entry named '{ManifestEntryName}'; rename or remove it before encrypting.");

            var relativePath = Path.GetRelativePath(sourceFolderPath, path).Replace(Path.DirectorySeparatorChar, '/');
            var isDirectory = Directory.Exists(path);
            entries[relativePath] = ReadEntry(path, isDirectory, captureLastAccessTime);
        }

        return JsonSerializer.Serialize(entries);
    }

    /// <summary>
    /// Reads the manifest (if any) from <paramref name="manifestPath"/>, deletes it, then applies
    /// every recorded timestamp under <paramref name="extractedFolderPath"/> — deepest entries first,
    /// so restoring a child's timestamps never bumps a parent directory's <c>LastWriteTime</c>.
    /// </summary>
    internal static void ApplyAndRemoveManifest(string extractedFolderPath, string manifestPath)
    {
        if (!File.Exists(manifestPath))
            return;

        var json = File.ReadAllText(manifestPath);
        File.Delete(manifestPath);

        var entries = JsonSerializer.Deserialize<Dictionary<string, Entry>>(json);
        if (entries is null)
            return;

        foreach (var (relativePath, entry) in entries.OrderByDescending(Depth))
        {
            var fullPath = relativePath == RootKey
                ? extractedFolderPath
                : Path.Combine(extractedFolderPath, relativePath.Replace('/', Path.DirectorySeparatorChar));

            var created = new DateTimeOffset(entry.CreatedTicks, TimeSpan.Zero);
            var modified = new DateTimeOffset(entry.ModifiedTicks, TimeSpan.Zero);
            var accessed = entry.AccessedTicks is { } ticks ? new DateTimeOffset(ticks, TimeSpan.Zero) : (DateTimeOffset?)null;

            if (entry.IsDirectory)
                TimestampRestorer.ApplyToDirectory(fullPath, created, modified, accessed);
            else if (File.Exists(fullPath))
                TimestampRestorer.ApplyToFile(fullPath, created, modified, accessed);
        }
    }

    private static int Depth(KeyValuePair<string, Entry> pair) =>
        pair.Key == RootKey ? -1 : pair.Key.Count(c => c == '/');

    private static Entry ReadEntry(string path, bool isDirectory, bool captureLastAccessTime)
    {
        var (createdUtc, modifiedUtc, accessedUtc) = isDirectory
            ? (Directory.GetCreationTimeUtc(path), Directory.GetLastWriteTimeUtc(path), Directory.GetLastAccessTimeUtc(path))
            : (File.GetCreationTimeUtc(path), File.GetLastWriteTimeUtc(path), File.GetLastAccessTimeUtc(path));

        return new Entry(
            isDirectory,
            createdUtc.Ticks,
            modifiedUtc.Ticks,
            captureLastAccessTime ? accessedUtc.Ticks : null);
    }
}
