namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Applies the original file-system timestamps carried in a <see cref="CryptoHeader"/> (see
/// ADR 0010) back onto a restored file or directory. A no-op when the header carries no timestamp
/// block.
/// </summary>
internal static class TimestampRestorer
{
    /// <summary>Applies <paramref name="header"/>'s timestamps to the file at <paramref name="path"/>, if present.</summary>
    internal static void Apply(string path, CryptoHeader header)
    {
        if (!header.Flags.HasFlag(HeaderFlags.TimestampsPresent))
            return;

        if (header.CreatedUtc is { } created)
            File.SetCreationTimeUtc(path, created.UtcDateTime);

        if (header.ModifiedUtc is { } modified)
            File.SetLastWriteTimeUtc(path, modified.UtcDateTime);

        if (header.AccessedUtc is { } accessed)
            File.SetLastAccessTimeUtc(path, accessed.UtcDateTime);
    }

    /// <summary>Applies explicit timestamps to the file at <paramref name="path"/>.</summary>
    internal static void ApplyToFile(string path, DateTimeOffset? createdUtc, DateTimeOffset? modifiedUtc, DateTimeOffset? accessedUtc)
    {
        if (createdUtc is { } created)
            File.SetCreationTimeUtc(path, created.UtcDateTime);

        if (modifiedUtc is { } modified)
            File.SetLastWriteTimeUtc(path, modified.UtcDateTime);

        if (accessedUtc is { } accessed)
            File.SetLastAccessTimeUtc(path, accessed.UtcDateTime);
    }

    /// <summary>Applies explicit timestamps to the directory at <paramref name="path"/>.</summary>
    internal static void ApplyToDirectory(string path, DateTimeOffset? createdUtc, DateTimeOffset? modifiedUtc, DateTimeOffset? accessedUtc)
    {
        if (createdUtc is { } created)
            Directory.SetCreationTimeUtc(path, created.UtcDateTime);

        if (modifiedUtc is { } modified)
            Directory.SetLastWriteTimeUtc(path, modified.UtcDateTime);

        if (accessedUtc is { } accessed)
            Directory.SetLastAccessTimeUtc(path, accessed.UtcDateTime);
    }
}
