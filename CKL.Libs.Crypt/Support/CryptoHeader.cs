using System.Buffers.Binary;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Bit flags carried in <see cref="CryptoHeader.Flags"/>. See ADR 0010.
/// </summary>
[Flags]
internal enum HeaderFlags : byte
{
    None = 0x00,

    /// <summary>The optional 24-byte timestamp block follows the KDF block.</summary>
    TimestampsPresent = 0x01,

    /// <summary>
    /// The <c>accessed</c> field in the timestamp block is not meaningful (written as zero) —
    /// the caller opted out of capturing <c>LastAccessTime</c>.
    /// </summary>
    LastAccessTimeOmitted = 0x02
}

/// <summary>
/// The v2 container format written ahead of every ciphertext (strings, byte arrays, files, and
/// folders). A cleartext, self-describing prefix — nothing here is authenticated (integrity is out
/// of scope, see ADR 0009) — that carries the format version, a flags byte, the key-derivation
/// identity and its parameters, an optional original-timestamp block (see ADR 0010), and the
/// per-encryption AES-CBC IV. One layout serves both the raw-key path (<see cref="KdfIdNone"/>) and
/// the password path (<see cref="KdfIdPbkdf2"/>).
/// </summary>
/// <remarks>
/// Byte layout:
/// <code>
/// [ magic:      4 bytes ]   ASCII "CKLC"
/// [ version:    1 byte  ]   0x02
/// [ flags:      1 byte  ]   bit 0 = timestamps present; bit 1 = LastAccessTime omitted
/// [ kdf-id:     1 byte  ]   0x00 = none (raw key) | 0x01 = PBKDF2-HMAC-SHA256
///   — if kdf-id == 0x01:
///       [ iterations: 4 bytes ]  big-endian uint32
///       [ key-size:   1 byte  ]
///       [ salt-len:   1 byte  ]
///       [ salt:       N bytes ]
///   — if flags bit 0 set:
///       [ created:    8 bytes ]  DateTimeOffset UTC ticks, Int64 big-endian
///       [ modified:   8 bytes ]  DateTimeOffset UTC ticks, Int64 big-endian
///       [ accessed:   8 bytes ]  DateTimeOffset UTC ticks, Int64 big-endian (0 if bit 1 set)
/// [ iv:         16 bytes ]
/// [ ciphertext: … ]
/// </code>
/// </remarks>
internal readonly record struct CryptoHeader(
    byte KdfId,
    int Iterations,
    byte KeySize,
    byte[] Salt,
    byte[] Iv,
    HeaderFlags Flags = HeaderFlags.None,
    DateTimeOffset? CreatedUtc = null,
    DateTimeOffset? ModifiedUtc = null,
    DateTimeOffset? AccessedUtc = null)
{
    private static readonly byte[] Magic = "CKLC"u8.ToArray();

    internal const byte Version = 0x02;
    internal const byte KdfIdNone = 0x00;
    internal const byte KdfIdPbkdf2 = 0x01;
    internal const int IvLength = 16;
    internal const int TimestampBlockLength = 24;

    /// <summary>Builds the header for a raw-key encryption (no KDF, no salt).</summary>
    internal static CryptoHeader ForRawKey(byte[] iv) =>
        new(KdfIdNone, 0, 0, [], iv);

    /// <summary>Builds the header for a password (PBKDF2) encryption.</summary>
    internal static CryptoHeader ForPbkdf2(int iterations, byte keySize, byte[] salt, byte[] iv) =>
        new(KdfIdPbkdf2, iterations, keySize, salt, iv);

    /// <summary>
    /// Returns a copy of this header carrying the original file-system timestamps
    /// (see ADR 0010). Pass <paramref name="accessedUtc"/> as <c>null</c> to omit
    /// <c>LastAccessTime</c> (sets <see cref="HeaderFlags.LastAccessTimeOmitted"/>).
    /// </summary>
    internal CryptoHeader WithTimestamps(DateTimeOffset createdUtc, DateTimeOffset modifiedUtc, DateTimeOffset? accessedUtc)
    {
        var flags = Flags | HeaderFlags.TimestampsPresent;
        if (accessedUtc is null)
            flags |= HeaderFlags.LastAccessTimeOmitted;

        return this with
        {
            Flags = flags,
            CreatedUtc = createdUtc,
            ModifiedUtc = modifiedUtc,
            AccessedUtc = accessedUtc ?? DateTimeOffset.UnixEpoch
        };
    }

    /// <summary>Serializes the header to a fresh byte array.</summary>
    internal byte[] ToBytes()
    {
        using var stream = new MemoryStream();
        WriteTo(stream);
        return stream.ToArray();
    }

    /// <summary>Writes the header to <paramref name="output"/>, ahead of the ciphertext.</summary>
    internal void WriteTo(Stream output)
    {
        output.Write(Magic, 0, Magic.Length);
        output.WriteByte(Version);
        output.WriteByte((byte)Flags);
        output.WriteByte(KdfId);

        if (KdfId == KdfIdPbkdf2)
            WritePbkdf2Params(output);

        if (Flags.HasFlag(HeaderFlags.TimestampsPresent))
            WriteTimestampBlock(output);

        output.Write(Iv, 0, Iv.Length);
    }

    private void WriteTimestampBlock(Stream output)
    {
        Span<byte> buffer = stackalloc byte[sizeof(long)];

        BinaryPrimitives.WriteInt64BigEndian(buffer, (CreatedUtc ?? DateTimeOffset.UnixEpoch).UtcTicks);
        output.Write(buffer);

        BinaryPrimitives.WriteInt64BigEndian(buffer, (ModifiedUtc ?? DateTimeOffset.UnixEpoch).UtcTicks);
        output.Write(buffer);

        BinaryPrimitives.WriteInt64BigEndian(buffer, (AccessedUtc ?? DateTimeOffset.UnixEpoch).UtcTicks);
        output.Write(buffer);
    }

    private void WritePbkdf2Params(Stream output)
    {
        Span<byte> iterationBytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(iterationBytes, (uint)Iterations);
        output.Write(iterationBytes);
        output.WriteByte(KeySize);
        output.WriteByte((byte)Salt.Length);
        output.Write(Salt, 0, Salt.Length);
    }

    /// <summary>
    /// Reads and validates a header from <paramref name="input"/>, leaving the stream positioned at
    /// the start of the ciphertext.
    /// </summary>
    internal static CryptoHeader ReadFrom(Stream input)
    {
        var magic = ReadExactly(input, Magic.Length);
        if (!magic.AsSpan().SequenceEqual(Magic))
            throw new InvalidDataException("Not a CKL.Libs.Crypt container (bad magic).");

        var version = ReadByteOrThrow(input);
        if (version != Version)
            throw new InvalidDataException($"Unsupported container version 0x{version:X2} (expected 0x{Version:X2}).");

        var flags = (HeaderFlags)ReadByteOrThrow(input);
        var kdfId = ReadByteOrThrow(input);
        var header = kdfId switch
        {
            KdfIdNone => ForRawKey(iv: []),
            KdfIdPbkdf2 => ReadPbkdf2(input),
            _ => throw new InvalidDataException($"Unknown key-derivation id 0x{kdfId:X2}.")
        };

        header = header with { Flags = flags };

        if (flags.HasFlag(HeaderFlags.TimestampsPresent))
            header = ReadTimestampBlock(input, header);

        return header with { Iv = ReadExactly(input, IvLength) };
    }

    private static CryptoHeader ReadTimestampBlock(Stream input, CryptoHeader header)
    {
        var created = ReadTicks(input);
        var modified = ReadTicks(input);
        var accessed = ReadTicks(input);

        return header with
        {
            CreatedUtc = created,
            ModifiedUtc = modified,
            AccessedUtc = header.Flags.HasFlag(HeaderFlags.LastAccessTimeOmitted) ? null : accessed
        };
    }

    private static DateTimeOffset ReadTicks(Stream input)
    {
        var ticks = BinaryPrimitives.ReadInt64BigEndian(ReadExactly(input, sizeof(long)));
        return new DateTimeOffset(ticks, TimeSpan.Zero);
    }

    private static CryptoHeader ReadPbkdf2(Stream input)
    {
        var iterations = (int)BinaryPrimitives.ReadUInt32BigEndian(ReadExactly(input, sizeof(uint)));
        var keySize = ReadByteOrThrow(input);
        var saltLength = ReadByteOrThrow(input);
        var salt = ReadExactly(input, saltLength);
        return ForPbkdf2(iterations, keySize, salt, iv: []);
    }

    private static byte ReadByteOrThrow(Stream input)
    {
        var value = input.ReadByte();
        if (value < 0)
            throw new EndOfStreamException("Container stream ended inside the header.");
        return (byte)value;
    }

    private static byte[] ReadExactly(Stream input, int count)
    {
        var buffer = new byte[count];
        var read = 0;
        while (read < count)
        {
            var chunk = input.Read(buffer, read, count - read);
            if (chunk == 0)
                throw new EndOfStreamException("Container stream ended inside the header.");
            read += chunk;
        }

        return buffer;
    }
}
