using System.Buffers.Binary;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// The v2 container format written ahead of every ciphertext (strings, byte arrays, files, and
/// folders). A cleartext, self-describing prefix — nothing here is authenticated (integrity is out
/// of scope, see ADR 0009) — that carries the format version, the key-derivation identity and its
/// parameters, and the per-encryption AES-CBC IV. One layout serves both the raw-key path
/// (<see cref="KdfIdNone"/>) and the password path (<see cref="KdfIdPbkdf2"/>).
/// </summary>
/// <remarks>
/// Byte layout:
/// <code>
/// [ magic:      4 bytes ]   ASCII "CKLC"
/// [ version:    1 byte  ]   0x02
/// [ kdf-id:     1 byte  ]   0x00 = none (raw key) | 0x01 = PBKDF2-HMAC-SHA256
///   — if kdf-id == 0x01:
///       [ iterations: 4 bytes ]  big-endian uint32
///       [ key-size:   1 byte  ]
///       [ salt-len:   1 byte  ]
///       [ salt:       N bytes ]
/// [ iv:         16 bytes ]
/// [ ciphertext: … ]
/// </code>
/// </remarks>
internal readonly record struct CryptoHeader(byte KdfId, int Iterations, byte KeySize, byte[] Salt, byte[] Iv)
{
    private static readonly byte[] Magic = "CKLC"u8.ToArray();

    internal const byte Version = 0x02;
    internal const byte KdfIdNone = 0x00;
    internal const byte KdfIdPbkdf2 = 0x01;
    internal const int IvLength = 16;

    /// <summary>Builds the header for a raw-key encryption (no KDF, no salt).</summary>
    internal static CryptoHeader ForRawKey(byte[] iv) =>
        new(KdfIdNone, 0, 0, [], iv);

    /// <summary>Builds the header for a password (PBKDF2) encryption.</summary>
    internal static CryptoHeader ForPbkdf2(int iterations, byte keySize, byte[] salt, byte[] iv) =>
        new(KdfIdPbkdf2, iterations, keySize, salt, iv);

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
        output.WriteByte(KdfId);

        if (KdfId == KdfIdPbkdf2)
            WritePbkdf2Params(output);

        output.Write(Iv, 0, Iv.Length);
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

        var kdfId = ReadByteOrThrow(input);
        return kdfId switch
        {
            KdfIdNone => ForRawKey(ReadExactly(input, IvLength)),
            KdfIdPbkdf2 => ReadPbkdf2(input),
            _ => throw new InvalidDataException($"Unknown key-derivation id 0x{kdfId:X2}.")
        };
    }

    private static CryptoHeader ReadPbkdf2(Stream input)
    {
        var iterations = (int)BinaryPrimitives.ReadUInt32BigEndian(ReadExactly(input, sizeof(uint)));
        var keySize = ReadByteOrThrow(input);
        var saltLength = ReadByteOrThrow(input);
        var salt = ReadExactly(input, saltLength);
        var iv = ReadExactly(input, IvLength);
        return ForPbkdf2(iterations, keySize, salt, iv);
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
