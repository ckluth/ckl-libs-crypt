using System.Security.Cryptography;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Low-level AES-CBC/PKCS7 building blocks shared by the byte-array, file, and folder paths.
/// The per-encryption 16-byte IV lives in the <see cref="CryptoHeader"/> that prefixes every
/// ciphertext; this type only performs the CBC transform and composes header + ciphertext for the
/// in-memory (string/byte-array) path.
/// </summary>
internal static class AesCryptoCore
{
    internal static byte[] GenerateIv()
    {
        var iv = new byte[CryptoHeader.IvLength];
        RandomNumberGenerator.Fill(iv);
        return iv;
    }

    internal static Aes CreateAes(byte[] key, byte[] iv)
    {
        var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Padding = PaddingMode.PKCS7;
        return aes;
    }

    /// <summary>Writes <paramref name="header"/> then the CBC ciphertext of <paramref name="plainBytes"/>.</summary>
    internal static byte[] EncryptWithHeader(byte[] plainBytes, byte[] key, CryptoHeader header)
    {
        using var output = new MemoryStream();
        header.WriteTo(output);
        WriteCbc(plainBytes, output, key, header.Iv);
        return output.ToArray();
    }

    /// <summary>
    /// Reads and validates the header, resolves the key from it (raw-key callers ignore the header;
    /// password callers re-derive), then CBC-decrypts the remaining bytes.
    /// </summary>
    internal static byte[] DecryptWithHeader(byte[] inputBytes, Func<CryptoHeader, byte[]> resolveKey)
    {
        using var source = new MemoryStream(inputBytes);
        var header = CryptoHeader.ReadFrom(source);
        var key = resolveKey(header);
        return ReadCbc(source, key, header.Iv);
    }

    private static void WriteCbc(byte[] plainBytes, Stream cipherOutput, byte[] key, byte[] iv)
    {
        using var aes = CreateAes(key, iv);
        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(cipherOutput, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
        cryptoStream.FlushFinalBlock();
    }

    private static byte[] ReadCbc(Stream cipherSource, byte[] key, byte[] iv)
    {
        using var aes = CreateAes(key, iv);
        using var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(cipherSource, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        using var plainStream = new MemoryStream();
        cryptoStream.CopyTo(plainStream);
        return plainStream.ToArray();
    }
}
