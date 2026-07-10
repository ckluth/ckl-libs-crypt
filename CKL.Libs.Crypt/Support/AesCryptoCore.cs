using System.Security.Cryptography;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Low-level AES-CBC/PKCS7 building blocks shared by the byte-array, file, and folder paths.
/// A random 16-byte IV is generated per encryption and travels as a prefix of the ciphertext.
/// </summary>
internal static class AesCryptoCore
{
    private const int IvLength = 16;

    internal static byte[] GenerateIv()
    {
        var iv = new byte[IvLength];
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

    /// <summary>Reads exactly the IV's bytes from <paramref name="cipherInput"/>.</summary>
    internal static byte[] ReadIv(Stream cipherInput)
    {
        var iv = new byte[IvLength];
        var bytesRead = 0;
        while (bytesRead < IvLength)
        {
            var read = cipherInput.Read(iv, bytesRead, IvLength - bytesRead);
            if (read == 0)
                throw new EndOfStreamException("Cipher stream ended before a full IV could be read.");
            bytesRead += read;
        }

        return iv;
    }

    internal static byte[] Encrypt(byte[] plainBytes, byte[] key)
    {
        var iv = GenerateIv();
        using var cipherStream = new MemoryStream();
        cipherStream.Write(iv, 0, iv.Length);
        WriteEncrypted(plainBytes, cipherStream, key, iv);
        return cipherStream.ToArray();
    }

    internal static byte[] Decrypt(byte[] cipherBytesWithIv, byte[] key)
    {
        var (iv, cipherBytes) = SplitIvAndCipher(cipherBytesWithIv);
        return ReadDecrypted(cipherBytes, key, iv);
    }

    private static void WriteEncrypted(byte[] plainBytes, Stream cipherOutput, byte[] key, byte[] iv)
    {
        using var aes = CreateAes(key, iv);
        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(cipherOutput, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
        cryptoStream.FlushFinalBlock();
    }

    private static byte[] ReadDecrypted(byte[] cipherBytes, byte[] key, byte[] iv)
    {
        using var aes = CreateAes(key, iv);
        using var decryptor = aes.CreateDecryptor();
        using var cipherStream = new MemoryStream(cipherBytes);
        using var cryptoStream = new CryptoStream(cipherStream, decryptor, CryptoStreamMode.Read);
        using var plainStream = new MemoryStream();
        cryptoStream.CopyTo(plainStream);
        return plainStream.ToArray();
    }

    private static (byte[] Iv, byte[] Cipher) SplitIvAndCipher(byte[] cipherBytesWithIv)
    {
        if (cipherBytesWithIv.Length < IvLength)
            throw new ArgumentException("Ciphertext is too short to contain an IV.", nameof(cipherBytesWithIv));

        var iv = new byte[IvLength];
        Buffer.BlockCopy(cipherBytesWithIv, 0, iv, 0, IvLength);
        var cipher = new byte[cipherBytesWithIv.Length - IvLength];
        Buffer.BlockCopy(cipherBytesWithIv, IvLength, cipher, 0, cipher.Length);
        return (iv, cipher);
    }
}
