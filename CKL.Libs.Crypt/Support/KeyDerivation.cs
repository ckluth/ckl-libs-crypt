using System.Security.Cryptography;
using System.Text;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Password-to-key derivation via PBKDF2. A random 16-byte salt is generated per encryption and
/// travels as a prefix of the output (string/byte[]/file/folder), mirroring how <see cref="AesCryptoCore"/>
/// prepends the IV.
/// </summary>
internal static class KeyDerivation
{
    internal const int SaltLength = 16;

    internal static (byte[] Key, byte[] Salt) DeriveFromPassword(string password, int iterations, int keySize)
    {
        var salt = new byte[SaltLength];
        RandomNumberGenerator.Fill(salt);
        var key = DeriveFromPassword(password, salt, iterations, keySize);
        return (key, salt);
    }

    /// <summary>Re-derives the key for a known salt (the decrypt-side counterpart).</summary>
    internal static byte[] DeriveFromPassword(string password, byte[] salt, int iterations, int keySize)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var key = new byte[keySize];
        Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, key, iterations, HashAlgorithmName.SHA256);
        return key;
    }

    /// <summary>Reads exactly the salt's bytes from <paramref name="saltedInput"/>.</summary>
    internal static byte[] ReadSalt(Stream saltedInput)
    {
        var salt = new byte[SaltLength];
        var bytesRead = 0;
        while (bytesRead < SaltLength)
        {
            var read = saltedInput.Read(salt, bytesRead, SaltLength - bytesRead);
            if (read == 0)
                throw new EndOfStreamException("Salted stream ended before a full salt could be read.");
            bytesRead += read;
        }

        return salt;
    }

    internal static byte[] Prepend(byte[] salt, byte[] payload)
    {
        var result = new byte[salt.Length + payload.Length];
        Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
        Buffer.BlockCopy(payload, 0, result, salt.Length, payload.Length);
        return result;
    }

    internal static (byte[] Salt, byte[] Payload) SplitSaltAndPayload(byte[] saltedPayload)
    {
        if (saltedPayload.Length < SaltLength)
            throw new ArgumentException("Input is too short to contain a salt.", nameof(saltedPayload));

        var salt = new byte[SaltLength];
        Buffer.BlockCopy(saltedPayload, 0, salt, 0, SaltLength);
        var payload = new byte[saltedPayload.Length - SaltLength];
        Buffer.BlockCopy(saltedPayload, SaltLength, payload, 0, payload.Length);
        return (salt, payload);
    }
}
