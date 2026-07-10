using System.Security.Cryptography;
using System.Text;

namespace CKL.Libs.Crypt.Support;

/// <summary>
/// Password-to-key derivation via PBKDF2-HMAC-SHA256. Parameters are fixed by policy
/// (600,000 iterations, a 32-byte / AES-256 key, a 16-byte salt) and travel in the
/// <see cref="CryptoHeader"/>, so a blob is self-describing and can be re-derived without the
/// caller remembering anything but the password.
/// </summary>
internal static class KeyDerivation
{
    internal const int DefaultIterations = 600_000;
    internal const byte KeySize = 32;
    internal const int SaltLength = 16;

    /// <summary>
    /// Derives a fresh key for a newly generated random salt (the encrypt-side entry point).
    /// The returned salt, plus the fixed iteration/key-size policy, are what the caller records in
    /// the header.
    /// </summary>
    internal static (byte[] Key, byte[] Salt) DeriveForNewSalt(string password)
    {
        var salt = new byte[SaltLength];
        RandomNumberGenerator.Fill(salt);
        var key = Derive(password, salt, DefaultIterations, KeySize);
        return (key, salt);
    }

    /// <summary>
    /// Re-derives the key from the parameters carried in <paramref name="header"/> (the decrypt-side
    /// counterpart).
    /// </summary>
    internal static byte[] DeriveFromHeader(string password, CryptoHeader header) =>
        Derive(password, header.Salt, header.Iterations, header.KeySize);

    private static byte[] Derive(string password, byte[] salt, int iterations, int keySize)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var key = new byte[keySize];
        Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, key, iterations, HashAlgorithmName.SHA256);
        return key;
    }
}
