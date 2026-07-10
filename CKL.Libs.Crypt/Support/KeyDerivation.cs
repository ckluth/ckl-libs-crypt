using System.Security.Cryptography;
using System.Text;

namespace CKL.Libs.Crypt.Support;

/// <summary>Password-to-key derivation via PBKDF2.</summary>
internal static class KeyDerivation
{
    private const int SaltLength = 16;

    internal static (byte[] Key, byte[] Salt) DeriveFromPassword(string password, int iterations, int keySize)
    {
        var salt = new byte[SaltLength];
        RandomNumberGenerator.Fill(salt);

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var key = new byte[keySize];
        Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, key, iterations, HashAlgorithmName.SHA256);

        return (key, salt);
    }
}
