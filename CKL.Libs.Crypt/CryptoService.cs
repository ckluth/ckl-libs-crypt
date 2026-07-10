using System.Text;
using CKL.Libs.Crypt.Contracts;
using CKL.Libs.Crypt.Support;
using CKL.Libs.ResultPattern;

namespace CKL.Libs.Crypt;

/// <inheritdoc cref="ICryptoService" />
public sealed class CryptoService : ICryptoService
{
    // Never instantiated — the type only exists to carry the static, Result-native API below.
    private CryptoService()
    {
    }

    /// <inheritdoc />
    public static Result<string> EncryptString(string plainText, byte[] key)
    {
        try
        {
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherBytes = AesCryptoCore.Encrypt(plainBytes, key);
            return Convert.ToBase64String(cipherBytes);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result<string> DecryptString(string cipherText, byte[] key)
    {
        try
        {
            var cipherBytes = Convert.FromBase64String(cipherText);
            var plainBytes = AesCryptoCore.Decrypt(cipherBytes, key);
            return Encoding.UTF8.GetString(plainBytes);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result<byte[]> Encrypt(byte[] plainBytes, byte[] key)
    {
        try
        {
            return AesCryptoCore.Encrypt(plainBytes, key);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result<byte[]> Decrypt(byte[] cipherBytes, byte[] key)
    {
        try
        {
            return AesCryptoCore.Decrypt(cipherBytes, key);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result EncryptFile(string sourceFilePath, string destinationFilePath, byte[] key)
    {
        try
        {
            FileCryptoCore.EncryptFile(sourceFilePath, destinationFilePath, key);
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result DecryptFile(string sourceFilePath, string destinationFilePath, byte[] key)
    {
        try
        {
            FileCryptoCore.DecryptFile(sourceFilePath, destinationFilePath, key);
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result EncryptFolder(string sourceFolderPath, string destinationFilePath, byte[] key)
    {
        try
        {
            FolderCryptoCore.EncryptFolder(sourceFolderPath, destinationFilePath, key);
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result DecryptFolder(string sourceFilePath, string destinationFolderPath, byte[] key)
    {
        try
        {
            FolderCryptoCore.DecryptFolder(sourceFilePath, destinationFolderPath, key);
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result<(byte[] Key, byte[] Salt)> DeriveKeyFromPassword(string password, int iterations = 100_000, int keySize = 32)
    {
        try
        {
            return KeyDerivation.DeriveFromPassword(password, iterations, keySize);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }
}
