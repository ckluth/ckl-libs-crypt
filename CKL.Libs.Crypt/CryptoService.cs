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
            var cipherBytes = AesCryptoCore.EncryptWithHeader(Encoding.UTF8.GetBytes(plainText), key, RawKeyHeader());
            return Convert.ToBase64String(cipherBytes);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result<string> EncryptString(string plainText, string password)
    {
        try
        {
            var (key, header) = PasswordHeader(password);
            var cipherBytes = AesCryptoCore.EncryptWithHeader(Encoding.UTF8.GetBytes(plainText), key, header);
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
            var plainBytes = AesCryptoCore.DecryptWithHeader(Convert.FromBase64String(cipherText), _ => key);
            return Encoding.UTF8.GetString(plainBytes);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result<string> DecryptString(string cipherText, string password)
    {
        try
        {
            var plainBytes = AesCryptoCore.DecryptWithHeader(Convert.FromBase64String(cipherText), ResolveKey(password));
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
            return AesCryptoCore.EncryptWithHeader(plainBytes, key, RawKeyHeader());
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result<byte[]> Encrypt(byte[] plainBytes, string password)
    {
        try
        {
            var (key, header) = PasswordHeader(password);
            return AesCryptoCore.EncryptWithHeader(plainBytes, key, header);
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
            return AesCryptoCore.DecryptWithHeader(cipherBytes, _ => key);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result<byte[]> Decrypt(byte[] cipherBytes, string password)
    {
        try
        {
            return AesCryptoCore.DecryptWithHeader(cipherBytes, ResolveKey(password));
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result EncryptFile(string sourceFilePath, string destinationFilePath, byte[] key, bool captureLastAccessTime = true)
    {
        try
        {
            using var destinationStream = File.Create(destinationFilePath);
            FileCryptoCore.EncryptFileToStream(sourceFilePath, destinationStream, key, RawKeyHeader(), captureLastAccessTime);
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result EncryptFile(string sourceFilePath, string destinationFilePath, string password, bool captureLastAccessTime = true)
    {
        try
        {
            var (key, header) = PasswordHeader(password);
            using var destinationStream = File.Create(destinationFilePath);
            FileCryptoCore.EncryptFileToStream(sourceFilePath, destinationStream, key, header, captureLastAccessTime);
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
            using var sourceStream = File.OpenRead(sourceFilePath);
            FileCryptoCore.DecryptStreamToFile(sourceStream, destinationFilePath, _ => key);
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result DecryptFile(string sourceFilePath, string destinationFilePath, string password)
    {
        try
        {
            using var sourceStream = File.OpenRead(sourceFilePath);
            FileCryptoCore.DecryptStreamToFile(sourceStream, destinationFilePath, ResolveKey(password));
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result EncryptFolder(string sourceFolderPath, string destinationFilePath, byte[] key, string? workingDirectory = null, bool captureLastAccessTime = true)
    {
        try
        {
            EncryptFolderToFile(sourceFolderPath, destinationFilePath, key, RawKeyHeader(), workingDirectory, captureLastAccessTime);
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result EncryptFolder(string sourceFolderPath, string destinationFilePath, string password, string? workingDirectory = null, bool captureLastAccessTime = true)
    {
        try
        {
            var (key, header) = PasswordHeader(password);
            EncryptFolderToFile(sourceFolderPath, destinationFilePath, key, header, workingDirectory, captureLastAccessTime);
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result DecryptFolder(string sourceFilePath, string destinationFolderPath, byte[] key, string? workingDirectory = null)
    {
        try
        {
            DecryptFileToFolder(sourceFilePath, destinationFolderPath, _ => key, workingDirectory);
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result DecryptFolder(string sourceFilePath, string destinationFolderPath, string password, string? workingDirectory = null)
    {
        try
        {
            DecryptFileToFolder(sourceFilePath, destinationFolderPath, ResolveKey(password), workingDirectory);
            return Result.Success;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <inheritdoc />
    public static Result<(byte[] Key, byte[] Salt)> DeriveKeyFromPassword(string password)
    {
        try
        {
            return KeyDerivation.DeriveForNewSalt(password);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    private static CryptoHeader RawKeyHeader() =>
        CryptoHeader.ForRawKey(AesCryptoCore.GenerateIv());

    private static (byte[] Key, CryptoHeader Header) PasswordHeader(string password)
    {
        var (key, salt) = KeyDerivation.DeriveForNewSalt(password);
        var header = CryptoHeader.ForPbkdf2(KeyDerivation.DefaultIterations, KeyDerivation.KeySize, salt, AesCryptoCore.GenerateIv());
        return (key, header);
    }

    private static Func<CryptoHeader, byte[]> ResolveKey(string password) =>
        header => KeyDerivation.DeriveFromHeader(password, header);

    private static void EncryptFolderToFile(string sourceFolderPath, string destinationFilePath, byte[] key, CryptoHeader header, string? workingDirectory, bool captureLastAccessTime) =>
        FolderCryptoCore.WithTempZip(tempZipPath =>
        {
            FolderCryptoCore.CreateZip(sourceFolderPath, tempZipPath, captureLastAccessTime);
            using var destinationStream = File.Create(destinationFilePath);
            FolderCryptoCore.EncryptZipToStream(tempZipPath, destinationStream, key, header);
        }, workingDirectory);

    private static void DecryptFileToFolder(string sourceFilePath, string destinationFolderPath, Func<CryptoHeader, byte[]> resolveKey, string? workingDirectory) =>
        FolderCryptoCore.WithTempZip(tempZipPath =>
        {
            using (var sourceStream = File.OpenRead(sourceFilePath))
            {
                FolderCryptoCore.DecryptStreamToZip(sourceStream, tempZipPath, resolveKey);
            }

            FolderCryptoCore.ExtractZip(tempZipPath, destinationFolderPath);
        }, workingDirectory);
}
