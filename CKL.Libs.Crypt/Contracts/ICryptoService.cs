using CKL.Libs.ResultPattern;

namespace CKL.Libs.Crypt.Contracts;

/// <summary>
/// Encryption for strings, byte arrays, files, and folders — currently symmetric (AES-CBC/PKCS7),
/// reporting outcomes as <see cref="Result"/>/<see cref="Result{TValue}"/> rather than exceptions.
/// </summary>
public interface ICryptoService
{
    /// <summary>Encrypts UTF-8 text, returning Base64-encoded ciphertext (IV prefixed).</summary>
    static abstract Result<string> EncryptString(string plainText, byte[] key);

    /// <summary>Decrypts Base64-encoded ciphertext produced by <see cref="EncryptString"/>.</summary>
    static abstract Result<string> DecryptString(string cipherText, byte[] key);

    /// <summary>Encrypts a byte array, returning the ciphertext with a prefixed random IV.</summary>
    static abstract Result<byte[]> Encrypt(byte[] plainBytes, byte[] key);

    /// <summary>Decrypts a byte array produced by <see cref="Encrypt"/>.</summary>
    static abstract Result<byte[]> Decrypt(byte[] cipherBytes, byte[] key);

    /// <summary>
    /// Compresses then encrypts <paramref name="sourceFilePath"/> into
    /// <paramref name="destinationFilePath"/>, streaming throughout (no full-file buffering).
    /// </summary>
    static abstract Result EncryptFile(string sourceFilePath, string destinationFilePath, byte[] key);

    /// <summary>Reverses <see cref="EncryptFile"/>: decrypts then decompresses.</summary>
    static abstract Result DecryptFile(string sourceFilePath, string destinationFilePath, byte[] key);

    /// <summary>
    /// Zips <paramref name="sourceFolderPath"/> and encrypts the archive into
    /// <paramref name="destinationFilePath"/> as a single output file.
    /// </summary>
    static abstract Result EncryptFolder(string sourceFolderPath, string destinationFilePath, byte[] key);

    /// <summary>
    /// Reverses <see cref="EncryptFolder"/>: decrypts then extracts the archive into
    /// <paramref name="destinationFolderPath"/>.
    /// </summary>
    static abstract Result DecryptFolder(string sourceFilePath, string destinationFolderPath, byte[] key);

    /// <summary>
    /// Derives an AES key from a password via PBKDF2 (SHA-256), returning the key and the
    /// randomly generated salt. The caller is responsible for persisting the salt alongside
    /// any ciphertext produced with the derived key.
    /// </summary>
    static abstract Result<(byte[] Key, byte[] Salt)> DeriveKeyFromPassword(string password, int iterations = 100_000, int keySize = 32);
}
