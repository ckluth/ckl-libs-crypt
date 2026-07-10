using CKL.Libs.ResultPattern;

namespace CKL.Libs.Crypt.Contracts;

/// <summary>
/// Encryption for strings, byte arrays, files, and folders — currently symmetric (AES-CBC/PKCS7),
/// reporting outcomes as <see cref="Result"/>/<see cref="Result{TValue}"/> rather than exceptions.
/// </summary>
/// <remarks>
/// <para><b>Scope &amp; threat model.</b> This library provides <i>confidentiality</i> for data at
/// rest in a private, single-user context: you encrypt your own data and decrypt it yourself. It
/// deliberately does <b>not</b> provide integrity — ciphertext tampering is not detected — and it
/// assumes no adversary can submit chosen ciphertexts to a decryptor and observe the outcome. Do
/// <b>not</b> rely on it to detect tampering, and do <b>not</b> expose it as a decryption service
/// that reports success/failure on attacker-supplied input; either changes the threat model and
/// requires authenticated encryption instead. See ADR 0009 for the full rationale.</para>
/// <para>Password-based overloads derive a key with PBKDF2-HMAC-SHA256 (600,000 iterations,
/// 32-byte/AES-256 key) and write a self-describing container header, so decryption needs only the
/// original password.</para>
/// </remarks>
public interface ICryptoService
{
    /// <summary>Encrypts UTF-8 text, returning Base64-encoded ciphertext (container header prefixed).</summary>
    static abstract Result<string> EncryptString(string plainText, byte[] key);

    /// <summary>
    /// Password-based overload of <see cref="EncryptString(string, byte[])"/>: derives the key via
    /// PBKDF2 and writes a self-contained container header (KDF params + salt + IV), so the result
    /// needs only the original password to decrypt.
    /// </summary>
    static abstract Result<string> EncryptString(string plainText, string password);

    /// <summary>Decrypts Base64-encoded ciphertext produced by <see cref="EncryptString(string, byte[])"/>.</summary>
    static abstract Result<string> DecryptString(string cipherText, byte[] key);

    /// <summary>Reverses <see cref="EncryptString(string, string)"/>: reads the header, re-derives the key, then decrypts.</summary>
    static abstract Result<string> DecryptString(string cipherText, string password);

    /// <summary>Encrypts a byte array, returning the ciphertext with a prefixed container header.</summary>
    static abstract Result<byte[]> Encrypt(byte[] plainBytes, byte[] key);

    /// <summary>
    /// Password-based overload of <see cref="Encrypt(byte[], byte[])"/>: derives the key via PBKDF2
    /// and writes a self-contained container header (KDF params + salt + IV).
    /// </summary>
    static abstract Result<byte[]> Encrypt(byte[] plainBytes, string password);

    /// <summary>Decrypts a byte array produced by <see cref="Encrypt(byte[], byte[])"/>.</summary>
    static abstract Result<byte[]> Decrypt(byte[] cipherBytes, byte[] key);

    /// <summary>Reverses <see cref="Encrypt(byte[], string)"/>: reads the header, re-derives the key, then decrypts.</summary>
    static abstract Result<byte[]> Decrypt(byte[] cipherBytes, string password);

    /// <summary>
    /// Compresses then encrypts <paramref name="sourceFilePath"/> into
    /// <paramref name="destinationFilePath"/>, streaming throughout (no full-file buffering). The
    /// source file's <c>CreationTime</c>/<c>LastWriteTime</c>/<c>LastAccessTime</c> are captured and
    /// restored on decrypt (see ADR 0010); pass <paramref name="captureLastAccessTime"/> as
    /// <c>false</c> to omit <c>LastAccessTime</c>.
    /// </summary>
    static abstract Result EncryptFile(string sourceFilePath, string destinationFilePath, byte[] key, bool captureLastAccessTime = true);

    /// <summary>
    /// Password-based overload of <see cref="EncryptFile(string, string, byte[], bool)"/>: derives the key
    /// via PBKDF2 and writes a self-contained container header at the front of the destination file.
    /// </summary>
    static abstract Result EncryptFile(string sourceFilePath, string destinationFilePath, string password, bool captureLastAccessTime = true);

    /// <summary>
    /// Reverses <see cref="EncryptFile(string, string, byte[], bool)"/>: decrypts then decompresses,
    /// restoring the original <c>CreationTime</c>/<c>LastWriteTime</c>/<c>LastAccessTime</c> when the
    /// container carries them (see ADR 0010).
    /// </summary>
    static abstract Result DecryptFile(string sourceFilePath, string destinationFilePath, byte[] key);

    /// <summary>Reverses <see cref="EncryptFile(string, string, string, bool)"/>: reads the header, re-derives the key, then decrypts and decompresses.</summary>
    static abstract Result DecryptFile(string sourceFilePath, string destinationFilePath, string password);

    /// <summary>
    /// Zips <paramref name="sourceFolderPath"/> and encrypts the archive into
    /// <paramref name="destinationFilePath"/> as a single output file. The intermediate plaintext
    /// zip is staged in <paramref name="workingDirectory"/> when supplied, otherwise in a per-user
    /// restricted-ACL workspace (not the shared temp directory). The original
    /// <c>CreationTime</c>/<c>LastWriteTime</c>/<c>LastAccessTime</c> of the root folder, every
    /// subdirectory, and every file are captured and restored on decrypt (see ADR 0010); pass
    /// <paramref name="captureLastAccessTime"/> as <c>false</c> to omit <c>LastAccessTime</c>.
    /// </summary>
    static abstract Result EncryptFolder(string sourceFolderPath, string destinationFilePath, byte[] key, string? workingDirectory = null, bool captureLastAccessTime = true);

    /// <summary>
    /// Password-based overload of <see cref="EncryptFolder(string, string, byte[], string?, bool)"/>: derives the key
    /// via PBKDF2 and writes a self-contained container header at the front of the destination file.
    /// </summary>
    static abstract Result EncryptFolder(string sourceFolderPath, string destinationFilePath, string password, string? workingDirectory = null, bool captureLastAccessTime = true);

    /// <summary>
    /// Reverses <see cref="EncryptFolder(string, string, byte[], string?, bool)"/>: decrypts then extracts the archive into
    /// <paramref name="destinationFolderPath"/>. The intermediate plaintext zip is staged in
    /// <paramref name="workingDirectory"/> when supplied, otherwise in a per-user restricted-ACL
    /// workspace.
    /// </summary>
    static abstract Result DecryptFolder(string sourceFilePath, string destinationFolderPath, byte[] key, string? workingDirectory = null);

    /// <summary>Reverses <see cref="EncryptFolder(string, string, string, string?, bool)"/>: reads the header, re-derives the key, then decrypts and extracts.</summary>
    static abstract Result DecryptFolder(string sourceFilePath, string destinationFolderPath, string password, string? workingDirectory = null);

    /// <summary>
    /// Derives an AES-256 key from a password via PBKDF2-HMAC-SHA256 (600,000 iterations), returning
    /// the key and the randomly generated salt. Intended for the raw-key overloads when a caller
    /// wants to derive once and reuse the key; the caller is then responsible for persisting the
    /// salt alongside any ciphertext produced with it.
    /// </summary>
    static abstract Result<(byte[] Key, byte[] Salt)> DeriveKeyFromPassword(string password);
}
