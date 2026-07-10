# CKL.Libs.Crypt

Encryption for strings, byte arrays, files, and folders — currently
symmetric (AES), reporting outcomes via `CKL.Libs.ResultPattern` instead of
exceptions.

Part of the `ckl-libs-<name>` family — see
[`ckl-builder`](https://github.com/ckluth/ckl-builder) for the ecosystem's
repo-family conventions and the decision-trail this repo follows.

---

## Quick start

```csharp
var key = RandomNumberGenerator.GetBytes(32); // AES-256 key

// Strings
var encrypted = CryptoService.EncryptString("Hello, CKL!", key);
var decrypted = CryptoService.DecryptString(encrypted.Value!, key);

// Byte arrays
var cipherBytes = CryptoService.Encrypt(plainBytes, key);
var plainBytes2 = CryptoService.Decrypt(cipherBytes.Value!, key);

// Files — compressed, then encrypted, streamed throughout
CryptoService.EncryptFile("document.pdf", "document.pdf.enc", key);
CryptoService.DecryptFile("document.pdf.enc", "document.pdf", key);

// Folders — zipped, then encrypted, as a single output file
CryptoService.EncryptFolder("my-folder", "my-folder.enc", key);
CryptoService.DecryptFolder("my-folder.enc", "my-folder-restored", key);

// Password-based key derivation (PBKDF2)
var derived = CryptoService.DeriveKeyFromPassword("a strong passphrase");
// derived.Value!.Key, derived.Value!.Salt — persist the salt alongside the ciphertext

// Password-based overloads — derive the key internally and prepend the
// generated salt to the output, so only the original password is needed to decrypt
var encryptedWithPw = CryptoService.EncryptString("Hello, CKL!", "a strong passphrase");
var decryptedWithPw = CryptoService.DecryptString(encryptedWithPw.Value!, "a strong passphrase");

CryptoService.EncryptFile("document.pdf", "document.pdf.enc", "a strong passphrase");
CryptoService.DecryptFile("document.pdf.enc", "document.pdf", "a strong passphrase");
```

Every method returns `Result`/`Result<TValue>` from `CKL.Libs.ResultPattern` —
check `.Succeeded` before using `.Value`; on failure, `.ErrorMessage` and
`.CallStackAsString` describe what went wrong.

## How it works

- **Strings/byte arrays** — AES-CBC with PKCS7 padding; a random 16-byte IV
  is generated per encryption and prefixed to the ciphertext.
- **Files** — compressed (GZip), then encrypted, streaming from source to
  destination without buffering the whole file in memory.
- **Folders** — zipped (which already compresses), then the archive is
  encrypted as a single output file; decrypting reverses both steps and
  extracts back into a destination folder.
- **Password-based overloads** — every encrypt/decrypt method has a
  `string password` overload. Encrypting derives a random salt + key via
  PBKDF2 and prepends the salt to the output, ahead of the IV/ciphertext;
  decrypting reads the salt back off, re-derives the key, and proceeds as
  usual — no separate salt management needed.

## For maintainers

.NET 10 SDK, C# (latest). Depends on `CKL.Libs.ResultPattern`.

```
CKL.Libs.Crypt\
├── CryptoService.cs             # Public, Result-native API
├── Contracts\
│   └── ICryptoService.cs        # API contract
└── Support\
    ├── AesCryptoCore.cs         # AES-CBC/PKCS7 building blocks
    ├── KeyDerivation.cs         # PBKDF2 password-to-key derivation
    ├── FileCryptoCore.cs        # Compress-then-encrypt streaming for files
    └── FolderCryptoCore.cs      # Zip-then-encrypt for folders
```

---

*CKL.Libs.Crypt — © 2026 ckluth — MIT License*
