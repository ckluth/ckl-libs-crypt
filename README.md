# CKL.Libs.Crypt

Encryption for strings, byte arrays, files, and folders — currently
symmetric (AES), reporting outcomes via `CKL.Libs.ResultPattern` instead of
exceptions.

Part of the `ckl-libs-<name>` family — see
[`ckl-builder`](https://github.com/ckluth/ckl-builder) for the ecosystem's
repo-family conventions and the decision-trail this repo follows.

---

## Scope & threat model

**Read this before use.** This library provides **confidentiality** for data at
rest in a **private, single-user** context: you encrypt your own data and
decrypt it yourself. Two assumptions are deliberately baked in:

1. **No integrity requirement.** It does **not** detect tampering with
   ciphertext. AES-CBC is unauthenticated; a modified ciphertext is not caught.
2. **No interactive decryption oracle.** It assumes no adversary can submit
   chosen ciphertexts to a decryptor and observe the outcome
   (success/failure/error/timing).

Under those assumptions the library is a sound at-rest confidentiality tool.
**Do not** use it where either fails:

- **Do not expose it as a decryption service/API** that decrypts input you did
  not produce and reports success/failure — that recreates a padding-oracle
  surface (a *confidentiality* break).
- **Do not rely on it to detect tampering** — if silent modification of stored
  ciphertext would be harmful, you need authenticated encryption (e.g. AES-GCM),
  which this library does not currently provide.

If your context breaks either assumption, this library is the wrong tool as-is.
The rationale, and the deferred authenticated-encryption path, are recorded in
`ckl-builder` ADR 0009.

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
// Optional: stage the intermediate zip in a directory you choose
CryptoService.EncryptFolder("my-folder", "my-folder.enc", key, workingDirectory: @"D:\scratch");

// Password-based key derivation (PBKDF2-HMAC-SHA256, 600,000 iterations, AES-256)
var derived = CryptoService.DeriveKeyFromPassword("a strong passphrase");
// derived.Value!.Key, derived.Value!.Salt — persist the salt alongside the ciphertext

// Password-based overloads — derive the key internally and write a self-contained
// container header, so only the original password is needed to decrypt
var encryptedWithPw = CryptoService.EncryptString("Hello, CKL!", "a strong passphrase");
var decryptedWithPw = CryptoService.DecryptString(encryptedWithPw.Value!, "a strong passphrase");

CryptoService.EncryptFile("document.pdf", "document.pdf.enc", "a strong passphrase");
CryptoService.DecryptFile("document.pdf.enc", "document.pdf", "a strong passphrase");
```

Every method returns `Result`/`Result<TValue>` from `CKL.Libs.ResultPattern` —
check `.Succeeded` before using `.Value`; on failure, `.ErrorMessage` and
`.CallStackAsString` describe what went wrong.

## How it works

- **Container header** — every ciphertext (string, byte array, file, or folder)
  is prefixed with a small, self-describing header. The header is cleartext and
  **not** authenticated (no integrity — see *Scope & threat model*):

  ```
  [ magic:       4 bytes ]  "CKLC"
  [ version:     1 byte  ]  0x02  ← unchanged
  [ flags:       1 byte  ]  bit 0 = timestamps present
                            bit 1 = LastAccessTime omitted (written as 0, ignored on restore)
  [ kdf block …          ]  unchanged from v2.0.0
    — kdf-id 0x00 = none (raw key)
    — kdf-id 0x01 = PBKDF2-HMAC-SHA256:
        [ iterations: 4 bytes ]  big-endian uint32
        [ key-size:   1 byte  ]  32
        [ salt-len:   1 byte  ]  16
        [ salt:       N bytes ]
  — if flags bit 0 set:
      [ created:   8 bytes ]  DateTimeOffset UTC ticks, Int64 big-endian
      [ modified:  8 bytes ]  DateTimeOffset UTC ticks, Int64 big-endian
      [ accessed:  8 bytes ]  DateTimeOffset UTC ticks, Int64 big-endian (0 if bit 1 set)
  [ iv:          16 bytes ]  per-encryption AES-CBC IV
  [ ciphertext:  …       ]
  ```

  A v2.0.0 container (`flags = 0x00`) remains fully readable; the timestamp
  block is simply absent.
- **Strings/byte arrays** — AES-CBC with PKCS7 padding; a random IV per
  encryption, carried in the header.
- **Files** — compressed (GZip), then encrypted, streaming from source to
  destination without buffering the whole file in memory.
- **Folders** — zipped (which already compresses), then the archive is
  encrypted as a single output file; decrypting reverses both steps and
  extracts back into a destination folder. The intermediate plaintext zip is
  staged in a per-user, restricted-ACL workspace (overridable via
  `workingDirectory`), not the shared temp directory.
- **Password-based overloads** — every encrypt/decrypt method has a
  `string password` overload. Encrypting derives a random salt + key via
  PBKDF2-HMAC-SHA256 (600,000 iterations, 32-byte/AES-256 key) and records the
  salt and parameters in the header; decrypting reads them back, re-derives the
  key, and proceeds — no separate salt or parameter management needed.

## For maintainers

.NET 10 SDK, C# (latest). Depends on `CKL.Libs.ResultPattern`.

```
CKL.Libs.Crypt\
├── CryptoService.cs             # Public, Result-native API
├── Contracts\
│   └── ICryptoService.cs        # API contract
└── Support\
    ├── CryptoHeader.cs          # Versioned container header (format v2)
    ├── AesCryptoCore.cs         # AES-CBC/PKCS7 building blocks
    ├── KeyDerivation.cs         # PBKDF2 password-to-key derivation
    ├── CryptoWorkspace.cs       # Per-user restricted-ACL staging for folder ops
    ├── FileCryptoCore.cs        # Compress-then-encrypt streaming for files
    └── FolderCryptoCore.cs      # Zip-then-encrypt for folders
```

---

*CKL.Libs.Crypt — © 2026 ckluth — MIT License*
