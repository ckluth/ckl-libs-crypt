# CKL.Libs.Crypt

Authenticated encryption for strings, byte arrays, files, and folders —
symmetric **AES-256-GCM**, reporting outcomes via `CKL.Libs.ResultPattern`
instead of exceptions. Both tampering and silent corruption are detected.

Part of the `ckl-libs-<name>` family — see
[`ckl-builder`](https://github.com/ckluth/ckl-builder) for the ecosystem's
repo-family conventions and the decision-trail this repo follows.

---

## Scope & threat model

**Read this before use.** This library provides **confidentiality *and*
integrity** for data at rest in a **private, single-user** context: you encrypt
your own data and decrypt it yourself.

Encryption is **authenticated** (AES-256-GCM, framed into fixed-size chunks each
carrying its own GCM tag, with the chunk index, a final-chunk marker, and the
container header bound as associated data). As a result:

1. **Tampering is detected.** Any modification of the ciphertext, tags, or
   header — including reordering, duplicating, or truncating whole chunks —
   fails decryption with a clean, uniform "decryption failed" result. No
   modified container ever decrypts to plausible-but-wrong plaintext.
2. **Silent corruption is detected too.** The same authentication check catches
   non-adversarial damage — bit rot, a bad disk, a faulty sync/backup
   round-trip — which is the more common failure mode for a personal archive.

One assumption is retained from the original threat model: the library is built
for a **single-user, at-rest** use — it assumes you are not standing up an
interactive decryption *oracle* for an adversary. Because a failed GCM tag is a
single constant failure with nothing to distinguish, the padding-oracle concern
that motivated that caveat no longer applies, but the confidentiality-first,
single-user framing still holds.

The rationale is recorded in `ckl-builder` ADR 0011 (which revises ADR 0009).

> **Breaking format change (v3.0.0).** Containers written by v2.x (unauthenticated
> AES-CBC) are **not** readable by v3 — this is a deliberate clean cutover with no
> migration path, made while no ciphertext existed in the wild.

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
  is prefixed with a small, self-describing header. The header is cleartext but
  its exact bytes are **authenticated**: they are bound as associated data into
  every framed chunk, so tampering with any header field fails decryption:

  ```
  [ magic:       4 bytes ]  "CKLC"
  [ version:     1 byte  ]  0x03
  [ cipher-id:   1 byte  ]  0x01 = AES-256-GCM
  [ flags:       1 byte  ]  bit 0 = timestamps present
                            bit 1 = LastAccessTime omitted (written as 0, ignored on restore)
  [ chunk-size:  4 bytes ]  big-endian uint32 plaintext chunk size (64 KiB)
  [ kdf block …          ]
    — kdf-id 0x00 = none (raw key)
    — kdf-id 0x01 = PBKDF2-HMAC-SHA256:
        [ iterations: 4 bytes ]  big-endian uint32
        [ key-size:   1 byte  ]  32
        [ salt-len:   1 byte  ]  16
        [ salt:       N bytes ]
  [ nonce-base:  12 bytes ]  per-encryption AES-GCM nonce base
  — if flags bit 0 set:
      [ created:   8 bytes ]  DateTimeOffset UTC ticks, Int64 big-endian
      [ modified:  8 bytes ]  DateTimeOffset UTC ticks, Int64 big-endian
      [ accessed:  8 bytes ]  DateTimeOffset UTC ticks, Int64 big-endian (0 if bit 1 set)
  [ framed chunks: (ciphertext‖16-byte tag)* ]
  ```

- **Authenticated framing (all inputs)** — the plaintext is split into fixed
  64 KiB chunks; each chunk is encrypted with AES-256-GCM under a per-chunk
  nonce (the header's 12-byte nonce base XORed with the chunk index) and emits
  its own 16-byte authentication tag. The chunk index, a final-chunk marker, and
  the header bytes are bound as associated data, so a flipped bit, a reordered,
  duplicated, or dropped chunk, a truncated stream, or a swapped header field all
  fail the tag. Decryption always authenticates at least one chunk, so a
  header-only blob cannot decode to an "empty" success. Framing keeps the
  pipeline **streaming** — only one chunk is buffered at a time — so .NET's
  one-shot `AesGcm` API works on arbitrarily large files/folders.
  > Raw-key note: a random 96-bit nonce base is safe for a single-user archive.
  > Do not reuse one raw key across an impractically large number of encryptions
  > (billions); prefer the password overloads, which derive a fresh key + salt
  > each time.
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

## Cryptographic design (deep dive)

For reviewers who want the primitive-level detail. The v3 construction is a
**framed AEAD**: a stream-friendly wrapper around .NET's one-shot `AesGcm`.

### Primitive & keys

- **AES-256-GCM** (`System.Security.Cryptography.AesGcm`, in-box BCL — no
  third-party crypto), **128-bit (16-byte) tags**, 96-bit (12-byte) nonces.
- **Key** is 32 bytes (AES-256). Either supplied raw by the caller, or derived
  from a password with **PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random
  salt** (fresh salt per encryption; iterations/key-size/salt recorded in the
  header). One key per encryption on the password path.

### Why framing (and not one-shot)

`AesGcm` is one-shot over full buffers — it has no `CryptoStream`. Buffering an
entire file/folder to authenticate it would break the streaming guarantee. So
the plaintext is split into **fixed 64 KiB chunks**, each independently sealed as
`(ciphertext ‖ 16-byte tag)`. Only one chunk (~64 KiB) is ever in memory, in
either direction, so arbitrarily large inputs stream.

### Nonce discipline (the part that matters)

Nonce reuse under a fixed GCM key is catastrophic, so the scheme is explicit:

- One **random 12-byte `nonce_base`** is drawn per encryption
  (`RandomNumberGenerator`) and stored in the header.
- The **per-chunk nonce** = `nonce_base` with its **low 8 bytes XORed with the
  big-endian `uint64` chunk index** (chunk 0's nonce is exactly `nonce_base`).
- **Within one encryption:** indices `0,1,2,…` are distinct, so the XOR yields
  distinct nonces; overflow is unreachable (2⁶⁴ chunks). No reuse, ever.
- **Across encryptions:** the fresh random base makes collisions a 96-bit
  birthday problem. On the password path each encryption also has a different
  key, so cross-encryption reuse is a non-issue. On the **raw-key path** the same
  key may be reused across encryptions with different random bases; the standard
  GCM random-nonce safety margin (~2³² nonces / chunks under one key) applies and
  is unreachable for a single-user archive. Prefer the password overloads if you
  would ever seal astronomically many blobs under one static key.

### What each chunk authenticates (associated data)

Every chunk's GCM AAD is:

```
AAD = full_header_bytes ‖ uint64_be(chunk_index) ‖ final_flag(1 byte)
```

- **`full_header_bytes`** — the *exact* bytes read/written for the header (not a
  re-serialization). The header is cleartext but fully authenticated, so a silent
  swap of chunk-size, nonce-base, KDF params, flags, or the timestamp block fails
  the tag. (Binding raw bytes also closes the latent gap where re-serialization
  could normalize away reserved bits.)
- **`chunk_index`** — defeats chunk **reordering** and **duplication** (a chunk
  moved to another position is verified under the wrong index nonce + AAD).
- **`final_flag`** (0x01 only on the last chunk) — defeats whole-chunk
  **truncation** (the prior chunk is then verified as final → mismatch) and
  **extension/append** (the real final chunk is verified as non-final →
  mismatch).

### Framing invariants

- Every **non-final** chunk is **exactly 64 KiB** plaintext (`65 536 + 16`
  ciphertext). A short read means EOF, so a short chunk is always the final one.
- **At least one chunk is always emitted** — empty plaintext produces a single
  authenticated final chunk (0 plaintext bytes + tag). Integrity therefore covers
  empty inputs.
- **Decryption requires ≥ 1 authenticated chunk.** A header-only blob (all chunks
  stripped) is a hard failure — it can *never* decode to an "empty payload"
  success. This is the truncation-to-zero case, closed deliberately.
- Both sides use a **one-chunk lookahead** to mark the final chunk deterministically.

### Guaranteed detections

Any of the following yields a single, uniform decryption **failure `Result`**
(never wrong plaintext):

| Attack / fault | Detected by |
| --- | --- |
| Flip any ciphertext or tag bit (incl. bit rot) | GCM tag |
| Reorder / duplicate whole chunks | index in AAD + nonce |
| Truncate mid-chunk or drop the final chunk | tag / final-flag |
| Append an extra chunk | final-flag |
| Strip all chunks (header-only) | ≥1-chunk invariant |
| Swap any header field | header bytes in AAD |
| Wrong key / wrong password | GCM tag |

Failures are **uniform**: a mismatch throws `CryptographicException`, surfaced as
a plain failure `Result` with nothing to distinguish *why* — so there is no
padding-oracle-style side channel to exploit (the concern that gated integrity in
ADR 0009 dissolves once every failure is one constant signal).

### Non-goals (stated, not overlooked)

- **Key commitment.** GCM is not key-committing (partitioning-oracle /
  "Invisible Salamanders" class). Not exploitable here: single key, single user,
  no decryption oracle, no multi-key/multi-recipient selection. Noted for
  completeness.
- **Argon2id KDF.** Deferred to a future ADR; the `kdf-id` byte already leaves
  room to add it without a format break.
- **Encrypt-side folder streaming** (eliminating the transient plaintext temp
  zip) remains deferred from the previous hardening pass.

The full rationale and the options considered are in `ckl-builder` ADR 0011
(which revises ADR 0009).

## For maintainers

.NET 10 SDK, C# (latest). Depends on `CKL.Libs.ResultPattern`.

```
CKL.Libs.Crypt\
├── CryptoService.cs             # Public, Result-native API
├── Contracts\
│   └── ICryptoService.cs        # API contract
└── Support\
    ├── CryptoHeader.cs          # Versioned container header (format v3)
    ├── AesCryptoCore.cs         # Framed AES-256-GCM building blocks (nonce/AAD rules)
    ├── GcmChunkWriteStream.cs   # Push-based chunked GCM encryptor (streaming)
    ├── GcmChunkReadStream.cs    # Pull-based chunked GCM decryptor (streaming)
    ├── KeyDerivation.cs         # PBKDF2 password-to-key derivation
    ├── CryptoWorkspace.cs       # Per-user restricted-ACL staging for folder ops
    ├── FileCryptoCore.cs        # Compress-then-encrypt streaming for files
    └── FolderCryptoCore.cs      # Zip-then-encrypt for folders
```

---

*CKL.Libs.Crypt — © 2026 ckluth — MIT License*
