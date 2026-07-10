# Changelog

All notable changes to `CKL.Libs.Crypt` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [3.0.0] - 2026-07-10

**Breaking release.** Switches the cryptographic core from unauthenticated
AES-CBC/PKCS7 to **authenticated AES-256-GCM**, so every container now provides
**integrity as well as confidentiality** (see `ckl-builder` ADR 0011, which
revises ADR 0009). The container format changed; **v2.x ciphertext cannot be
decrypted by v3** — a deliberate clean cutover with no migration path, made
while no ciphertext existed in the wild.

### Changed

- **Authenticated encryption (AES-256-GCM).** Strings, byte arrays, files, and
  folders are now encrypted with AES-256-GCM instead of AES-CBC/PKCS7. Both
  **tampering and silent corruption** (bit rot, a bad sync/backup round-trip)
  are detected: a modified or damaged container fails decryption with a clean,
  uniform failure `Result` rather than yielding wrong plaintext.
- **Chunked AEAD framing.** Because .NET's `AesGcm` is a one-shot API, the
  plaintext is split into fixed 64 KiB chunks, each with its own 12-byte-derived
  nonce and 16-byte tag, streamed so large files/folders are never buffered
  whole. The chunk index, a final-chunk marker, and the full header are bound as
  associated data, so chunk reorder/duplicate/truncate/append and header-field
  tampering all fail the tag. Decryption always authenticates at least one
  chunk, so a header-only blob cannot decode to an "empty" success.
- **v3 container header.** `version` is now `0x03`; a `cipher-id` byte
  (`0x01 = AES-256-GCM`) and a big-endian `chunk-size` uint32 were added, and
  the 16-byte AES-CBC IV was replaced by a 12-byte per-encryption GCM nonce
  base. The `flags` byte and optional timestamp block (v2.1.0) are unchanged.
  Unknown magic/version/cipher-id are rejected with a clean failure.

### Security

- **Integrity is now provided.** The "no integrity" guarantee documented for
  v2.x is reversed: authenticated encryption detects tampering *and* corruption.
  The confidentiality-first, single-user framing is retained; because a failed
  GCM tag is a single constant failure, the padding-oracle caveat from ADR 0009
  no longer applies. The README "Scope & threat model" and the `ICryptoService`
  API remarks were flipped to state that integrity is provided.

## [2.1.0] - 2026-07-10

**Additive, non-breaking release.** Preserves the original file-system
timestamps (`CreationTime`, `LastWriteTime`, `LastAccessTime`) across
encrypt/decrypt for files and folders (see `ckl-builder` ADR 0010).
v2.0.0 containers remain readable unchanged.

### Added

- **Timestamp round-trip for single files.** `EncryptFile`/`DecryptFile`
  capture the source file's `CreationTime`, `LastWriteTime`, and
  `LastAccessTime` into the container header and restore them on decrypt,
  after the destination file is fully written. A new `captureLastAccessTime`
  parameter (default `true`) lets callers opt out of capturing
  `LastAccessTime`.
- **Timestamp round-trip for folders.** `EncryptFolder`/`DecryptFolder` write
  a `__ckl_timestamps.json` manifest as the first entry of the intermediate
  zip, capturing the root folder's and every subdirectory's/file's original
  timestamps; the manifest is applied and removed after extraction. A source
  folder containing a file already named `__ckl_timestamps.json` is rejected
  with a clear `Result` failure before encryption proceeds. `EncryptFolder`
  also gained a `captureLastAccessTime` parameter (default `true`).
- **Header `flags` byte.** The v2 container header gained a `flags` byte
  (between `version` and `kdf-id`) marking whether the optional 24-byte
  timestamp block follows the KDF block. This is a permanent, additive
  extension point for future per-container metadata — no further version
  bumps are needed for additive fields.

## [2.0.0] - 2026-07-10

**Breaking release.** Hardens the library under a documented private/at-rest
threat model (see `ckl-builder` ADR 0009). The container format changed; **v1
ciphertext cannot be decrypted by v2** — this is a deliberate clean break with
no migration path (no v1 data existed).

### Changed

- **Versioned container header.** Every ciphertext (string, byte array, file,
  folder) is now prefixed with a self-describing header (`"CKLC"` magic, format
  version, key-derivation id and parameters, and the per-encryption IV),
  replacing v1's bare salt/IV prefix. Blobs are self-contained and report a
  clear failure on an unrecognized magic/version/KDF id.
- **Stronger key derivation.** PBKDF2-HMAC-SHA256 iterations raised from
  100,000 to **600,000** (current OWASP guidance); the derived key is fixed at
  32 bytes (AES-256). The `iterations` and `keySize` parameters were removed
  from the password overloads and from `DeriveKeyFromPassword` — the values are
  fixed and recorded in the header.
- **Hardened folder staging.** Folder operations stage their intermediate
  (plaintext) zip in a per-user, restricted-ACL workspace under
  `%LOCALAPPDATA%` instead of the shared temp directory.

### Added

- **"Scope & threat model" documentation** (README section + `ICryptoService`
  API remarks): the library provides confidentiality only, does not detect
  tampering, and assumes no interactive decryption oracle — with the explicit
  conditions that would invalidate those assumptions.
- **Optional `workingDirectory` parameter** on the folder encrypt/decrypt
  overloads, to override where the intermediate zip is staged.

### Security

- Documented the confidentiality-only guarantee and its assumptions. Integrity
  (authenticated encryption, e.g. AES-GCM) is deliberately **not** provided and
  is deferred to a future revision — see ADR 0009 for the rationale.

## [1.0.0] - Unreleased

### Added

- Symmetric (AES) encryption/decryption for strings, byte arrays, files, and
  folders, reporting outcomes via `CKL.Libs.ResultPattern`.
- Password-based overloads of every `ICryptoService` encrypt/decrypt method
  (string, byte array, file, folder): derive the key from a password via
  `DeriveKeyFromPassword` and delegate to the byte[]-key method. The
  generated salt is prepended to the output (ahead of the IV/ciphertext),
  so the result is self-contained — decrypting needs only the original
  password.
