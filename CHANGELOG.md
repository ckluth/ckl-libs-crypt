# Changelog

All notable changes to `CKL.Libs.Crypt` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
