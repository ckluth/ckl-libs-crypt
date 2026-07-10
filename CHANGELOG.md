# Changelog

All notable changes to `CKL.Libs.Crypt` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
