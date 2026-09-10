# Changelog

## 1.0.0-beta.1

Extracted from the [`paritytech/bcts`](https://github.com/paritytech/bcts)
monorepo (`@bcts/crypto`) and redesigned as an idiomatic TypeScript library;
see [MIGRATION.md](./MIGRATION.md). Every output byte is unchanged.

- Algorithm families are objects: `chacha20Poly1305`, `x25519`, `ecdsa`,
  `schnorr`, `ed25519`, each with its size constants. Hashes, MACs and KDFs
  stay as root functions; the `hash` namespace is gone.
- AEAD `encrypt` returns `ciphertext || tag` as one `Uint8Array`; `decrypt`
  takes the same. `{ aad }` replaces the `WithAad` twins.
- `ed25519.verify(publicKey, signature, message)`: argument order unified
  with the other schemes.
- Options objects replace positional parameters and `*Opt`/`*Using`
  variants: `{ rng }`, `{ auxRand }`, `{ iterations, dkLen }`,
  `{ dkLen, logN, r, p }`, `{ dkLen, t, m, p }`, `{ littleEndian }`.
- One `CryptoError` with `code: "InvalidSize" | "InvalidData" |
  "AuthenticationFailed" | "Unsupported"`, typed `details`, and factories;
  `AeadError` and `CryptoResult` removed. Wrong-length inputs throw
  `CryptoError` instead of a bare `Error`.
- `crc32` runs 2.2× faster; everything else is within noise of the
  pre-redesign bundle (`bench/benchmark.mjs`).
- 511 golden vectors, a differential corpus against the frozen pre-redesign
  bundle, and a Rust cross-validation harness (`tests/rust-validation`,
  `bc-crypto 0.14.0`: 511/511 match).

---

## History as `@bcts/crypto`

## [1.0.0-beta.6] - 2026-07-29

### Changed

- Workspace version bump

## [1.0.0-beta.5] - 2026-07-01

### Changed

- Workspace version bump

## [1.0.0-beta.4] - 2026-06-28

### Changed

- Dependency sync

## [1.0.0-beta.3] - 2026-06-22

### Changed

- Dependencies bump

## [1.0.0-beta.2] - 2026-06-16

### Changed

- Dependencies bump

## [1.0.0-beta.1] - 2026-05-27

### Changed

- Workspace version bump

## [1.0.0-beta.0] - 2026-04-27

### Changed

- `argon`, `error`, `public-key-encryption`, `scrypt`, `memzero` modules and re-exports aligned with upstream `bc-crypto`.

## [1.0.0-alpha.23] - 2026-04-24

### Changed

- Workspace version bump

## [1.0.0-alpha.22] - 2026-03-01

### Changed

- Workspace version bump

## [1.0.0-alpha.21] - 2026-02-27

### Changed

- Workspace version bump

## [1.0.0-alpha.20] - 2026-02-12

### Changed

- Workspace version bump

## [1.0.0-alpha.19] - 2026-02-05

### Changed

- Workspace version bump

## [1.0.0-alpha.18] - 2025-01-31
