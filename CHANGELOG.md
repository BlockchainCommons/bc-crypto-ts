# Changelog

## Unreleased

Closes every divergence from the reference that a TypeScript design can
remove. The reference is the `bc-rust/bc-crypto-rust` working tree (commit
`4f2b791`, tag 0.14.0, plus its input-validation edits), which the Rust harness
now patches in; against it there is no exception list. Requires
`@blockchaincommons/rand` ≥ 1.0.0-beta.3.

### Changed (breaking)

- **Every argument is type-checked first.** A byte argument that is not a
  `Uint8Array` (a string, a plain array, an `ArrayBuffer`), an options
  argument that is not an object, or a `littleEndian` that is not a boolean
  throws `CryptoError` `InvalidParameter` naming the argument, before any
  length, domain or backend check. Before, such values leaked engine
  `TypeError`s, were silently accepted (`crc32([1, 2, 3])` returned a
  checksum, `ed25519.verify(pk, sig, "msg")` returned `false`) or blamed
  another argument (`ecdsa.sign(key, "msg")` reported the private key). A
  `Buffer` and a `Uint8Array` from another realm are accepted. `memzero` and
  `memzeroAll` require numeric typed arrays.
- **A low-order X25519 peer is `NonContributoryKey`.** `x25519.sharedKey`
  throws the new code with the reference's message, `"X25519 peer key
  produces an all-zero shared secret"` (its `try_x25519_shared_key` returns
  `Err(NonContributoryKey)`), instead of `InvalidData` "low-order point".
  `CryptoErrorCode` and `CryptoErrorDetails` gain the member.
- **scrypt has no default memory ceiling.** `maxmem` is an opt-in ceiling;
  by default the parameters decide, as in the reference. logN 17, r 64
  (1.07 GiB) now derives (`88d8c775…86f3`), where noble's ~1 GiB default
  rejected it.

### Added

- **A paged scrypt core for oversize parameter sets.** JavaScriptCore (Bun,
  Safari) holds at most 2^32 bytes in one typed array; when `128·r·N` or
  `128·r·p` exceeds 2^31 bytes, `scrypt` derives with an in-package RFC 7914
  core that keeps `V` and `B` in pages, byte-identical to noble and to the
  reference (logN 22, r 9 gives `1fc13793…d167` on Bun in about 6 s at
  4.8 GiB). Smaller sets still go to noble.
- **Hybrid uncompressed keys.** `ecdsa.compressPublicKey` accepts
  libsecp256k1's `06`/`07` prefixes when the low bit matches the parity of
  y, as the reference does; a mismatch is `InvalidData`.
- **PBKDF2 `dkLen` up to (2^32 − 1)·hLen** (RFC 8018 §5.2; 32 or 64), where
  the port stopped at 2^32 − 1. `iterations` 0 stays `InvalidParameter` at
  every length, the typed form of the reference's `assert!(iterations > 0)`.
- `chacha20` returns `Uint8Array<ArrayBuffer>`.

### Validation

- The harness is patched to the reference tree, has no exception list, and
  parses every argument with the Rust width before the call: a wrong-length
  fixed argument, sealed data under 16 bytes, a number outside `u8`, `u32`
  or `usize`, and raw ChaCha20 are js-only, never matches or mismatches.
  The golden file grew from 679 to 807 vectors: point (de)compression and
  AEAD decryption success paths, 66 non-canonical Ed25519 A and R rows, 19
  undecodable-key and r/s ∈ {0, n} verify rows, 21 low-order X25519 rows
  carrying the error value, 6 hybrid keys, the logN 17 r 64 row and 3 width
  probes. `--full` replays the whole corpus (1195) and `heavy.json` the
  logN 22, r 9 vector; CI runs all three, plus the heavy vector on Bun and
  Node. Results: `807 vectors - 793 match, 14 js-only, 0 MISMATCH`;
  `1195 - 1180, 15, 0`; `1 - 1, 0, 0`.
- Tests: an argument-type property over every exported function, the
  Ed25519 decoder boundary (dalek decodes 26 of the 40 non-canonical
  encodings, the port none; `verify` is `false` for all 40 on both sides),
  a verify-never-throws property, the Ed25519 packed and fallback generator
  paths, malformed generators propagating rand's `InvalidGenerator`
  unwrapped, backend spies for the PBKDF2 bound and the scrypt ceiling, and
  the paged core against noble under one-block, three-block and default
  pages plus the RFC 7914 vectors.

## 1.0.0-beta.2 - 2026-09-12

Fixes Ed25519 verification and adds reference parameter validation.

### Fixed

- Ed25519 verification now checks the uncofactored equation used by Rust's
  `verify_strict`. Signatures with a nonzero torsion residual no longer verify.
  Canonical encoding and small-order checks remain; valid mixed-order cases
  satisfying the equation are not rejected merely for having torsion.
- Raw ChaCha20 validates the initial counter in `[0, 2^32 - 2]` and the
  remaining block capacity before invoking the backend. Overflow is reported
  as `CryptoError` with `InvalidParameter`.
- scrypt validates `logN` in `[1, 32]`, the installed backend's supported range.
  Raising `maxmem` does not bypass that limit or runtime allocation limits.
- ECDSA explicitly requests low-S verification rather than relying on the
  backend default.

- **`scrypt` accepted a parameter shape the reference (and RFC 7914) reject.**
  `scrypt::Params::new` requires `N < 2^(128·r/8)` - `logN < 16·r` - and
  `r·p < 2^30`; noble does not check the first, so `scrypt(pw, salt,
  { dkLen: 32, logN: 17, r: 1 })` derived a key here and panicked there.
  Both rules are now enforced as named `InvalidParameter`s.

### Changed

- **`scrypt` output length on the parameterised path is `10..=64`**, as the
  reference's `scrypt_opt` (`scrypt::Params::new`) requires; the default
  path (no `logN`/`r`/`p`) keeps accepting any `dkLen ≥ 1`, as the
  reference's `scrypt` does. `scrypt(pw, salt, { dkLen: 8, logN: 4 })` now
  throws; `scrypt(pw, salt, { dkLen: 8 })` still works.
- **`pbkdf2Sha256` / `pbkdf2Sha512` accept `dkLen: 0`** and return an empty
  key when iterations is positive (HKDF already allowed empty output).
- **`argon2id` has no `t`, `m`, `p` options.** The reference exposes only
  `Argon2::default()` (Argon2id v0x13, m 19456 KiB, t 2, p 1), which is what
  the port derived with by default; the wire format carries a salt only, so
  other costs could never be reproduced by another implementation.
  `Argon2idOptions` is `{ dkLen }`.
- `CryptoError.authenticationFailed()` carries the reference's message,
  `"AEAD error"` (was `"AEAD authentication failed"`; the `code` is
  unchanged).

### Added

- `ScryptOptions.maxmem`: the working-memory ceiling noble enforces
  (`128·r·(N + p + 1)` bytes; default a little over 1 GiB). The reference
  allocates whatever the parameters imply, so a caller who must derive with
  parameters above the default - for example to unlock a key locked in Rust
  with `logN 21, r 8` - passes a larger value. Backend and runtime limits still apply.

### Validation

- Added 16 Ed25519 torsion fixtures and PBKDF2 zero-iteration fixtures for
  both hashes with empty and nonempty output. The Rust 0.14.0 comparison
  reports 649 matches and 30 expected-divergence/JS-only cases, with no
  unexpected mismatches.

## 1.0.0-beta.1 - 2026-09-12

Initial beta implementation.
