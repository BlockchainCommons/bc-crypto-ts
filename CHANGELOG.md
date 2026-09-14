# Changelog

## 1.0.0-beta.3 - 2026-09-14

Closes the following divergences from the reference, the published `bc-crypto` (tag 0.14.0).

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
- **A low-order X25519 peer derives the reference's key.** For every
  low-order encoding (RFC 7748 §6.1), `x25519.sharedKey` returns HKDF-SHA-256
  of the all-zero shared secret, `6ddeb1af…8d6e` whatever the private key,
  as the reference's `x25519_shared_key` does (x25519-dalek's
  `diffie_hellman`, which it does not check), instead of throwing
  `InvalidData` "low-order point". Reject such peers yourself before deriving
  from an untrusted key.
- **`verify` throws where the reference's parse panics.** `ecdsa.verify`,
  `schnorr.verify` and `ed25519.verify` throw `InvalidData` naming the key
  when it does not decode (the reference `.expect`s `PublicKey::from_slice`
  and `XOnlyPublicKey::from_byte_array` and `.unwrap()`s
  `VerifyingKey::from_bytes`), and `ecdsa.verify` throws it for an r or s ≥ n
  (`Signature::from_compact`); all of these were `false`. An input that
  parses still verifies or not. `ed25519.verify` decodes the key as dalek
  does (a non-canonical y reduced), so the 26 non-canonical encodings dalek
  takes are `false` and the 14 it rejects are `InvalidData`.
- **Zero KDF costs derive.** PBKDF2 `iterations: 0` computes what 1 does (the
  reference's `pbkdf2` 0.12.2 runs `rounds − 1` rounds after the first block)
  and scrypt `logN: 0` derives with N = 1 (`scrypt::Params::new` takes
  `log_n` 0), where both were rejected.
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
  the port stopped at 2^32 − 1.
- `chacha20` returns `Uint8Array<ArrayBuffer>`.

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

## 1.0.0-beta.1 - 2026-09-09

Initial beta implementation.
