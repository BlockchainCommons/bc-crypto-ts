# Changelog

## 1.0.0-beta.2

Pending release. Fixes Ed25519 verification and adds reference parameter
validation. Four behavioral differences remain against published Rust
`bc-crypto` 0.14.0; see [RUST_DIVERGENCES.md](./RUST_DIVERGENCES.md).
Ordinary signing and derivation outputs are unchanged.

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

### Internal

- `RUST_DIVERGENCES.md` now records exactly four divergences, each kept
  on purpose: low-order X25519 peer keys (rejected here, a predictable key
  there), `verify` on malformed encodings (`false` here, a panic there -
  BIP-340 and RFC 8032 specify `false`), scrypt `logN: 0`, and PBKDF2
  `iterations: 0` (the reference's crate treats it as one).
- The Rust harness allows only exact reviewed divergence recipes and checks
  the expected HKDF-of-zero output for low-order X25519 peers. Its `--strict`
  mode disables behavioral exceptions for candidate reference versions.
- Expanded the golden corpus to 679 vectors, including Ed25519 torsion,
  PBKDF2 zero-cost/empty-output, X25519 encodings, scrypt parameter rules,
  empty HKDF salt, and non-canonical Ed25519 scalar cases.

## 1.0.0-beta.1

Initial beta implementation.
