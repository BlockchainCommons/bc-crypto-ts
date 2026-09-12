# Changelog

## 1.0.0-beta.2

Closes the divergences from `bc-crypto` 0.14.0 that could be closed without
reproducing a defect of the reference, and pins every one that remains
(`RUST_DIVERGENCES.md` §1: four, each with the reason and the upstream fix).
Rust harness: 660 vectors, 633 match, 27 recorded divergence / JS-only,
0 mismatch. Every honest output of 1.0.0-beta.1 is unchanged. Analysis:
`Docs/DIVERGENCES_BC_CRYPTO_TS.md` in the BlockchainCommons workspace.

### Fixed

- **`scrypt` accepted a parameter shape the reference (and RFC 7914) reject.**
  `scrypt::Params::new` requires `N < 2^(128·r/8)` — `logN < 16·r` — and
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
  key, as the reference does (HKDF already did).
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
  parameters above the default — for example to unlock a key locked in Rust
  with `logN 21, r 8` — passes a larger value. This is the one resource
  bound the port keeps.

### Internal

- `RUST_DIVERGENCES.md` §1 now records exactly four divergences, each kept
  on purpose: low-order X25519 peer keys (rejected here, a predictable key
  there), `verify` on malformed encodings (`false` here, a panic there —
  BIP-340 and RFC 8032 specify `false`), scrypt `logN: 0`, and PBKDF2
  `iterations: 0` (the reference's crate treats it as one). Each names the
  upstream fix.
- Harness: the low-order X25519 class is matched by set membership (all
  encodings of the seven low-order points, bit 255 masked) instead of two
  hex strings; D6 removed; D5 narrowed to `iterations: 0`.
- Vectors 642 → 660: nine low-order encodings and `ff…ff`
  (bit 255 masked on both sides), the scrypt shape and length rules on both
  paths, an empty HKDF salt (SHA-256 and SHA-512), a non-canonical Ed25519
  `s` (`s + L`). Of the 642, two changed as described above and the
  `argon2id t: 0` fault vector is gone.
- typedoc writes to `docs/api`.

## 1.0.0-beta.1

Initial beta implementation.