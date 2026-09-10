# Divergences from the Rust reference implementation

This library is a TypeScript port of
[`BlockchainCommons/bc-crypto-rust`](https://github.com/BlockchainCommons/bc-crypto-rust),
tracked at version **0.14.0**
([`4f2b791`](https://github.com/BlockchainCommons/bc-crypto-rust/commit/4f2b791320730578b04943c833c4a9e6c232fc4d)).

The tracked version and commit are recorded in
[`.github/versions.yml`](./.github/versions.yml), and the `upstream.yml`
workflow opens a tracking issue whenever the reference implementation moves
ahead of it.

This document is the deliberate record of every place the TypeScript behaviour
differs from the Rust reference. It has three kinds of entry:

1. **True behavioral divergences** - the same input produces a different outcome.
2. **JS-only input domain** - inputs that have no Rust analog, so there is nothing to diverge from.
3. **Mapping equivalences** - JS-specific inputs that are validated through the bytes they produce.

## 1. True behavioral divergences

_None._ All 511 golden vectors (`tests/vectors/vectors.json`) replay
byte-for-byte against `bc-crypto 0.14.0` through
`tests/rust-validation` (`cargo run --release -- ../vectors/vectors.json`),
with an empty expected-divergence allowlist.

> Any divergence found must be added here in the same commit that
> introduces or discovers it, with the input, the Rust outcome, the
> TypeScript outcome, and the reason the difference is intentional, and
> mirrored in `expected_divergence()` in the harness.

## 2. JS-only input domain

- **Wrong-length inputs.** Rust takes fixed-size arrays (`&[u8; 32]`), so a
  wrong length cannot reach it. TypeScript throws `CryptoError` with
  `code: "InvalidSize"` and `details: { what, expected, actual }`. The four
  corpus recipes exercising this are skipped by the harness as untestable
  rather than allowlisted as divergences.
- **Malformed signatures and public keys of the right length.** Rust's
  `*_verify` return `bool`; noble throws for some malformed encodings
  (e.g. an x-only key not on the curve, BIP-340 vectors 5 and 14). The
  TypeScript `verify` functions catch and return `false`, matching Rust's
  boolean contract.

## 3. Mapping equivalences

- **API shape.** `bc_crypto::ecdsa_sign(priv, msg)` ↔ `ecdsa.sign(priv, msg)`;
  the `*_using(rng)` functions ↔ `{ rng }` options; `scrypt_opt(pw, salt,
  len, log_n, r, p)` ↔ `scrypt(pw, salt, { dkLen, logN, r, p })`. The
  harness maps each recipe to the Rust call directly.
- **AEAD layout.** Rust returns `(ciphertext, tag)`; TypeScript returns the
  concatenation. Vectors store the concatenation and the harness joins the
  Rust tuple.
- **Ed25519 verify order.** Rust and the pre-redesign TypeScript took
  `(pub, msg, sig)`; the redesign takes `(pub, sig, msg)` like the other
  schemes. Pure argument order; the harness swaps.
- **RNG bridge.** Rust functions that draw randomness take
  `rand_core::CryptoRngCore`; the harness bridges `bc-rand`'s seeded
  generator into that trait so seeded vectors compare exactly (one 32-byte
  fill per key or aux-rand, both sides).

## Maintenance

When the upstream reference moves:

1. Review the diff via the link in the `upstream.yml` tracking issue.
2. Port the relevant changes.
3. Update `.github/versions.yml` with the new version and commit.
4. Update the tracked version at the top of this file.
5. Add, amend, or remove divergence entries as the port requires.
