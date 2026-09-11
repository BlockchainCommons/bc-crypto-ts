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

Checked by `tests/rust-validation` (`cargo run --release -- ../vectors/vectors.json`)
over the 642 golden vectors: **619 match, 23 expected divergence / JS-only
(D2 ×2, D3 ×13, D4 ×1, D5 ×2, D6 ×1, J1 ×4), 0 MISMATCH.** Every entry below
is one of those 23.

### D2. X25519 with a low-order public key

`x25519-dalek`'s `diffie_hellman` returns the all-zero shared secret for a
low-order peer key and the reference never checks `was_contributory`, so
`x25519_shared_key(priv, 00…00)` and `(priv, 01‖00…)` return
`HKDF-SHA-256(0³², "agreement")`, the same bytes for every private key.
TypeScript rejects with `CryptoError` `InvalidData` (`what: "X25519 public
key"`, the backend's error as `cause`): a predictable key is the failure the
check exists to prevent.

### D3. `verify` on malformed input of the right length

The reference's `*_verify` parse the key and signature with `expect` /
`unwrap` and **panic** on an x-only key not on the curve, an ECDSA `r`/`s`
≥ n, or an Ed25519 public key that is not a valid point (13 vectors,
including BIP-340 vectors 5 and 14). TypeScript returns `false`: a verifier
must not be crashable by its input.

### D4. scrypt with `logN: 0`

`scrypt_opt(pw, salt, 32, 0, 8, 1)` computes (N = 1 is accepted by the
`scrypt` crate); noble requires `N ≥ 2`, so TypeScript throws. Kept: a
cost of one is not a KDF.

### D5. PBKDF2 with `iterations: 0` or `dkLen: 0`

`pbkdf2_hmac_sha256(pw, salt, 0, 32)` returns bytes and `(…, 1, 0)` returns
an empty vector; TypeScript throws `CryptoError` `InvalidParameter` on both.
Kept: both are argument-domain faults.

### D6. `scrypt_opt` output length outside 10..=64

The reference's `scrypt_opt` goes through `scrypt::Params::new`, which
requires `10 ≤ len ≤ 64` and panics otherwise, while its default-parameter
`scrypt` accepts any `len > 0`. TypeScript's single `scrypt(pw, salt,
{ dkLen, logN, r, p })` accepts `dkLen: 8` on both paths. Kept: the bound is
the RustCrypto crate's, not a property of scrypt.

> Any divergence found must be added here in the same commit that
> introduces or discovers it, with the input, the Rust outcome, the
> TypeScript outcome, and the reason the difference is intentional, and
> mirrored in `expected_divergence()` in the harness.

## 2. JS-only input domain

- **Wrong-length inputs.** Rust takes fixed-size arrays (`&[u8; 32]`), so a
  wrong length cannot reach it. TypeScript throws `CryptoError` with
  `code: "InvalidSize"` and `details: { what, expected, actual }`. The
  harness's `fixed::<N>` maps a wrong length to `throw`, so these vectors
  are *compared* (throw = throw), not skipped.
- **Malformed signatures and public keys of the right length** — see D3.
- **`chacha20`** (raw keystream, `{ counter }`) has no reference analog;
  its vectors are classified `J1` by the harness before comparison.
- **`argon2id`'s `t`, `m`, `p`** — the reference exposes only the defaults
  (t = 2, m = 19456, p = 1, which are vectored); a recipe that sets one is
  `J1`.
- **Argument-domain faults** (zero or out-of-range scalars, points not on
  the curve, KDF numbers out of range, negative counters): every one throws
  `CryptoError` — `InvalidData` for a scalar or point, `InvalidParameter`
  for a KDF number or counter — with the backend's error as `cause` where
  there is one. The reference panics on the same inputs except the D4/D5
  cases above.

## 3. Mapping equivalences

- **Strict Ed25519.** The reference's `ed25519_verify` is `ed25519-dalek`'s
  `verify_strict`: canonical encodings only, and a small-order public key
  or `R` is rejected. The port decodes the key and `R` with `zip215: false`,
  returns `false` if either is small-order, then verifies with
  `{ zip215: false }` — the same acceptance set. Vectored: the identity key
  with the `(identity, 0)` signature, its non-canonical `y = p + 1`
  encoding, a non-canonical `R`, RFC 8032 vectors 1–3 with bit-flip
  negatives, and every signing triple with flipped signature, message and
  key.
- **Low-S ECDSA.** Both sides reject a high-S signature (libsecp256k1's
  `verify_ecdsa` does not normalise; noble verifies with `lowS: true`);
  vectored per signing triple.
- **Derivations.** `derive_signing_private_key` and
  `ecdsa_derive_private_key` are the same computation in the reference; the
  port exports one `deriveSigningPrivateKey` (and `deriveAgreementPrivateKey`)
  at the root. The frozen `ecdsaDerive` recipe maps to the Rust
  `ecdsa_derive_private_key` and the TypeScript `deriveSigningPrivateKey`.

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
  fill per key or aux-rand, both sides). The bridge maps `fill_bytes` to
  `fill_random_data` — the one-draw-per-byte path — which is the choice that
  reproduces the reference's own Ed25519 keygen fixture (`7eb559…`).

## Maintenance

When the upstream reference moves:

1. Review the diff via the link in the `upstream.yml` tracking issue.
2. Port the relevant changes.
3. Update `.github/versions.yml` with the new version and commit.
4. Update the tracked version at the top of this file.
5. Add, amend, or remove divergence entries as the port requires.
