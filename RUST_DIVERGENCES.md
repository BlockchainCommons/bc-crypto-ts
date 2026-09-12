# Divergences from the Rust reference implementation

This library is a TypeScript port of
[`BlockchainCommons/bc-crypto-rust`](https://github.com/BlockchainCommons/bc-crypto-rust), tracked
at version **0.14.0**
([`4f2b791`](https://github.com/BlockchainCommons/bc-crypto-rust/commit/4f2b791320730578b04943c833c4a9e6c232fc4d)).

The tracked version and commit are recorded in [`.github/versions.yml`](./.github/versions.yml), and
the `upstream.yml` workflow opens a tracking issue whenever the reference implementation moves ahead
of it.

This document records known differences from the tracked Rust version, JavaScript input validation,
and API mappings:

1. **True behavioral divergences** - the same input produces a different outcome.
2. **JS-only input domain** - inputs that have no Rust analog, so there is nothing to diverge from.
3. **Mapping equivalences** - JS-specific inputs that are validated through the bytes they produce.

## 1. True behavioral divergences

Checked by `tests/rust-validation` (`cargo run --release -- ../vectors/vectors.json`) over the 660
golden vectors: **633 match, 27 expected divergence / JS-only (D2 ×9, D3 ×13, D4 ×1, D5 ×1, J1 ×3),
0 MISMATCH.** Four behavioral divergences remain. The proposed upstream changes below would resolve
them; they are not fixes in the tracked Rust version. The counts describe the committed vectors, not
exhaustive input coverage.

### D2. X25519 with a low-order public key (9 vectors)

`x25519-dalek`'s `diffie_hellman` returns the all-zero shared secret for a low-order peer key and
the reference never checks `was_contributory()`, so `x25519_shared_key` returns
`HKDF-SHA-256(0³², "agreement")` — the same bytes for every private key — for every encoding of the
seven low-order points (RFC 7748 §6.1: 0, 1, the two order-8 points, p − 1, p, p + 1, and each with
bit 255 set, which both sides mask). TypeScript rejects all of them with `CryptoError` `InvalidData`
(`what: "X25519 public key"`, the backend's error as `cause`). **Proposed upstream change:** check
`shared_secret.was_contributory()` in `bc-crypto` and return an error. The other public-key vectors,
including `ff…ff`, derive identically on both sides.

### D3. `verify` on a malformed key or signature of the right length (13 vectors)

The reference's `*_verify` parse the key and signature with `expect` / `unwrap` and **panic** on an
x-only key not on the curve, an ECDSA `r`/`s` ≥ n, or an Ed25519 encoding that does not decompress
(BIP-340 vectors 5 and 14 among them). TypeScript returns `false`. BIP-340's own test vectors and
RFC 8032 §5.1.7 specify that verification _fails_ on these inputs; the port represents these
verification failures as `false`. **Proposed upstream change:** parse with `is_ok()` and return
`false`.

### D4. scrypt with `logN: 0` (1 vector)

`scrypt::Params::new(0, r, p, len)` passes every check (`0 < 16·r`), so the reference computes with
N = 1; noble requires `2 ≤ N ≤ 2^32`, so TypeScript throws `InvalidParameter`. The port keeps the
backend's minimum cost. **Proposed upstream change:** require `log_n ≥ 1`.

### D5. PBKDF2 with `iterations: 0` (1 vector)

RustCrypto's `pbkdf2_body` computes `U₁` unconditionally and iterates `1..rounds`, so **zero
iterations produce the same bytes as one**; TypeScript throws `InvalidParameter`. RFC 8018 §5.2
defines the iteration count as a positive integer; the port enforces that requirement. (A
zero-length output, `dkLen: 0`, is an empty key on both sides.) **Proposed upstream change:** assert
`iterations ≥ 1` in `bc-crypto` (or in components' `PBKDF2Params`).

> Any divergence found must be added here in the same commit that introduces or discovers it, with
> the input, the Rust outcome, the TypeScript outcome, the reason the difference is intentional and
> the upstream fix, and mirrored in `expected_divergence()` in the harness.

## 2. JS-only input domain

- **Wrong-length inputs.** Rust takes fixed-size arrays (`&[u8; 32]`), so a wrong length cannot
  reach it. TypeScript throws `CryptoError` with `code: "InvalidSize"` and
  `details: { what, expected, actual }`. The harness's `fixed::<N>` maps a wrong length to `throw`,
  so these vectors are _compared_ (throw = throw), not skipped.
- **`scrypt`'s memory ceiling.** noble refuses a derivation whose working set `128·r·(N + p + 1)`
  exceeds `maxmem` (default `128·8·(2^20 + 2)`, a little over 1 GiB); the reference allocates
  whatever the parameters imply. `ScryptOptions.maxmem` lifts the ceiling on request; the default
  limits the memory requested by a derivation.
- **`chacha20`** (raw keystream, `{ counter }`) has no function in `bc-crypto`; the reference stack
  has it in `provenance-mark-rust`, which uses the `chacha20` crate directly. Its vectors are
  classified `J1` by the harness (the provenance-mark harness compares the obfuscated output end to
  end).
- **Argument-domain faults** (zero or out-of-range scalars, points not on the curve, KDF numbers out
  of range, negative counters): every one throws `CryptoError` — `InvalidData` for a scalar or
  point, `InvalidParameter` for a KDF number or counter — with the backend's error as `cause` where
  there is one. The reference panics on the same inputs (D4 and D5 above are the two it computes
  instead).

## 3. Mapping equivalences

- **Strict Ed25519.** The reference's `ed25519_verify` is `ed25519-dalek`'s `verify_strict`: a
  small-order public key or `R` is rejected, a non-canonical `s` (≥ L) is rejected by
  `check_scalar`, and a non-canonical `R` fails the byte comparison against the recomputed `R`. The
  port decodes the key and `R` with `zip215: false`, returns `false` if either is small-order, then
  verifies with `{ zip215: false }`. The reference parser also accepts some non-canonical encodings
  of the **public key** (`FieldElement::from_bytes` ignores bit 255 and does not check `y < p`)
  while the port rejects it, as RFC 8032 requires; that encoding exists only for a point with
  `y ≤ 18`. The generated signing fixtures do not establish equivalence for every such encoding.
  Vectored: the identity key with the `(identity, 0)` signature, its non-canonical `y = p + 1`
  encoding, a non-canonical `R`, a non-canonical `s` (`s + L`), RFC 8032 vectors 1–3 with bit-flip
  negatives, and every signing triple with flipped signature, message and key.
- **Low-S ECDSA.** Both sides reject a high-S signature (libsecp256k1's `verify_ecdsa` does not
  normalise; noble verifies with `lowS: true`); vectored per signing triple.
- **X25519 bit 255.** Both sides mask the high bit of a public key (RFC 7748 §5): `ff…ff` derives
  the same key on both (vectored).
- **HKDF with an empty salt** equals a salt of `hashLen` zero bytes on both sides (RFC 5869 default;
  HMAC pads either to the block size). Vectored for SHA-256 and SHA-512; provenance-mark's only HKDF
  call relies on it.
- **scrypt parameter rules.** `scrypt::Params::new` (the reference's parameterised `scrypt_opt`)
  requires `log_n < 64`, `r, p > 0`, `log_n < 16·r`, `r·p < 2^30` and `10 ≤ len ≤ 64`; the
  reference's default `scrypt` uses `Params::recommended()` (log₂N 17, r 8, p 1) and only requires
  `len > 0`. The port enforces the same rules on the same two paths (`logN`/`r`/`p` given → the
  parameterised rules). Vectored on both paths, including `(logN 17, r 1)` and
  `(logN 4, r 32768, p 32768)`.
- **argon2id.** `Argon2::default()` — Argon2id, version 0x13, m 19456 KiB, t 2, p 1 — on both sides;
  `dkLen ≥ 4` and `salt ≥ 8` are the crate's minimums and the port's checks. There are no other
  costs on either side.
- **Derivations.** `derive_signing_private_key` and `ecdsa_derive_private_key` are the same
  computation in the reference; the port exports one `deriveSigningPrivateKey` (and
  `deriveAgreementPrivateKey`) at the root. The frozen `ecdsaDerive` recipe maps to the Rust
  `ecdsa_derive_private_key` and the TypeScript `deriveSigningPrivateKey`.
- **API shape.** `bc_crypto::ecdsa_sign(priv, msg)` ↔ `ecdsa.sign(priv, msg)`; the `*_using(rng)`
  functions ↔ `{ rng }` options; `scrypt_opt(pw, salt, len, log_n, r, p)` ↔
  `scrypt(pw, salt, { dkLen, logN, r, p })`. The harness maps each recipe to the Rust call directly.
- **AEAD layout.** Rust returns `(ciphertext, tag)`; TypeScript returns the concatenation. Vectors
  store the concatenation and the harness joins the Rust tuple. A failed decryption is `Error::Aead`
  there and `CryptoError` `AuthenticationFailed` (message `"AEAD error"`) here.
- **Ed25519 verify order.** Rust and the pre-redesign TypeScript took `(pub, msg, sig)`; the
  redesign takes `(pub, sig, msg)` like the other schemes. Pure argument order; the harness swaps.
- **RNG bridge and the two byte streams.** `ecdsa_new_private_key_using`,
  `x25519_new_private_key_using` and `schnorr_sign_using` draw `rng.random_data(n)` (one 64-bit step
  per byte on the seeded generator); `ed25519_new_private_key_using` takes a
  `rand_core::CryptoRngCore` and `SigningKey::generate` draws `fill_bytes` — on the seeded generator
  the _packed_ `fill_bytes_via_next` stream (eight bytes per step). TypeScript mirrors both:
  `randomBytes(n, { rng })` for the first three, `rng.fillBytesPacked ?? rng.fillBytes` for Ed25519
  (identical for every generator but `SeededRng`). The harness bridges `bc-rand`'s generator into
  the 0.6 trait by forwarding each method to the generator's own. From the fixture seed an Ed25519
  private key is `7e061813…` on both sides.

## Maintenance

When the upstream reference moves:

1. Review the diff via the link in the `upstream.yml` tracking issue.
2. Port the relevant changes.
3. Update `.github/versions.yml` with the new version and commit.
4. Update the tracked version at the top of this file.
5. Add, amend, or remove divergence entries as the port requires.
