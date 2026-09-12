# Compatibility with the Rust reference

The published reference is `bc-crypto` **0.14.0**, commit
[`4f2b791320730578b04943c833c4a9e6c232fc4d`](https://github.com/BlockchainCommons/bc-crypto-rust/commit/4f2b791320730578b04943c833c4a9e6c232fc4d),
recorded in [`.github/versions.yml`](./.github/versions.yml).
This document describes the current TypeScript working tree, including the pending beta.2 fixes
listed in [CHANGELOG.md](./CHANGELOG.md) and [MIGRATION.md](./MIGRATION.md).

## Validation scope

The committed corpus contains **679 vectors**. Against the published Rust reference:

```
679 vectors - 649 match, 30 expected-divergence/js-only, 0 MISMATCH
```

The 30 comprise D2 ×9, D3 ×13, D4 ×1, D5 ×4, and raw ChaCha20 ×3.
The exception list contains exact reviewed recipes in
[`tests/rust-validation/expected-divergences.json`](./tests/rust-validation/expected-divergences.json).
A new recipe cannot automatically inherit an exception. The harness also checks that D2
returns the specific HKDF-of-zero key, not merely any successful result.

The harness compares Rust outputs against committed TypeScript expectations. Golden tests
check the current TypeScript implementation against those expectations. Failures are
normalized to `throw`; this does not establish equality of error classes, messages,
panic recovery, or allocation behavior. Wrong-length fixed-array arguments are rejected
by the harness adapter because the Rust call cannot represent them. Raw ChaCha20 is
classified before comparison because `bc-crypto` has no corresponding function.

## Remaining behavioral differences from Rust 0.14.0

### D2: X25519 low-order peers

Rust applies HKDF-SHA-256 with salt `agreement` to the all-zero shared secret,
producing the same symmetric key independently of the private key. TypeScript rejects
that secret as `CryptoError` with `InvalidData`.

The fixtures cover nine low-order encodings/aliases. They do not exhaust every high-bit
variant. RFC 7748 permits all-zero rejection; this higher-level API deliberately chooses it.

### D3: malformed verification inputs

TypeScript returns `false` for right-length invalid keys/signatures. Rust 0.14.0 can panic:

- ECDSA: public-key or compact-signature parsing fails.
- Schnorr: x-only public-key parsing fails; invalid signature values can instead return false.
- Ed25519: public-key decoding fails; malformed R or s is handled inside verification.

### D4: scrypt logN = 0

Rust's parameter constructor accepts N = 1 and computes a result. TypeScript requires
logN >= 1 and rejects this input with `InvalidParameter`, consistent with RFC 7914.

### D5: PBKDF2 iterations = 0

For nonempty output, Rust treats zero iterations as one. For empty output, it returns
an empty vector. TypeScript rejects zero before checking output length, for both
SHA-256 and SHA-512. The four fixtures cover both hashes with lengths 0 and 32.

## Closed in TypeScript: Ed25519's verification equation

The beta.2 TypeScript implementation computes `[s]B - [k]A` and compares its canonical
encoding with R, as Dalek's `verify_strict` does. The earlier call to noble's verifier
cleared the cofactor, allowing a nonzero torsion residual to verify.

Sixteen fixtures cover order-two torsion in A, R, both, or neither. They include signatures
that must reject and mixed-order cases that satisfy the equation and must remain valid.
Both implementations agree on these fixtures. Ordinary generated signatures retain their
results. Rejecting every mixed-order point would not implement Rust's policy.

A residual **decoding-policy difference** remains: TypeScript requires canonical A and R
encodings; Dalek can decode some non-canonical A encodings and hashes the original bytes.
Dalek's final canonical byte comparison rejects non-canonical R. A parser difference alone
does not demonstrate an accepted-signature difference, and the present fixtures do not
prove equivalence for every non-canonical A. Keep this qualification when describing
“strict” compatibility; do not switch to ZIP-215 verification as a substitute.

## Platform limits and additional APIs

- **Integer and length validation:** JavaScript can express nonintegers, negative numbers,
  and wrong-length byte arrays where Rust uses unsigned integers or fixed arrays. TypeScript
  validates these inputs. This is not a cryptographic output difference.
- **scrypt limits:** TypeScript supports logN 1–32, subject to `logN < 16*r`, `r*p < 2^30`,
  output-length rules, and backend/runtime allocation limits. Parameterized output lengths
  are 10–64; the default path accepts 1 through `(2^32 - 1)*32` subject to memory.
  Rust additionally checks usize multiplication overflow and has an architecture-dependent
  logN limit. Its 0.11.0 backend's integer-division length check technically admits another
  31 output bytes beyond the stated maximum; this enormous allocation was not tested.
- **scrypt memory:** noble defaults to `128*8*(2^20 + 2)` bytes and checks
  `128*r*(N+p+1)` against `maxmem`. Rust has no matching configurable ceiling. This is a real
  resource-policy difference for parameters expressible on both sides. Raising `maxmem`
  does not enable logN > 32 or bypass engine allocation limits.
- **PBKDF2 output:** TypeScript caps dkLen at `u32::MAX`; Rust accepts usize. Huge outputs
  have not been allocated to test runtime behavior. Empty outputs match only with positive
  iterations.
- **Raw ChaCha20:** this is an additional TypeScript API used by provenance marks. Its
  backend reserves block counter `2^32 - 1`; initial counters are 0 through `2^32 - 2`, and
  `ceil(data.length / 64)` must not exceed `2^32 - 1 - counter`. The wrapper validates
  capacity and normalizes backend rejection to `CryptoError.InvalidParameter`.
- **Error handling:** documented validation/authentication failures use `CryptoError`;
  verification failures of the correct input lengths return false. Resource exhaustion or
  failures in user-supplied random generators are not covered by a universal error guarantee.

## Equivalent mappings over supported inputs

- ECDSA signs double SHA-256 using deterministic signatures and explicitly rejects high-S
  signatures. Both sides produce compact 64-byte signatures.
- X25519 masks the public key's high bit on both sides, independently of low-order rejection.
- HKDF uses the same salts, empty info, and output bytes. Empty salt is equivalent to the
  default zero salt for SHA-256 and SHA-512. Signing/agreement derivation names map to the
  same HKDF operations; the two Rust signing derivations share one TypeScript function.
- scrypt defaults are logN 17, r 8, p 1. Argon2id defaults are v0x13, m 19456 KiB, t 2, p 1;
  output length is at least 4 and salt length at least 8. Platform allocation limits remain.
- Rust's AEAD `(ciphertext, tag)` maps to TypeScript's `ciphertext || tag`. The harness joins
  and splits them. Authentication failures are compared as normalized failures.
- Grouped TypeScript methods and options map to Rust free functions. Ed25519 verification
  takes `(publicKey, signature, message)` in TypeScript; the adapter swaps Rust's order.
- ECDSA/X25519 private-key generation and Schnorr auxiliary randomness use `random_data`
  on Rust and `randomBytes` on TypeScript. Ed25519 uses rand_core's `fill_bytes`, mapped to
  `fillBytesPacked` when supplied and otherwise `fillBytes`. Any custom generator with
  distinct streams must expose the packed method. Seeded fixtures compare both paths.

## Maintenance

Run golden tests and the Rust harness whenever vectors or reference versions change.
A newly discovered divergence must include an input, both outcomes, rationale, and regression
coverage. Only add a reviewed exact-recipe exception for an intentionally retained difference.
When upstream fixes ship, update `.github/versions.yml`, the harness dependency/lockfile,
changelog and migration notes before revising this inventory and removing obsolete exceptions.
