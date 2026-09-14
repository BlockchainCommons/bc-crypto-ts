# Divergences from the Rust reference implementation

The reference is the `bc-rust/bc-crypto-rust` working tree: commit
[`4f2b791320730578b04943c833c4a9e6c232fc4d`](https://github.com/BlockchainCommons/bc-crypto-rust/commit/4f2b791320730578b04943c833c4a9e6c232fc4d)
(tag `0.14.0`, `Cargo.toml` version 0.14.0) plus its uncommitted edits, recorded in
[`.github/versions.yml`](./.github/versions.yml):

- `ecdsa_verify`, `schnorr_verify` and `ed25519_verify` return `false` for an unparseable public key or signature (`src/ecdsa_signing.rs`, `schnorr_signing.rs`, `ed25519_signing.rs`);
- `try_x25519_shared_key` returns `Err(Error::NonContributoryKey)` for a low-order peer, and `x25519_shared_key` panics on it (`src/public_key_encryption.rs`, `error.rs`);
- `scrypt_opt` asserts `log_n > 0` (`src/scrypt.rs`);
- `pbkdf2_hmac_sha256` and `pbkdf2_hmac_sha512` assert `iterations > 0`, including for empty output (`src/hash.rs`).

The released `bc-crypto` 0.14.0 differs from the reference on these four points and is not the reference. `tests/rust-validation/Cargo.toml` patches `bc-crypto` to that tree (`[patch.crates-io]`), and CI reproduces the tree from `tests/rust-validation/reference/bc-crypto-rust-4f2b791-edits.patch`; when the release that contains the edits ships, the pin moves to it and nothing else changes (see Maintenance).

`tests/rust-validation` replays the vectors against the reference in CI:

    807 vectors - 793 match, 14 js-only, 0 MISMATCH      tests/vectors/vectors.json
    1195 vectors - 1180 match, 15 js-only, 0 MISMATCH    the full corpus (generated in CI)
    1 vectors - 1 match, 0 js-only, 0 MISMATCH           tests/vectors/heavy.json (scrypt logN 22, r 9)

There is no exception list: any difference is a MISMATCH. The js-only rows are inputs the reference's signatures cannot receive (no reference function, as for raw ChaCha20; a fixed-size argument of the wrong length; sealed data under 16 bytes; a number outside the Rust width); they are neither matches nor divergences.

## 1. True behavioral divergences (same input, different outcome)

For every input the reference accepts and a JavaScript runtime can hold, outputs and accept/reject decisions are identical, with one exception.

### D1. PBKDF2 output past (2^32 − 1)·hLen

`pbkdf2Sha256`, `pbkdf2Sha512` and scrypt's default path stop at (2^32 − 1)·hLen output bytes (RFC 8018 §5.2) and throw `InvalidParameter` beyond it. The reference accepts a longer `key_len`, and its `pbkdf2` 0.12.2 backend's `u32` block counter then overflows: a panic with overflow checks, a wrapped counter (the output repeats from the start) without them. `scrypt` 0.11.0 admits 31 further bytes that reach that block. The port does not reproduce this because the reference's result depends on its build profile and needs at least 137 GiB of output.

## Maintenance

- CI runs the harness on `vectors.json`, the full corpus and `heavy.json`, and checks the heavy vectors in TypeScript under Bun and Node. A difference is a bug on one side. Either fix it, or record it here with an input, both outcomes, the reason no TypeScript design can match, and a vector.
- The reference is the bc-rust working tree, patched into the harness with `[patch.crates-io] bc-crypto = { path = … }`; the harness prints the resolved source on stderr. `.github/workflows/upstream.yml` opens an issue when bc-crypto-rust moves. When the release that contains the four edits ships, re-pin `tests/rust-validation/Cargo.toml`, `Cargo.lock` and `.github/versions.yml` to it, and drop the patch, the `reference/` directory and the CI step that materialises the tree. No port behaviour changes with that move; the three result lines must be unchanged. The bc-components-ts and bc-envelope-ts harnesses carry the same patch and move their locks on their own schedule.
