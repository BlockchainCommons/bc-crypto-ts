# Divergences from the Rust reference implementation

The reference is the published `bc-crypto` 0.14.0 crate, as-is. Its sources
are `bc-crypto-rust` commit
[`4f2b791320730578b04943c833c4a9e6c232fc4d`](https://github.com/BlockchainCommons/bc-crypto-rust/commit/4f2b791320730578b04943c833c4a9e6c232fc4d)
(tag `0.14.0`, the head of `master`), recorded in
[`.github/versions.yml`](./.github/versions.yml). `tests/rust-validation`
depends on the crate from crates.io (`bc-crypto = "=0.14.0"`).

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
- The reference is the crates.io crate pinned in `tests/rust-validation/Cargo.toml` and `Cargo.lock`; the harness prints the resolved version and source on stderr. `.github/workflows/upstream.yml` opens an issue when bc-crypto-rust moves. When a release ships, re-pin `Cargo.toml`, `Cargo.lock` and `.github/versions.yml` to it, regenerate the vectors and run the three replays; every new difference is a bug on one side.
