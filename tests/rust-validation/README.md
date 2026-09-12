# Rust reference cross-validation

Replays `tests/vectors/vectors.json` against `bc-crypto = 0.14.0`.

```sh
cd tests/rust-validation
cargo run --release -- ../vectors/vectors.json
```

Exit 0 iff every vector matches the Rust reference or is an allowlisted
expected divergence. The allowlist (`expected_divergence()`) is the
machine-readable twin of `RUST_DIVERGENCES.md`; keep them in sync.
Not wired into CI (needs a Rust toolchain); run it manually when updating vectors or the reference version.

The reviewed exceptions are exact recipes in `expected-divergences.json`.
Pass `--strict` after the vectors path to reject every behavioral divergence
while still classifying the raw ChaCha20 extension as JS-only. Use this mode
when checking an upstream candidate that fixes D2–D5. Normal validation remains
pinned to the published 0.14.0 crate.
