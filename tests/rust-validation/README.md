# Rust reference cross-validation (Phase 1.4)

Replays `tests/vectors/vectors.json` against `bc-crypto = 0.14.0`.

```sh
cd tests/rust-validation
cargo run --release -- ../vectors/vectors.json
```

Exit 0 iff every vector matches the Rust reference or is an allowlisted
expected divergence. The allowlist (`expected_divergence()`) is the
machine-readable twin of `RUST_DIVERGENCES.md`; keep them in sync.
Not wired into CI (needs a Rust toolchain); a mandatory manual gate at phase
boundaries.
