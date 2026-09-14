# Rust reference cross-validation

Replays vector files against the `bc-crypto` reference: the published
`bc-crypto` 0.14.0 crate from crates.io, whose sources are `bc-crypto-rust`
commit `4f2b791` (tag 0.14.0, the head of `master`). Nothing is patched.

```sh
cd tests/rust-validation
cargo run --release --offline -- ../vectors/vectors.json          # the golden file
bun ../../scripts/generate-vectors.ts --full /tmp/crypto-full.json
cargo run --release --offline -- /tmp/crypto-full.json            # the whole corpus
cargo run --release --offline -- ../vectors/heavy.json            # about 5 GiB, seconds
```

Result lines on 2026-09-14 (stderr names the resolved reference and the js-only classes):

```
807 vectors - 793 match, 14 js-only, 0 MISMATCH
1195 vectors - 1180 match, 15 js-only, 0 MISMATCH
1 vectors - 1 match, 0 js-only, 0 MISMATCH
```

## What is compared

- Every recipe is parsed into the reference's argument types first, outside
  `catch_unwind`. An input no Rust signature can receive is **js-only**, counted
  apart from matches and mismatches: J1, no reference function (raw ChaCha20);
  J2, a fixed-size argument of the wrong length; J3, sealed data under 16 bytes;
  J4, a number that is not an integer of the Rust width (`u8` logN, `u32`
  iterations, r and p, `usize` lengths). Nothing is truncated or cast.
- The reference call alone runs under `catch_unwind`: a panic is a throw. Every
  failure on both sides normalises to `throw`, so error codes and messages are
  not compared here; the golden and property suites pin the TypeScript codes.
- There is no exception list. Any other difference is a MISMATCH and the exit
  code is 1.

## The heavy vectors

`tests/vectors/heavy.json` holds scrypt with logN 22, r 9 (4.8 GiB of `V`),
which exercises the paged scrypt core. Rust replays it as above;
`bun scripts/check-heavy-vectors.ts` replays it on JavaScriptCore, where one
typed array cannot hold it, and `CRYPTO_HEAVY=1 bunx vitest run tests/heavy-vectors.test.ts`
on Node. Regenerate it with `bun scripts/generate-vectors.ts --heavy`.

## CI

The `rust-validation` job in `.github/workflows/ci.yml` builds the harness
against the crate (`cargo run --locked`), then runs the golden file, the
generated full corpus and the heavy file, followed by the Bun and Node heavy
checks. A MISMATCH anywhere fails the job.

## Maintenance

When the reference moves: update the pin in `Cargo.toml`, run
`cargo update -p bc-crypto`, update `.github/versions.yml`, regenerate the
vectors, run the three replays and copy the result lines into
`RUST_DIVERGENCES.md`. A new difference is a bug on one side: fix it, or
record it in `RUST_DIVERGENCES.md` with an input, both outcomes, the reason
no TypeScript design can match, and a vector.
