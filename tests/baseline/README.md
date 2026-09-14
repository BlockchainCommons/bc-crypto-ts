# Frozen baseline build

`crypto-baseline.mjs` is the self-contained ESM bundle of `@blockchaincommons/crypto` built from
commit `d2c99548ef30dfc0b763793ed236ffc9a0db8386`, the `@bcts/crypto` wire-format reference. Sibling
`@blockchaincommons/*` packages are INLINED from their own frozen baseline
bundles (@blockchaincommons/rand, @blockchaincommons/dcbor), so this bundle keeps the
behaviour its dependencies had at that commit.
`crypto-baseline.d.mts` is the public surface at that commit.

`tests/differential.test.ts` runs every corpus recipe through this bundle and
the working tree and asserts identical outcomes; it pins the sha256 below so
an accidental rebuild cannot turn the differential into a self-comparison.

Baseline commit: d2c99548ef30dfc0b763793ed236ffc9a0db8386
Baseline sha256: d3a5a82546fd0424232ba32ea1c1bd485e08f35f3f241edc90c8476fb1559655

`rand-baseline.mjs` / `rand-baseline.d.mts` are a vendored copy of
`@blockchaincommons/rand`'s own frozen baseline (see its `tests/baseline/README.md`),
needed here because the crypto baseline's `*Using(rng)` functions
take the baseline rand interface (`SeededRandomNumberGenerator`, `randomData(n)`),
not the current `SeededRng`/`fillBytes`.

Baseline commit: e59bf7d1d244c08a6686d20f60a26d5a8ba3f26b
Baseline sha256: 6548f8a20aab023597c495cebbfbc0f83204d63160523425973293ee11829163