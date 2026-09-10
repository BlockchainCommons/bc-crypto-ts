# Frozen baseline build

`crypto-baseline.mjs` is the self-contained ESM bundle of `@blockchaincommons/crypto` built from
commit `d2c99548ef30dfc0b763793ed236ffc9a0db8386`, the pre-redesign wire-format reference. Sibling
`@blockchaincommons/*` packages are INLINED from their own frozen baseline
bundles (@blockchaincommons/rand, @blockchaincommons/dcbor), so this bundle keeps the
pre-redesign behaviour of its dependencies after they change.
`crypto-baseline.d.mts` is the public surface at that commit (Phase 0.5).

`tests/differential.test.ts` runs every corpus recipe through this bundle and
the working tree and asserts identical outcomes; it pins the sha256 below so
an accidental rebuild cannot turn the differential into a self-comparison.

Baseline commit: d2c99548ef30dfc0b763793ed236ffc9a0db8386
Baseline sha256: 57148b07094f9488bdc8c3a35183faad440181967aed5e08452ccee45c106fd5
