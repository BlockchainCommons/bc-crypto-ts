# Migrating from `@bcts/crypto` to `@blockchaincommons/crypto`

`@blockchaincommons/crypto` is the canonical home of this library. It was extracted from the
[`paritytech/bcts`](https://github.com/paritytech/bcts) monorepo, where it was
published as `@bcts/crypto`, into its own Blockchain Commons repository at
[`BlockchainCommons/bc-crypto-ts`](https://github.com/BlockchainCommons/bc-crypto-ts).

For the extraction release, **`1.0.0-beta.1`, the public API is unchanged.** The
migration is a rename. `@bcts/crypto` remains published for one beta cycle as a
thin re-export of this package, so nothing breaks the moment you update.

## TL;DR checklist

- [ ] Replace the `@bcts/crypto` dependency with `@blockchaincommons/crypto`.
- [ ] Rewrite import specifiers: `@bcts/crypto` becomes `@blockchaincommons/crypto`.
- [ ] Raise your Node floor to **22.12**.
- [ ] Ensure TypeScript **>= 5.7** to consume the published types.
- [ ] If you relied on the `browser` field or a global-script build, switch to the ESM or CJS entry point.

## 1. Package name and imports

```diff
- import { /* ... */ } from "@bcts/crypto";
+ import { /* ... */ } from "@blockchaincommons/crypto";
```

```diff
  "dependencies": {
-   "@bcts/crypto": "^1.0.0-beta.6"
+   "@blockchaincommons/crypto": "^1.0.0-beta.1"
  }
```

## 2. Version numbering restarts

`@bcts/crypto` versions moved in lockstep with every other package in the
monorepo, which is why it reached `1.0.0-beta.6`. Each extracted package now
versions independently and starts again at `1.0.0-beta.1`. A lower version
number here does **not** mean older code.

## 3. Node and TypeScript floors moved up

| | `@bcts/crypto` | `@blockchaincommons/crypto` |
|---|---|---|
| Node | `>= 18` | `>= 22.12` |
| TypeScript (consumers) | 6.x | `>= 5.7` |

## 4. The IIFE / global-script build is gone

`@bcts/crypto` shipped an additional IIFE bundle exposed through the `browser`
field. That build is dropped: IIFE entry points cannot share chunks, which forks
module-level singletons across entry points. Use the ESM entry (`import`) or the
CJS entry (`require`); both are declared in `exports` and validated in CI by
`publint` and `@arethetypeswrong/cli`.

## 5. Peer packages renamed too

Every sibling library moved from the `@bcts` scope to `@blockchaincommons`. If
you depend on more than one, rename them together so a single copy of each
shared type is resolved:

| Old | New |
|---|---|
| `@bcts/dcbor` | `@blockchaincommons/dcbor` |
| `@bcts/<name>` | `@blockchaincommons/<name>` |

## 6. What did not change

- The public API: every exported name, signature and type is identical.
- The wire format. Encodings produced by `@bcts/crypto` decode here, and the reverse.
- Parity with the Rust reference implementation. See [`RUST_DIVERGENCES.md`](./RUST_DIVERGENCES.md).
