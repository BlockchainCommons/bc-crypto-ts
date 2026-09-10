# Blockchain Commons Cryptographic Utilities

### _by Leonardo Custodio_

**`bc-crypto-ts`** provides the hashing, symmetric encryption, key derivation, and signature primitives shared across the Blockchain Commons TypeScript stack.

`@bcts/crypto` exposes a uniform API for the cryptographic primitives used in higher-level [Blockchain Commons](https://blockchaincommons.com) projects such as Gordian Envelope.

## Features

- **Hash Functions**: SHA-256, SHA-512, HMAC, PBKDF2, HKDF, CRC32
- **Symmetric Encryption**: ChaCha20-Poly1305 AEAD
- **Public Key Cryptography**:
  - X25519 (key agreement)
  - ECDSA (secp256k1 signing/verification)
  - Schnorr signatures (BIP-340)
  - Ed25519 (signing/verification)
- **Key Derivation**: Scrypt, Argon2id
- **Memory Security**: Best-effort memory zeroing utilities

## Security Considerations

### Memory Zeroing (`memzero`)

⚠️ **IMPORTANT SECURITY LIMITATION**

The `memzero()` function provides **best-effort** memory clearing in JavaScript/TypeScript, but **cannot guarantee** that sensitive data is fully erased from memory.

**Why this limitation exists:**

- JavaScript/TypeScript lacks volatile memory writes (unlike the Rust reference implementation which uses `std::ptr::write_volatile()`)
- JavaScript engines and JIT compilers may optimize away zeroing operations
- The garbage collector may have made copies of sensitive data
- Swapped pages or memory dumps may contain copies

**What `memzero()` does:**

- ✅ Overwrites memory with zeros to reduce exposure time
- ✅ Makes a verification check to prevent some optimizations
- ❌ Cannot guarantee complete erasure from physical memory

**Best practices for sensitive operations:**

1. **Use Web Crypto API when possible**: For truly sensitive cryptographic operations, use `crypto.subtle` with non-extractable keys
2. **Minimize exposure time**: Call `memzero()` immediately after sensitive operations
3. **Understand the limitations**: This is defense-in-depth, not a security guarantee
4. **Consider your threat model**: Evaluate if JavaScript is appropriate for your security requirements

**Example:**

```typescript
import { memzero } from '@bcts/crypto';

const sensitiveKey = new Uint8Array(32);
// ... use the key ...

// Clear from memory (best effort)
memzero(sensitiveKey);
```

For more details, see the [implementation comments](./src/memzero.ts).

## Installation Instructions

[@blockchaincommons/crypto](https://www.npmjs.com/package/@blockchaincommons/crypto) is published to npm. Install it with your package manager of choice:

```sh
npm install @blockchaincommons/crypto
# or
pnpm add @blockchaincommons/crypto
# or
yarn add @blockchaincommons/crypto
# or
bun add @blockchaincommons/crypto
```

**Requirements:** TypeScript >= 5.7 is required to consume the published types. Node >= 22.12 is required.

## Usage Instructions

```typescript
import {
  sha256,
  hkdfSha256,
  chacha20Poly1305,
  ecdsa,
  schnorr,
  ed25519,
  x25519,
  CryptoError,
} from "@blockchaincommons/crypto";

// Hashes and KDFs are plain functions.
const digest = sha256(new TextEncoder().encode("hello"));
const key = hkdfSha256(digest, new Uint8Array(16), 32);

// Algorithm families are objects; every function that draws randomness
// takes `{ rng }` and defaults to the secure generator.
const priv = ecdsa.generatePrivateKey();
const sig = ecdsa.sign(priv, digest);
ecdsa.verify(ecdsa.publicKey(priv), sig, digest); // true

// AEAD returns `ciphertext || tag` as one buffer.
const nonce = new Uint8Array(chacha20Poly1305.NONCE_SIZE);
const sealed = chacha20Poly1305.encrypt(key, nonce, digest, { aad: new Uint8Array(0) });
try {
  chacha20Poly1305.decrypt(key, nonce, sealed);
} catch (e) {
  if (CryptoError.isCryptoError(e) && e.code === "AuthenticationFailed") {
    /* tampered */
  }
}
```

Runnable examples live in the [`examples/`](https://github.com/BlockchainCommons/bc-crypto-ts/tree/master/examples) directory.

## Status - Beta

`bc-crypto-ts` is currently under active development and in beta testing. It should not be used for production tasks until it has had further testing and auditing. See [Blockchain Commons' Development Phases](https://github.com/BlockchainCommons/Community/blob/master/release-path.md).

### Version History

- **1.0.0-beta.1 (September 9, 2026)** - Initial beta release, extracted from the [`paritytech/bcts`](https://github.com/paritytech/bcts) monorepo and redesigned as an idiomatic TypeScript library ([MIGRATION.md](./MIGRATION.md)). Output bytes are unchanged and cross-validated against `bc-crypto 0.14.0`.

### Roadmap

- Continued testing and auditing on the path from beta to a stable **1.0.0** release.
- Continued parity with the Rust reference implementation as it evolves (see [`RUST_DIVERGENCES.md`](./RUST_DIVERGENCES.md)).

### Dependencies

`@blockchaincommons/crypto` depends on `@blockchaincommons/rand`, `@noble/ciphers`, `@noble/curves`, `@noble/hashes` at runtime.

To build and work on this library, you'll need the following tools:

- [Node.js](https://nodejs.org/) >= 22.12 - JavaScript runtime.
- [Bun](https://bun.sh/) - used in CI to install dependencies and run scripts (any Node-compatible package manager also works).
- [TypeScript](https://www.typescriptlang.org/) >= 5.7 - language and type checker.

### Derived from ...

This `bc-crypto-ts` project is either derived from or was inspired by:

- [BlockchainCommons/bc-crypto-rust](https://github.com/BlockchainCommons/bc-crypto-rust) - The reference Rust implementation, by [Wolf McNally](https://github.com/wolfmcnally).
- [paritytech/bcts](https://github.com/paritytech/bcts) - A TypeScript port covering many Blockchain Commons' implementations, by [Parity Technologies](https://github.com/paritytech).

## Financial Support

`bc-crypto-ts` is a project of [Blockchain Commons](https://www.blockchaincommons.com/). We are proudly a "not-for-profit" social benefit corporation committed to open source & open development. Our work is funded entirely by donations and collaborative partnerships with people like you. Every contribution will be spent on building open tools, technologies, and techniques that sustain and advance blockchain and internet security infrastructure and promote an open web.

To financially support further development of `bc-crypto-ts` and other projects, please consider becoming a Patron of Blockchain Commons through ongoing monthly patronage as a [GitHub Sponsor](https://github.com/sponsors/BlockchainCommons). You can also support Blockchain Commons with bitcoins at our [BTCPay Server](https://btcpay.blockchaincommons.com/).

## Contributing

We encourage public contributions through issues and pull requests! Please review [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our development process. All contributions to this repository require a GPG signed [Contributor License Agreement](./CLA.md).

### Discussions

The best place to talk about Blockchain Commons and its projects is in our GitHub Discussions areas.

[**Gordian Developer Community**](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions). For standards and open-source developers who want to talk about interoperable wallet specifications, please use the Discussions area of the [Gordian Developer Community repo](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions). This is where you talk about Gordian specifications such as [Gordian Envelope](https://github.com/BlockchainCommons/Gordian/tree/master/Envelope#articles), [bc-shamir](https://github.com/BlockchainCommons/bc-shamir), [Sharded Secret Key Reconstruction](https://github.com/BlockchainCommons/bc-sskr), and [bc-ur](https://github.com/BlockchainCommons/bc-ur) as well as the larger [Gordian Architecture](https://github.com/BlockchainCommons/Gordian/blob/master/Docs/Overview-Architecture.md), its [Principles](https://github.com/BlockchainCommons/Gordian#gordian-principles) of independence, privacy, resilience, and openness, and its macro-architectural ideas such as functional partition (including airgapping, the original name of this community).

[**Gordian User Community**](https://github.com/BlockchainCommons/Gordian/discussions). For users of the Gordian reference apps, including [Gordian Coordinator](https://github.com/BlockchainCommons/iOS-GordianCoordinator), [Gordian Seed Tool](https://github.com/BlockchainCommons/GordianSeedTool-iOS), [Gordian Server](https://github.com/BlockchainCommons/GordianServer-macOS), [Gordian Wallet](https://github.com/BlockchainCommons/GordianWallet-iOS), and [SpotBit](https://github.com/BlockchainCommons/spotbit) as well as our whole series of [CLI apps](https://github.com/BlockchainCommons/Gordian/blob/master/Docs/Overview-Apps.md#cli-apps). This is a place to talk about bug reports and feature requests as well as to explore how our reference apps embody the [Gordian Principles](https://github.com/BlockchainCommons/Gordian#gordian-principles).

[**Blockchain Commons Discussions**](https://github.com/BlockchainCommons/Community/discussions). For developers, interns, and patrons of Blockchain Commons, please use the discussions area of the [Community repo](https://github.com/BlockchainCommons/Community) to talk about general Blockchain Commons issues, the intern program, or topics other than those covered by the [Gordian Developer Community](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions) or the 
[Gordian User Community](https://github.com/BlockchainCommons/Gordian/discussions).

### Other Questions & Problems

As an open-source, open-development community, Blockchain Commons does not have the resources to provide direct support of our projects. Please consider the discussions area as a locale where you might get answers to questions. Alternatively, please use this repository's [issues](https://github.com/BlockchainCommons/bc-crypto-ts/issues) feature. Unfortunately, we can not make any promises on response time.

If your company requires support to use our projects, please feel free to contact us directly about options. We may be able to offer you a contract for support from one of our contributors, or we might be able to point you to another entity who can offer the contractual support that you need.

### Credits

The following people directly contributed to this repository. You can add your name here by getting involved. The first step is learning how to contribute from our [CONTRIBUTING.md](./CONTRIBUTING.md) documentation.

| Name              | Role                | Github                                            | Email                                 | GPG Fingerprint                                    |
| ----------------- | ------------------- | ------------------------------------------------- | ------------------------------------- | -------------------------------------------------- |
| Christopher Allen | Principal Architect | [@ChristopherA](https://github.com/ChristopherA) | \<ChristopherA@LifeWithAlacrity.com\> | FDFE 14A5 4ECB 30FC 5D22  74EF F8D3 6C91 3574 05ED |
| Wolf McNally      | Lead Researcher/Engineer | [@wolfmcnally](https://github.com/wolfmcnally) | \<Wolf@WolfMcNally.com\> | 9436 52EE 3844 1760 C3DC  3536 4B6C 2FCF 8947 80AE |
| Leonardo Custodio | Maintainer        | [@leonardocustodio](https://github.com/leonardocustodio) | \<leonardo@snowpine.io\> | 59DA D997 67EF 3BAB 2B90 D057 5384 DEF3 B582 450D |

### Contributing Sponsor

**Blockchain Commons Cryptographic Utilities for TypeScript** was produced as a collaboration between Blockchain Commons and one of our patrons, [Parity Technologies](https://parity.io): Parity wrote the wrappers based on Blockchain Commons' specifications and reference libraries. Blockchain Commons is dedicated to not just creating open infrastructure on our own, but also coordinating the work of other companies in benefiting the Commons. Thanks to Parity for working directly with us in this manner.

![](.github/parity.svg)

## Responsible Disclosure

We want to keep all of our software safe for everyone. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us in a responsible manner. We are unfortunately not able to offer bug bounties at this time.

We do ask that you offer us good faith and use best efforts not to leak information or harm any user, their data, or our developer community. Please give us a reasonable amount of time to fix the issue before you publish it. Do not defraud our users or us in the process of discovery. We promise not to bring legal action against researchers who point out a problem provided they do their best to follow the these guidelines.

### Reporting a Vulnerability

Please report suspected security vulnerabilities in private via email to ChristopherA@BlockchainCommons.com (do not use this email for support). Please do NOT create publicly viewable issues for suspected security vulnerabilities.

The following keys may be used to communicate sensitive information to developers:

| Name              | Fingerprint                                        |
| ----------------- | -------------------------------------------------- |
| Christopher Allen | FDFE 14A5 4ECB 30FC 5D22  74EF F8D3 6C91 3574 05ED |

You can import a key by running the following command with that individual’s fingerprint: `gpg --recv-keys "<fingerprint>"` Ensure that you put quotes around fingerprints that contain spaces.
