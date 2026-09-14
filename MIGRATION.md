# Migrating from `@bcts/crypto` to `@blockchaincommons/crypto`

`@blockchaincommons/crypto` is the redesigned successor to `@bcts/crypto`.

## TL;DR checklist

- [ ] Replace the `@bcts/crypto` dependency with `@blockchaincommons/crypto`.
- [ ] Rewrite import specifiers: `@bcts/crypto` becomes `@blockchaincommons/crypto`.
- [ ] Rename calls per the table in §2; algorithm families are now objects
      (`ecdsa.sign`, `chacha20Poly1305.encrypt`, …).
- [ ] AEAD: `encrypt` returns one `Uint8Array` (`ciphertext || tag`); `decrypt`
      takes the same. Drop the tuple destructuring.
- [ ] `ed25519.verify(publicKey, signature, message)`: the argument order
      now matches `ecdsa.verify` and `schnorr.verify`.
- [ ] `*Using(rng)` variants are gone; pass `{ rng }`.
- [ ] `hkdfHmacSha256(km, salt, len)` becomes `hkdfSha256(km, salt, { dkLen: len })`.
- [ ] `*_SIZE` constants: use the family members (`ecdsa.SIGNATURE_SIZE`).
- [ ] `ecdsaDerivePrivateKey` becomes `deriveSigningPrivateKey` (same bytes);
      `deriveAgreementPrivateKey` is unchanged.
- [ ] Catch one `CryptoError` and switch on `details.code`; `AeadError` and
      `CryptoResult` no longer exist, for documented validation and authentication failures.
- [ ] `ed25519.verify` is strict (a small-order or non-canonical key or `R`
      never verifies); standard generated signatures are unaffected.
- [ ] Pass `Uint8Array`s (a `Buffer` qualifies). A string, plain array or
      `ArrayBuffer` in any byte position is now `CryptoError`
      `InvalidParameter`, named after the argument; encode text explicitly.
- [ ] A low-order X25519 peer in `x25519.sharedKey` derives the reference's
      fixed key instead of throwing `InvalidData`; reject such peers yourself.
- [ ] `verify` throws `InvalidData` for a public key the reference cannot
      parse (and `ecdsa.verify` for r or s ≥ n); a parsed input is still
      `true`/`false`. PBKDF2 `iterations: 0` and scrypt `logN: 0` derive.
- [ ] scrypt has no default memory ceiling; pass `maxmem` if you want one.
      PBKDF2 accepts `dkLen` up to (2^32 − 1)·hLen.
- [ ] Raise your Node floor to **22.12** and TypeScript to **>= 5.7**.

## 1. Package name and imports

```diff
- import { ecdsaSign } from "@bcts/crypto";
+ import { ecdsa } from "@blockchaincommons/crypto";
```

## 2. Renames

Hashes, MACs and KDFs stay free functions at the root. The `hash` namespace
is gone; everything it held is exported from the root under the new names.

| `@bcts/crypto` | `@blockchaincommons/crypto` |
| --- | --- |
| `hash.crc32(d)` / `crc32(d)` | `crc32(d)` |
| `hash.crc32Data(d)` | `crc32Bytes(d)` |
| `hash.crc32DataOpt(d, le)` | `crc32Bytes(d, { littleEndian: le })` |
| `sha256`, `doubleSha256`, `sha512`, `hmacSha256`, `hmacSha512` | unchanged |
| `pbkdf2HmacSha256(pw, salt, iter, len)` | `pbkdf2Sha256(pw, salt, { iterations, dkLen })` |
| `pbkdf2HmacSha512(pw, salt, iter, len)` | `pbkdf2Sha512(pw, salt, { iterations, dkLen })` |
| `hkdfHmacSha256(km, salt, len)` | `hkdfSha256(km, salt, { dkLen: len })` |
| `hkdfHmacSha512(km, salt, len)` | `hkdfSha512(km, salt, { dkLen: len })` |
| `scrypt(pw, salt, len)` | `scrypt(pw, salt, { dkLen })` |
| `scryptOpt(pw, salt, len, logN, r, p)` | `scrypt(pw, salt, { dkLen, logN, r, p })` |
| `argon2id(pw, salt, len)` | `argon2id(pw, salt, { dkLen })` |
| `argon2idHashOpt(pw, salt, len, t, m, p)` | removed: the reference exposes only `Argon2::default()` (Argon2id v0x13, m 19456 KiB, t 2, p 1) and the wire (`Argon2idParams`) carries a salt only, so no other costs can be reproduced elsewhere |
| `memzero(a)` | unchanged |
| `memzeroVecVecU8(arrays)` | `memzeroAll(arrays)` |

Algorithm families are `as const` objects, each carrying its size constants:

| `@bcts/crypto` | `@blockchaincommons/crypto` |
| --- | --- |
| `aeadChaCha20Poly1305Encrypt(pt, key, nonce)` → `[ct, tag]` | `chacha20Poly1305.encrypt(key, nonce, pt)` → `ct ‖ tag` |
| `aeadChaCha20Poly1305EncryptWithAad(pt, key, nonce, aad)` | `chacha20Poly1305.encrypt(key, nonce, pt, { aad })` |
| `aeadChaCha20Poly1305Decrypt(ct, key, nonce, tag)` | `chacha20Poly1305.decrypt(key, nonce, ct ‖ tag)` |
| `aeadChaCha20Poly1305DecryptWithAad(ct, key, nonce, aad, tag)` | `chacha20Poly1305.decrypt(key, nonce, ct ‖ tag, { aad })` |
| `x25519NewPrivateKey()` / `x25519NewPrivateKeyUsing(rng)` | `x25519.generatePrivateKey({ rng })` |
| `x25519PublicKeyFromPrivateKey(k)` | `x25519.publicKey(k)` |
| `x25519SharedKey(priv, pub)` | `x25519.sharedKey(priv, pub)` |
| `deriveAgreementPrivateKey(km)` | `deriveAgreementPrivateKey(km)` (unchanged, root) |
| `deriveSigningPrivateKey(km)` | unchanged (root) |
| `ecdsaNewPrivateKey()` / `ecdsaNewPrivateKeyUsing(rng)` | `ecdsa.generatePrivateKey({ rng })` |
| `ecdsaDerivePrivateKey(km)` | `deriveSigningPrivateKey(km)` (the same HKDF; one name) |
| `ecdsaPublicKeyFromPrivateKey(k)` | `ecdsa.publicKey(k)` |
| `ecdsaDecompressPublicKey` / `ecdsaCompressPublicKey` | `ecdsa.decompressPublicKey` / `ecdsa.compressPublicKey` |
| `ecdsaSign(k, msg)` / `ecdsaVerify(pub, sig, msg)` | `ecdsa.sign(k, msg)` / `ecdsa.verify(pub, sig, msg)` |
| `schnorrPublicKeyFromPrivateKey(k)` | `schnorr.publicKey(k)` |
| `schnorrSign(k, msg)` | `schnorr.sign(k, msg)` |
| `schnorrSignUsing(k, msg, rng)` | `schnorr.sign(k, msg, { rng })` |
| `schnorrSignWithAuxRand(k, msg, aux)` | `schnorr.sign(k, msg, { auxRand: aux })` |
| `schnorrVerify(pub, sig, msg)` | `schnorr.verify(pub, sig, msg)` |
| `ed25519NewPrivateKey()` / `ed25519NewPrivateKeyUsing(rng)` | `ed25519.generatePrivateKey({ rng })` |
| `ed25519PublicKeyFromPrivateKey(k)` | `ed25519.publicKey(k)` |
| `ed25519Sign(k, msg)` | `ed25519.sign(k, msg)` |
| `ed25519Verify(pub, **msg, sig**)` | `ed25519.verify(pub, **sig, msg**)` |

The flat `*_SIZE` constants are gone; sizes live on the family objects
(`ecdsa.SIGNATURE_SIZE`, `chacha20Poly1305.TAG_SIZE`, `x25519.PUBLIC_KEY_SIZE`,
`ed25519.PRIVATE_KEY_SIZE`). The hash sizes (`SHA256_SIZE`, `SHA512_SIZE`,
`CRC32_SIZE`) stay at the root.

## 3. AEAD returns one buffer

```diff
- const [ciphertext, tag] = aeadChaCha20Poly1305EncryptWithAad(pt, key, nonce, aad);
- const back = aeadChaCha20Poly1305DecryptWithAad(ciphertext, key, nonce, aad, tag);
+ const sealed = chacha20Poly1305.encrypt(key, nonce, pt, { aad });
+ const back = chacha20Poly1305.decrypt(key, nonce, sealed, { aad });
```

`sealed` is `ciphertext || tag`; the tag is the trailing
`chacha20Poly1305.TAG_SIZE` (16) bytes. Use `subarray` if a wire format keeps
them apart.

## 4. Errors

One class, `CryptoError`, with a `code` union, `details` discriminated by
that code, `cause`, and `is(code)`:

```ts
try {
  chacha20Poly1305.decrypt(key, nonce, sealed);
} catch (e) {
  if (CryptoError.isCryptoError(e)) {
    switch (e.details.code) {
      case "AuthenticationFailed": // tag mismatch; e.cause is the backend's error
      case "InvalidSize": // e.details: { what, expected, actual }
      case "InvalidData": // a key, point or signature of the right length that is not valid
      case "InvalidParameter": // an argument outside its domain, including a non-Uint8Array byte argument
    }
  }
}
```

`AeadError`, the `CryptoResult<T>` alias, the `Unsupported` code and the
public `CryptoError` constructor are gone; instances come from the static
factories. Length checks that used to throw a bare
`Error("Private key must be 32 bytes")` now throw `CryptoError` with
`code: "InvalidSize"`; the message names the parameter and the actual length.
Invalid scalars or points and rejected KDF parameters are reported as
`CryptoError` (previously the noble library's own `Error`/`RangeError`
escaped); a low-order X25519 public key derives the reference's fixed key
(HKDF of the all-zero secret, as x25519-dalek's unchecked `diffie_hellman`
gives it). Every byte argument is checked to be a `Uint8Array`
before anything else, and every options object to be an object: a string,
plain array or `ArrayBuffer` is `InvalidParameter` naming the argument (it
used to leak an engine `TypeError`, be silently accepted, or blame another
argument). The three `verify` functions throw `InvalidData` for a public key
the reference's parser rejects (its `.expect`, a panic) and `ecdsa.verify`
for an r or s ≥ n; any input that parses is `true` or `false`.
`ed25519.verify` is strict (`verify_strict`: no small-order key or `R`, a
canonical `R` and `s`, and an uncofactored equation) and decodes the key as
dalek does, a non-canonical y reduced.

## 5. Randomness

Functions that draw randomness take `{ rng }` and default to
`@blockchaincommons/rand`'s `secureRng()`. ECDSA/X25519 key generation and Schnorr auxiliary randomness use
`randomBytes`. Ed25519 uses `fillBytesPacked` when supplied, falling back
to `fillBytes`; this matches the Rust rand_core path. Custom generators
with different byte streams must expose that packed method. A generator's
own error, including rand's `RandError` `InvalidGenerator` for a generator
that lacks a method the draw calls, propagates unwrapped:

```diff
- const key = ecdsaNewPrivateKeyUsing(rng);
- const sig = schnorrSignUsing(key, msg, rng);
+ const key = ecdsa.generatePrivateKey({ rng });
+ const sig = schnorr.sign(key, msg, { rng });
```
