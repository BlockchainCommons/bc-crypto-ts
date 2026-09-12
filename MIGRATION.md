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
      `CryptoResult` no longer exist, and no noble error escapes any more.
- [ ] `ed25519.verify` is strict (a small-order or non-canonical key or `R`
      never verifies); honest signatures are unaffected.
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
      case "InvalidParameter": // a KDF or counter argument outside its domain
    }
  }
}
```

`AeadError`, the `CryptoResult<T>` alias, the `Unsupported` code and the
public `CryptoError` constructor are gone; instances come from the static
factories. Length checks that used to throw a bare
`Error("Private key must be 32 bytes")` now throw `CryptoError` with
`code: "InvalidSize"`; the message names the parameter and the actual length.
Every other fault — an invalid scalar or point, a low-order X25519 public
key, a KDF argument out of range — is also a `CryptoError` (previously the
noble library's own `Error`/`RangeError` escaped). The three `verify`
functions return `false` for a malformed signature or public key of the
right length and only throw for wrong lengths; `ed25519.verify` is strict
(canonical encodings only, no small-order key or `R`), as the reference's
`verify_strict`.

## 5. Randomness

Functions that draw randomness take `{ rng }` and default to
`@blockchaincommons/rand`'s `secureRng()`. The bytes drawn from a given
generator are the same as before (one 32-byte fill per key, one per
Schnorr aux-rand), so seeded outputs are unchanged:

```diff
- const key = ecdsaNewPrivateKeyUsing(rng);
- const sig = schnorrSignUsing(key, msg, rng);
+ const key = ecdsa.generatePrivateKey({ rng });
+ const sig = schnorr.sign(key, msg, { rng });
```

## 6. Node and TypeScript floors

Node **22.12** and TypeScript **5.7** (for `Uint8Array<ArrayBuffer>` return
types). The IIFE / global-script build is gone; use the ESM or CJS entry.

## 7. What did not change

- Every output byte, including the HKDF salts (`"agreement"`, `"signing"`),
  the scrypt defaults (log₂N 17, r 8, p 1) and the Argon2id defaults
  (t 2, m 19456 KiB, p 1).
- ECDSA signs `doubleSha256(message)` deterministically (RFC 6979) and
  returns the 64-byte compact form.
- Schnorr is BIP-340 with 32 bytes of aux-rand.
