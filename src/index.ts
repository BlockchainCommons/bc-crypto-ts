/**
 * @blockchaincommons/crypto - the cryptographic primitives the Blockchain
 * Commons stack is built on, over the noble libraries.
 *
 * - Hashes and KDFs as free functions: {@link sha256}, {@link hmacSha256},
 *   {@link hkdfSha256}, {@link pbkdf2Sha256}, {@link scrypt}, {@link argon2id}, {@link crc32}.
 * - Algorithm families as objects: {@link chacha20Poly1305}, {@link x25519},
 *   {@link ecdsa}, {@link schnorr}, {@link ed25519}; each carries its own
 *   size constants (`ecdsa.PRIVATE_KEY_SIZE`, `chacha20Poly1305.TAG_SIZE`).
 * - The stack's two key derivations at the root: {@link deriveSigningPrivateKey}
 *   and {@link deriveAgreementPrivateKey}.
 * - Every failure of an argument or of a primitive is a {@link CryptoError}
 *   with a `code`; a backend's own error, when there is one, is its `cause`.
 *   Byte arguments must be `Uint8Array`s (checked before anything else). A
 *   generator's own error (`RandError`), and allocation failure outside the
 *   KDFs, propagate as thrown.
 * - Every function that draws randomness takes `{ rng }` ({@link RngOptions}
 *   from `@blockchaincommons/rand`), defaulting to the secure generator.
 *
 * @module @blockchaincommons/crypto
 */
export { CryptoError, type CryptoErrorCode, type CryptoErrorDetails } from "./error.js";
export type { RngOptions } from "@blockchaincommons/rand";
export { memzero, memzeroAll, type NumericTypedArray } from "./memzero.js";
export {
  CRC32_SIZE,
  SHA256_SIZE,
  SHA512_SIZE,
  crc32,
  crc32Bytes,
  type Crc32Options,
  sha256,
  doubleSha256,
  sha512,
  hmacSha256,
  hmacSha512,
  pbkdf2Sha256,
  pbkdf2Sha512,
  type Pbkdf2Options,
  hkdfSha256,
  hkdfSha512,
  type HkdfOptions,
} from "./hash.js";
export { scrypt, type ScryptOptions, argon2id, type Argon2idOptions } from "./kdf.js";
export { chacha20Poly1305, type Chacha20Poly1305, type AeadOptions } from "./aead.js";
export {
  x25519,
  type X25519,
  deriveSigningPrivateKey,
  deriveAgreementPrivateKey,
} from "./x25519.js";
export { ecdsa, type Ecdsa, schnorr, type Schnorr, type SchnorrSignOptions } from "./ecdsa.js";
export { ed25519, type Ed25519 } from "./ed25519.js";
export { chacha20, type Chacha20Options } from "./stream.js";
