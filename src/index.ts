/**
 * @blockchaincommons/crypto - the cryptographic primitives the Blockchain
 * Commons stack is built on, over the noble libraries.
 *
 * - Hashes and KDFs as free functions: {@link sha256}, {@link hmacSha256},
 *   {@link hkdfSha256}, {@link pbkdf2Sha256}, {@link scrypt}, {@link argon2id}, {@link crc32}.
 * - Algorithm families as objects: {@link chacha20Poly1305}, {@link x25519},
 *   {@link ecdsa}, {@link schnorr}, {@link ed25519}.
 * - Every failure is a {@link CryptoError} with a `code`.
 * - Every function that draws randomness takes `{ rng }`, defaulting to the
 *   secure generator.
 *
 * @module @blockchaincommons/crypto
 */
export {
  CryptoError,
  type CryptoErrorCode,
  type CryptoErrorDetailsByCode,
  type CryptoErrorTyped,
} from "./error.js";
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
} from "./hash.js";
export { scrypt, type ScryptOptions, argon2id, type Argon2idOptions } from "./kdf.js";
export {
  SYMMETRIC_KEY_SIZE,
  SYMMETRIC_NONCE_SIZE,
  SYMMETRIC_AUTH_SIZE,
  chacha20Poly1305,
  type Chacha20Poly1305,
  type AeadOptions,
} from "./aead.js";
export {
  X25519_PRIVATE_KEY_SIZE,
  X25519_PUBLIC_KEY_SIZE,
  x25519,
  type X25519,
  deriveSigningPrivateKey,
  type KeygenOptions,
} from "./x25519.js";
export {
  ECDSA_PRIVATE_KEY_SIZE,
  ECDSA_PUBLIC_KEY_SIZE,
  ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE,
  ECDSA_MESSAGE_HASH_SIZE,
  ECDSA_SIGNATURE_SIZE,
  SCHNORR_PUBLIC_KEY_SIZE,
  SCHNORR_SIGNATURE_SIZE,
  ecdsa,
  type Ecdsa,
  schnorr,
  type Schnorr,
  type SchnorrSignOptions,
} from "./ecdsa.js";
export {
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
  ed25519,
  type Ed25519,
} from "./ed25519.js";
