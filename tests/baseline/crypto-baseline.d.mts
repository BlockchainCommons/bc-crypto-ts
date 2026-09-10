import { RandomNumberGenerator } from "@blockchaincommons/rand";
declare namespace hash_d_exports {
  export {
    CRC32_SIZE,
    SHA256_SIZE,
    SHA512_SIZE,
    crc32,
    crc32Data,
    crc32DataOpt,
    doubleSha256,
    hkdfHmacSha256,
    hkdfHmacSha512,
    hmacSha256,
    hmacSha512,
    pbkdf2HmacSha256,
    pbkdf2HmacSha512,
    sha256,
    sha512,
  };
}
declare const CRC32_SIZE = 4;
declare const SHA256_SIZE = 32;
declare const SHA512_SIZE = 64;
/**
 * Calculate CRC-32 checksum
 */
declare function crc32(data: Uint8Array): number;
/**
 * Calculate CRC-32 checksum and return as a 4-byte big-endian array
 */
declare function crc32Data(data: Uint8Array): Uint8Array;
/**
 * Calculate CRC-32 checksum and return as a 4-byte array
 * @param data - Input data
 * @param littleEndian - If true, returns little-endian; otherwise big-endian
 */
declare function crc32DataOpt(data: Uint8Array, littleEndian: boolean): Uint8Array;
/**
 * Calculate SHA-256 hash
 */
declare function sha256(data: Uint8Array): Uint8Array;
/**
 * Calculate double SHA-256 hash (SHA-256 of SHA-256)
 * This is the standard Bitcoin hashing function
 */
declare function doubleSha256(message: Uint8Array): Uint8Array;
/**
 * Calculate SHA-512 hash
 */
declare function sha512(data: Uint8Array): Uint8Array;
/**
 * Calculate HMAC-SHA-256
 */
declare function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array;
/**
 * Calculate HMAC-SHA-512
 */
declare function hmacSha512(key: Uint8Array, message: Uint8Array): Uint8Array;
/**
 * Derive a key using PBKDF2 with HMAC-SHA-256
 */
declare function pbkdf2HmacSha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  keyLen: number,
): Uint8Array;
/**
 * Derive a key using PBKDF2 with HMAC-SHA-512
 */
declare function pbkdf2HmacSha512(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  keyLen: number,
): Uint8Array;
/**
 * Derive a key using HKDF with HMAC-SHA-256
 */
declare function hkdfHmacSha256(
  keyMaterial: Uint8Array,
  salt: Uint8Array,
  keyLen: number,
): Uint8Array;
/**
 * Derive a key using HKDF with HMAC-SHA-512
 */
declare function hkdfHmacSha512(
  keyMaterial: Uint8Array,
  salt: Uint8Array,
  keyLen: number,
): Uint8Array;
//#endregion
//#region src/error.d.ts
/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 */
/**
 * AEAD-specific error for authentication failures
 */
declare class AeadError extends Error {
  constructor(message?: string);
}
/**
 * Generic crypto error type
 */
declare class CryptoError extends Error {
  override readonly cause?: Error | undefined;
  constructor(message: string, cause?: Error);
  /**
   * Create a CryptoError for AEAD authentication failures.
   *
   * @param error - Optional underlying AeadError
   * @returns A CryptoError wrapping the AEAD error
   */
  static aead(error?: AeadError): CryptoError;
  /**
   * Create a CryptoError for invalid parameter values.
   *
   * **TS-specific.** Rust's `bc_crypto::Error` enum has no
   * `InvalidParameter` variant; size validation in Rust is enforced at
   * compile time via fixed-size array references (e.g. `&[u8; 32]`) or
   * via `panic!`/`expect(...)` for runtime checks. The TS port has no
   * fixed-size array types, so it surfaces those same conditions through
   * a thrown `CryptoError.invalidParameter(...)`. Catching this is
   * equivalent to defensive guards around an `expect`-style panic on the
   * Rust side.
   *
   * @param message - Description of the invalid parameter
   * @returns A CryptoError describing the invalid parameter
   */
  static invalidParameter(message: string): CryptoError;
}
/**
 * Result type for crypto operations (using standard Error)
 */
type CryptoResult<T> = T;
//#endregion
//#region src/memzero.d.ts
/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 */
/**
 * Any of the integer-/float-valued typed arrays that JavaScript exposes.
 * Maps to Rust's `&mut [T]` parameter on `bc_crypto::memzero<T>`.
 */
type NumericTypedArray =
  | Uint8Array
  | Uint8ClampedArray
  | Uint16Array
  | Uint32Array
  | Int8Array
  | Int16Array
  | Int32Array
  | Float32Array
  | Float64Array;
/**
 * Securely zero out a typed array.
 *
 * Mirrors Rust `bc_crypto::memzero<T>(s: &mut [T])`. The Rust impl uses
 * `std::ptr::write_volatile()` to guarantee the writes survive optimization;
 * JavaScript has no equivalent primitive, so this is **best-effort** — JIT
 * compilers may still elide the loop, though the post-hoc verification
 * check forces the engine to keep the writes observable.
 *
 * For truly sensitive cryptographic operations, consider using the Web
 * Crypto API's `crypto.subtle` with non-extractable keys when possible, as
 * it provides stronger guarantees than what can be achieved with pure
 * JavaScript.
 *
 * Accepts any of the standard numeric typed arrays — `Uint8Array`,
 * `Uint8ClampedArray`, `Uint16Array`, `Uint32Array`, `Int8Array`,
 * `Int16Array`, `Int32Array`, `Float32Array`, `Float64Array` — matching
 * Rust's generic `&mut [T]`. (`BigInt64Array` / `BigUint64Array` are
 * excluded because their elements are `bigint`, not `number`; if that
 * support is needed, add a dedicated overload.)
 */
declare function memzero(data: NumericTypedArray): void;
/**
 * Securely zero out an array of Uint8Arrays.
 */
declare function memzeroVecVecU8(arrays: Uint8Array[]): void;
//#endregion
//#region src/symmetric-encryption.d.ts
declare const SYMMETRIC_KEY_SIZE = 32;
declare const SYMMETRIC_NONCE_SIZE = 12;
declare const SYMMETRIC_AUTH_SIZE = 16;
/**
 * Encrypt data using ChaCha20-Poly1305 AEAD cipher.
 *
 * **Security Warning**: The nonce MUST be unique for every encryption operation
 * with the same key. Reusing a nonce completely breaks the security of the
 * encryption scheme and can reveal plaintext.
 *
 * @param plaintext - The data to encrypt
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce (MUST be unique per encryption with the same key)
 * @returns Tuple of [ciphertext, authTag] where authTag is 16 bytes
 * @throws {CryptoError} If key is not 32 bytes or nonce is not 12 bytes
 */
declare function aeadChaCha20Poly1305Encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
): [Uint8Array, Uint8Array];
/**
 * Encrypt data using ChaCha20-Poly1305 AEAD cipher with additional authenticated data.
 *
 * **Security Warning**: The nonce MUST be unique for every encryption operation
 * with the same key. Reusing a nonce completely breaks the security of the
 * encryption scheme and can reveal plaintext.
 *
 * @param plaintext - The data to encrypt
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce (MUST be unique per encryption with the same key)
 * @param aad - Additional authenticated data (not encrypted, but integrity-protected)
 * @returns Tuple of [ciphertext, authTag] where authTag is 16 bytes
 * @throws {CryptoError} If key is not 32 bytes or nonce is not 12 bytes
 */
declare function aeadChaCha20Poly1305EncryptWithAad(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): [Uint8Array, Uint8Array];
/**
 * Decrypt data using ChaCha20-Poly1305 AEAD cipher.
 *
 * @param ciphertext - The encrypted data
 * @param key - 32-byte encryption key (must match key used for encryption)
 * @param nonce - 12-byte nonce (must match nonce used for encryption)
 * @param authTag - 16-byte authentication tag from encryption
 * @returns Decrypted plaintext
 * @throws {CryptoError} If key/nonce/authTag sizes are invalid
 * @throws {CryptoError} If authentication fails (tampered data or wrong key/nonce)
 */
declare function aeadChaCha20Poly1305Decrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  authTag: Uint8Array,
): Uint8Array;
/**
 * Decrypt data using ChaCha20-Poly1305 AEAD cipher with additional authenticated data.
 *
 * @param ciphertext - The encrypted data
 * @param key - 32-byte encryption key (must match key used for encryption)
 * @param nonce - 12-byte nonce (must match nonce used for encryption)
 * @param aad - Additional authenticated data (must exactly match AAD used for encryption)
 * @param authTag - 16-byte authentication tag from encryption
 * @returns Decrypted plaintext
 * @throws {CryptoError} If key/nonce/authTag sizes are invalid
 * @throws {CryptoError} If authentication fails (tampered data, wrong key/nonce, or AAD mismatch)
 */
declare function aeadChaCha20Poly1305DecryptWithAad(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  authTag: Uint8Array,
): Uint8Array;
//#endregion
//#region src/public-key-encryption.d.ts
declare const X25519_PRIVATE_KEY_SIZE = 32;
declare const X25519_PUBLIC_KEY_SIZE = 32;
/**
 * Derive an X25519 agreement private key from key material.
 * Uses HKDF with "agreement" as domain separation salt.
 */
declare function deriveAgreementPrivateKey(keyMaterial: Uint8Array): Uint8Array;
/**
 * Derive a signing private key from key material.
 * Uses HKDF with "signing" as domain separation salt.
 */
declare function deriveSigningPrivateKey(keyMaterial: Uint8Array): Uint8Array;
/**
 * Generate a new random X25519 private key.
 */
declare function x25519NewPrivateKeyUsing(rng: RandomNumberGenerator): Uint8Array;
/**
 * Derive an X25519 public key from a private key.
 */
declare function x25519PublicKeyFromPrivateKey(privateKey: Uint8Array): Uint8Array;
/**
 * Compute a shared symmetric key using X25519 key agreement (ECDH).
 *
 * This function performs X25519 Diffie-Hellman key agreement and then
 * derives a symmetric key using HKDF-SHA256 with "agreement" as the salt.
 * This matches the Rust bc-crypto implementation for cross-platform compatibility.
 *
 * **Low-order public key handling.** The underlying `@noble/curves` X25519
 * implementation rejects low-order public keys (where the u-coordinate is
 * `0`) by throwing `'invalid private or public key received'`. Rust's
 * `x25519-dalek` (v2.0-rc.2) instead silently produces the all-zero shared
 * secret. This means an adversarial low-order public key fed in via TS
 * surfaces as an exception, while in Rust it would yield an HKDF-derived
 * key from a zero shared secret. For honest inputs both implementations
 * produce byte-identical results; the TS port's stricter behaviour is a
 * security improvement, not a parity bug.
 *
 * @param x25519Private - 32-byte X25519 private key
 * @param x25519Public - 32-byte X25519 public key from the other party
 * @returns 32-byte derived symmetric key
 * @throws {Error} If private key is not 32 bytes or public key is not 32 bytes
 * @throws {Error} If the public key is low-order (`@noble/curves`-specific guard)
 */
declare function x25519SharedKey(x25519Private: Uint8Array, x25519Public: Uint8Array): Uint8Array;
//#endregion
//#region src/ecdsa-keys.d.ts
declare const ECDSA_PRIVATE_KEY_SIZE = 32;
declare const ECDSA_PUBLIC_KEY_SIZE = 33;
declare const ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
declare const ECDSA_MESSAGE_HASH_SIZE = 32;
declare const ECDSA_SIGNATURE_SIZE = 64;
declare const SCHNORR_PUBLIC_KEY_SIZE = 32;
/**
 * Generate a new random ECDSA private key using secp256k1.
 *
 * Note: Unlike some implementations, this directly returns the random bytes
 * without validation. The secp256k1 library will handle any edge cases when
 * the key is used.
 */
declare function ecdsaNewPrivateKeyUsing(rng: RandomNumberGenerator): Uint8Array;
/**
 * Derive a compressed ECDSA public key from a private key.
 */
declare function ecdsaPublicKeyFromPrivateKey(privateKey: Uint8Array): Uint8Array;
/**
 * Decompress a compressed public key to uncompressed format.
 */
declare function ecdsaDecompressPublicKey(compressed: Uint8Array): Uint8Array;
/**
 * Compress an uncompressed public key.
 */
declare function ecdsaCompressPublicKey(uncompressed: Uint8Array): Uint8Array;
/**
 * Derive an ECDSA private key from key material using HKDF.
 *
 * Note: This directly returns the HKDF output without validation,
 * matching the Rust reference implementation behavior.
 */
declare function ecdsaDerivePrivateKey(keyMaterial: Uint8Array): Uint8Array;
/**
 * Extract the x-only (Schnorr) public key from a private key.
 * This is used for BIP-340 Schnorr signatures.
 */
declare function schnorrPublicKeyFromPrivateKey(privateKey: Uint8Array): Uint8Array;
//#endregion
//#region src/ecdsa-signing.d.ts
/**
 * Sign a message using ECDSA with secp256k1.
 *
 * The message is hashed with double SHA-256 before signing (Bitcoin standard).
 *
 * **Security Note**: The private key must be kept secret. ECDSA requires
 * cryptographically secure random nonces internally; this is handled by
 * the underlying library using RFC 6979 deterministic nonces.
 *
 * @param privateKey - 32-byte secp256k1 private key
 * @param message - Message to sign (any length, will be double-SHA256 hashed)
 * @returns 64-byte compact signature (r || s format)
 * @throws {Error} If private key is not 32 bytes
 */
declare function ecdsaSign(privateKey: Uint8Array, message: Uint8Array): Uint8Array;
/**
 * Verify an ECDSA signature with secp256k1.
 *
 * The message is hashed with double SHA-256 before verification (Bitcoin standard).
 *
 * @param publicKey - 33-byte compressed secp256k1 public key
 * @param signature - 64-byte compact signature (r || s format)
 * @param message - Original message that was signed
 * @returns `true` if signature is valid, `false` if signature verification fails
 * @throws {Error} If public key is not 33 bytes or signature is not 64 bytes
 */
declare function ecdsaVerify(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): boolean;
//#endregion
//#region src/schnorr-signing.d.ts
declare const SCHNORR_SIGNATURE_SIZE = 64;
/**
 * Sign a message using Schnorr signature (BIP-340).
 * Uses secure random auxiliary randomness.
 *
 * @param ecdsaPrivateKey - 32-byte private key
 * @param message - Message to sign (not pre-hashed, per BIP-340)
 * @returns 64-byte Schnorr signature
 */
declare function schnorrSign(ecdsaPrivateKey: Uint8Array, message: Uint8Array): Uint8Array;
/**
 * Sign a message using Schnorr signature with a custom RNG.
 *
 * @param ecdsaPrivateKey - 32-byte private key
 * @param message - Message to sign
 * @param rng - Random number generator for auxiliary randomness
 * @returns 64-byte Schnorr signature
 */
declare function schnorrSignUsing(
  ecdsaPrivateKey: Uint8Array,
  message: Uint8Array,
  rng: RandomNumberGenerator,
): Uint8Array;
/**
 * Sign a message using Schnorr signature with specific auxiliary randomness.
 * This is useful for deterministic signing in tests.
 *
 * @param ecdsaPrivateKey - 32-byte private key
 * @param message - Message to sign
 * @param auxRand - 32-byte auxiliary randomness (per BIP-340)
 * @returns 64-byte Schnorr signature
 */
declare function schnorrSignWithAuxRand(
  ecdsaPrivateKey: Uint8Array,
  message: Uint8Array,
  auxRand: Uint8Array,
): Uint8Array;
/**
 * Verify a Schnorr signature (BIP-340).
 *
 * @param schnorrPublicKey - 32-byte x-only public key
 * @param signature - 64-byte Schnorr signature
 * @param message - Original message
 * @returns true if signature is valid
 */
declare function schnorrVerify(
  schnorrPublicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): boolean;
//#endregion
//#region src/ed25519-signing.d.ts
declare const ED25519_PUBLIC_KEY_SIZE = 32;
declare const ED25519_PRIVATE_KEY_SIZE = 32;
declare const ED25519_SIGNATURE_SIZE = 64;
/**
 * Generate a new random Ed25519 private key.
 */
declare function ed25519NewPrivateKeyUsing(rng: RandomNumberGenerator): Uint8Array;
/**
 * Derive an Ed25519 public key from a private key.
 */
declare function ed25519PublicKeyFromPrivateKey(privateKey: Uint8Array): Uint8Array;
/**
 * Sign a message using Ed25519.
 *
 * **Security Note**: The private key must be kept secret. The same private key
 * can safely sign multiple messages.
 *
 * @param privateKey - 32-byte Ed25519 private key
 * @param message - Message to sign (any length)
 * @returns 64-byte Ed25519 signature
 * @throws {Error} If private key is not 32 bytes
 */
declare function ed25519Sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array;
/**
 * Verify an Ed25519 signature.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @param message - Original message that was signed
 * @param signature - 64-byte Ed25519 signature
 * @returns `true` if signature is valid, `false` if signature verification fails
 * @throws {Error} If public key is not 32 bytes or signature is not 64 bytes
 */
declare function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean;
//#endregion
//#region src/scrypt.d.ts
/**
 * Derive a key using Scrypt with recommended parameters.
 *
 * Mirrors Rust `bc_crypto::scrypt` which calls `scrypt::Params::recommended()`.
 * The recommended parameters per the upstream `scrypt` crate are
 * `log_n = 17` (N = 2^17 = 131072), `r = 8`, `p = 1`.
 *
 * @param password - Password or passphrase
 * @param salt - Salt value
 * @param outputLen - Desired output length
 * @returns Derived key
 */
declare function scrypt(password: Uint8Array, salt: Uint8Array, outputLen: number): Uint8Array;
/**
 * Derive a key using Scrypt with custom parameters.
 *
 * @param password - Password or passphrase
 * @param salt - Salt value
 * @param outputLen - Desired output length
 * @param logN - Log2 of the CPU/memory cost parameter N (must be <64)
 * @param r - Block size parameter (must be >0)
 * @param p - Parallelization parameter (must be >0)
 * @returns Derived key
 */
declare function scryptOpt(
  password: Uint8Array,
  salt: Uint8Array,
  outputLen: number,
  logN: number,
  r: number,
  p: number,
): Uint8Array;
//#endregion
//#region src/argon.d.ts
/**
 * Derive a key using Argon2id with default parameters.
 *
 * Mirrors Rust `bc_crypto::argon2id` which calls `Argon2::default()`. The
 * upstream `argon2` crate's defaults are `t = 2` iterations, `m = 19 * 1024
 * = 19456` KiB of memory, `p = 1` lane (per `argon2-0.5.x/src/params.rs`).
 *
 * @param password - Password or passphrase
 * @param salt - Salt value (must be at least 8 bytes)
 * @param outputLen - Desired output length
 * @returns Derived key
 */
declare function argon2id(password: Uint8Array, salt: Uint8Array, outputLen: number): Uint8Array;
//#endregion
export {
  AeadError,
  CRC32_SIZE,
  CryptoError,
  type CryptoResult,
  ECDSA_MESSAGE_HASH_SIZE,
  ECDSA_PRIVATE_KEY_SIZE,
  ECDSA_PUBLIC_KEY_SIZE,
  ECDSA_SIGNATURE_SIZE,
  ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
  type NumericTypedArray,
  SCHNORR_PUBLIC_KEY_SIZE,
  SCHNORR_SIGNATURE_SIZE,
  SHA256_SIZE,
  SHA512_SIZE,
  SYMMETRIC_AUTH_SIZE,
  SYMMETRIC_KEY_SIZE,
  SYMMETRIC_NONCE_SIZE,
  X25519_PRIVATE_KEY_SIZE,
  X25519_PUBLIC_KEY_SIZE,
  aeadChaCha20Poly1305Decrypt,
  aeadChaCha20Poly1305DecryptWithAad,
  aeadChaCha20Poly1305Encrypt,
  aeadChaCha20Poly1305EncryptWithAad,
  argon2id,
  deriveAgreementPrivateKey,
  deriveSigningPrivateKey,
  doubleSha256,
  ecdsaCompressPublicKey,
  ecdsaDecompressPublicKey,
  ecdsaDerivePrivateKey,
  ecdsaNewPrivateKeyUsing,
  ecdsaPublicKeyFromPrivateKey,
  ecdsaSign,
  ecdsaVerify,
  ed25519NewPrivateKeyUsing,
  ed25519PublicKeyFromPrivateKey,
  ed25519Sign,
  ed25519Verify,
  hash_d_exports as hash,
  hkdfHmacSha256,
  hmacSha256,
  hmacSha512,
  memzero,
  memzeroVecVecU8,
  pbkdf2HmacSha256,
  schnorrPublicKeyFromPrivateKey,
  schnorrSign,
  schnorrSignUsing,
  schnorrSignWithAuxRand,
  schnorrVerify,
  scrypt,
  scryptOpt,
  sha256,
  sha512,
  x25519NewPrivateKeyUsing,
  x25519PublicKeyFromPrivateKey,
  x25519SharedKey,
};
//# sourceMappingURL=index.d.mts.map
