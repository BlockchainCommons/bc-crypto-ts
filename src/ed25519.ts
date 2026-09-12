/**
 * Ed25519 signatures.
 *
 * @module ed25519
 */
import { ed25519 as noble } from "@noble/curves/ed25519.js";
import { type RandomNumberGenerator, type RngOptions, secureRng } from "@blockchaincommons/rand";
import { requireLength } from "./error.js";

const ED25519_PUBLIC_KEY_SIZE = 32;
const ED25519_PRIVATE_KEY_SIZE = 32;
const ED25519_SIGNATURE_SIZE = 64;

/** The shape of the {@link ed25519} family. */
export interface Ed25519 {
  /** Private key (seed) length in bytes. */
  readonly PRIVATE_KEY_SIZE: 32;
  /** Public key length in bytes. */
  readonly PUBLIC_KEY_SIZE: 32;
  /** Signature length in bytes. */
  readonly SIGNATURE_SIZE: 64;
  /** 32 random bytes from `options.rng` (default secure). */
  generatePrivateKey(options?: RngOptions): Uint8Array<ArrayBuffer>;
  /**
   * The public key of the 32-byte seed `privateKey` (RFC 8032).
   * @throws {CryptoError} `InvalidSize` on a wrong-length key.
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * Deterministic RFC 8032 signature (64 bytes).
   * @throws {CryptoError} `InvalidSize` on a wrong-length key.
   */
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * `(publicKey, signature, message)`, the same order as `ecdsa.verify` and `schnorr.verify`.
   *
   * Strict (the reference's `verify_strict`): only canonical point
   * encodings are accepted, and a small-order public key or `R` never
   * verifies. `false` on any invalid or malformed input of the right length.
   * @throws {CryptoError} `InvalidSize` on a wrong-length key or signature.
   */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}

/** Ed25519 (RFC 8032) signatures with strict verification. */
export const ed25519: Ed25519 = {
  PRIVATE_KEY_SIZE: 32,
  PUBLIC_KEY_SIZE: 32,
  SIGNATURE_SIZE: 64,

  generatePrivateKey(options) {
    // The reference's `ed25519_new_private_key_using` reaches the generator
    // through rand_core generics (`SigningKey::generate` → `fill_bytes`): the
    // packed stream where a generator distinguishes one, else the same bytes
    // as `randomBytes`.
    const rng: RandomNumberGenerator = options?.rng ?? secureRng();
    const key = new Uint8Array(ED25519_PRIVATE_KEY_SIZE);
    if (rng.fillBytesPacked !== undefined) rng.fillBytesPacked(key);
    else rng.fillBytes(key);
    return key;
  },

  publicKey(privateKey) {
    requireLength("Ed25519 private key", privateKey, ED25519_PRIVATE_KEY_SIZE);
    return noble.getPublicKey(privateKey);
  },

  sign(privateKey, message) {
    requireLength("Ed25519 private key", privateKey, ED25519_PRIVATE_KEY_SIZE);
    return noble.sign(message, privateKey);
  },

  verify(publicKey, signature, message) {
    requireLength("Ed25519 public key", publicKey, ED25519_PUBLIC_KEY_SIZE);
    requireLength("Ed25519 signature", signature, ED25519_SIGNATURE_SIZE);
    try {
      // Canonical decoding (zip215 = false) of the key and of R, then the
      // small-order checks `verify_strict` makes, then the equation.
      const a = noble.Point.fromBytes(publicKey, false);
      const r = noble.Point.fromBytes(signature.subarray(0, 32), false);
      if (a.isSmallOrder() || r.isSmallOrder()) return false;
      return noble.verify(signature, message, publicKey, { zip215: false });
    } catch {
      return false;
    }
  },
};
