/**
 * X25519 key agreement and the HKDF key derivations built on it.
 *
 * @module x25519
 */
import { x25519 as noble } from "@noble/curves/ed25519.js";
import { type RngOptions, randomBytes, secureRng } from "@blockchaincommons/rand";
import { hkdfSha256 } from "./hash.js";
import { CryptoError, requireBytes, requireLength, requireOptions } from "./error.js";
import { guard } from "./domain.js";

const X25519_PRIVATE_KEY_SIZE = 32;
const X25519_PUBLIC_KEY_SIZE = 32;

// The HKDF salts are wire: every derived key in the stack depends on them.
const textEncoder = new TextEncoder();
const AGREEMENT_SALT = textEncoder.encode("agreement");
const SIGNING_SALT = textEncoder.encode("signing");

/**
 * The stack's signing-key derivation: HKDF-SHA-256(keyMaterial, salt "signing")
 * → 32 bytes, used for ECDSA, Schnorr and Ed25519 private keys alike
 * (the reference's `derive_signing_private_key` ≡ `ecdsa_derive_private_key`).
 * @throws {CryptoError} `InvalidParameter` unless `keyMaterial` is a `Uint8Array`.
 */
export function deriveSigningPrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer> {
  requireBytes("signing key material", keyMaterial);
  return hkdfSha256(keyMaterial, SIGNING_SALT, { dkLen: 32 });
}

/**
 * The stack's agreement-key derivation: HKDF-SHA-256(keyMaterial, salt
 * "agreement") → 32 bytes, an X25519 private key.
 * @throws {CryptoError} `InvalidParameter` unless `keyMaterial` is a `Uint8Array`.
 */
export function deriveAgreementPrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer> {
  requireBytes("agreement key material", keyMaterial);
  return hkdfSha256(keyMaterial, AGREEMENT_SALT, { dkLen: X25519_PRIVATE_KEY_SIZE });
}

/** The shape of the {@link x25519} family. */
export interface X25519 {
  /** Private key length in bytes. */
  readonly PRIVATE_KEY_SIZE: 32;
  /** Public key length in bytes. */
  readonly PUBLIC_KEY_SIZE: 32;
  /**
   * 32 random bytes from `options.rng` (default secure), unvalidated; the
   * reference's `x25519_new_private_key_using` (`random_data`). A generator's
   * own error, including rand's `InvalidGenerator`, propagates unwrapped.
   * @throws {CryptoError} `InvalidParameter` unless `options` is an object or absent.
   */
  generatePrivateKey(options?: RngOptions): Uint8Array<ArrayBuffer>;
  /**
   * The X25519 public key of `privateKey` (clamped per RFC 7748).
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong-length key.
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * X25519 Diffie-Hellman, then HKDF-SHA-256 with salt "agreement" → 32 bytes
   * (the reference's `try_x25519_shared_key`).
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`;
   * `InvalidSize` on a wrong length; `NonContributoryKey` when `publicKey`
   * is a low-order point, i.e. the shared secret would be all zero, as the
   * reference's `try_x25519_shared_key` returns `Err(Error::NonContributoryKey)`
   * (its `x25519_shared_key` wrapper panics on the same input).
   */
  sharedKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array<ArrayBuffer>;
}

/** X25519 key agreement: key generation, public keys and the salted shared key. */
export const x25519: X25519 = {
  PRIVATE_KEY_SIZE: 32,
  PUBLIC_KEY_SIZE: 32,

  generatePrivateKey(options) {
    requireOptions("X25519 options", options, true);
    return randomBytes(X25519_PRIVATE_KEY_SIZE, { rng: options?.rng ?? secureRng() });
  },

  publicKey(privateKey) {
    requireLength("X25519 private key", privateKey, X25519_PRIVATE_KEY_SIZE);
    return noble.getPublicKey(privateKey);
  },

  sharedKey(privateKey, publicKey) {
    requireLength("X25519 private key", privateKey, X25519_PRIVATE_KEY_SIZE);
    requireLength("X25519 public key", publicKey, X25519_PUBLIC_KEY_SIZE);
    // Both arguments are 32 bytes here and every 32-byte private key is
    // clamped and valid, so noble's only failure is its low-order set, which
    // equals dalek's `!was_contributory()`: the reference's `NonContributoryKey`.
    const secret = guard(
      () => noble.getSharedSecret(privateKey, publicKey),
      (cause) => CryptoError.nonContributoryKey(cause),
    );
    return hkdfSha256(secret, AGREEMENT_SALT, { dkLen: 32 });
  },
};
