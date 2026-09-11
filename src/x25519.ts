/**
 * X25519 key agreement and the HKDF key derivations built on it.
 *
 * @module x25519
 */
import { x25519 as noble } from "@noble/curves/ed25519.js";
import { type RngOptions, randomBytes, secureRng } from "@blockchaincommons/rand";
import { hkdfSha256 } from "./hash.js";
import { CryptoError, requireLength } from "./error.js";
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
 */
export function deriveSigningPrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer> {
  return hkdfSha256(keyMaterial, SIGNING_SALT, { dkLen: 32 });
}

/**
 * The stack's agreement-key derivation: HKDF-SHA-256(keyMaterial, salt
 * "agreement") → 32 bytes, an X25519 private key.
 */
export function deriveAgreementPrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer> {
  return hkdfSha256(keyMaterial, AGREEMENT_SALT, { dkLen: X25519_PRIVATE_KEY_SIZE });
}

/** The shape of the {@link x25519} family. */
export interface X25519 {
  /** Private key length in bytes. */
  readonly PRIVATE_KEY_SIZE: 32;
  /** Public key length in bytes. */
  readonly PUBLIC_KEY_SIZE: 32;
  /** 32 random bytes from `options.rng` (default secure), unvalidated. */
  generatePrivateKey(options?: RngOptions): Uint8Array<ArrayBuffer>;
  /**
   * The X25519 public key of `privateKey` (clamped per RFC 7748).
   * @throws {CryptoError} `InvalidSize` on a wrong-length key.
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * X25519 Diffie-Hellman, then HKDF-SHA-256 with salt "agreement" → 32 bytes.
   * @throws {CryptoError} `InvalidData` when `publicKey` is a low-order point
   * (the reference derives a predictable key instead; divergence D2).
   */
  sharedKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array<ArrayBuffer>;
}

/** X25519 key agreement: key generation, public keys and the salted shared key. */
export const x25519: X25519 = {
  PRIVATE_KEY_SIZE: 32,
  PUBLIC_KEY_SIZE: 32,

  generatePrivateKey(options) {
    return randomBytes(X25519_PRIVATE_KEY_SIZE, { rng: options?.rng ?? secureRng() });
  },

  publicKey(privateKey) {
    requireLength("X25519 private key", privateKey, X25519_PRIVATE_KEY_SIZE);
    return noble.getPublicKey(privateKey);
  },

  sharedKey(privateKey, publicKey) {
    requireLength("X25519 private key", privateKey, X25519_PRIVATE_KEY_SIZE);
    requireLength("X25519 public key", publicKey, X25519_PUBLIC_KEY_SIZE);
    const secret = guard(
      () => noble.getSharedSecret(privateKey, publicKey),
      (cause) => CryptoError.invalidData("X25519 public key", "low-order point", cause),
    );
    return hkdfSha256(secret, AGREEMENT_SALT, { dkLen: 32 });
  },
};
