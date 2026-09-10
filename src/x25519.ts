/**
 * X25519 key agreement and the HKDF key derivations built on it.
 *
 * @module x25519
 */
import { x25519 as noble } from "@noble/curves/ed25519.js";
import { type RandomNumberGenerator, randomBytes, secureRng } from "@blockchaincommons/rand";
import { hkdfSha256 } from "./hash.js";
import { requireLength } from "./error.js";

export const X25519_PRIVATE_KEY_SIZE = 32;
export const X25519_PUBLIC_KEY_SIZE = 32;

/** Options for the key generators. */
export interface KeygenOptions {
  /** Generator to draw the key from. Default: secure. */
  readonly rng?: RandomNumberGenerator | undefined;
}

// The HKDF salts are wire: every derived key in the stack depends on them.
const textEncoder = new TextEncoder();
const AGREEMENT_SALT = textEncoder.encode("agreement");
const SIGNING_SALT = textEncoder.encode("signing");

/** HKDF-SHA-256(keyMaterial, salt "signing") → 32 bytes. */
export function deriveSigningPrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer> {
  return hkdfSha256(keyMaterial, SIGNING_SALT, 32);
}

/** The {@link x25519} family. */
export interface X25519 {
  readonly PRIVATE_KEY_SIZE: 32;
  readonly PUBLIC_KEY_SIZE: 32;
  /** 32 random bytes from `options.rng` (default secure), unvalidated. */
  generatePrivateKey(options?: KeygenOptions): Uint8Array<ArrayBuffer>;
  /** HKDF-SHA-256(keyMaterial, salt "agreement") → 32 bytes. */
  deriveAgreementPrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer>;
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /** X25519 Diffie-Hellman, then HKDF-SHA-256 with salt "agreement" → 32 bytes. */
  sharedKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array<ArrayBuffer>;
}

export const x25519: X25519 = {
  PRIVATE_KEY_SIZE: 32,
  PUBLIC_KEY_SIZE: 32,

  generatePrivateKey(options) {
    return randomBytes(X25519_PRIVATE_KEY_SIZE, { rng: options?.rng ?? secureRng() });
  },

  deriveAgreementPrivateKey(keyMaterial) {
    return hkdfSha256(keyMaterial, AGREEMENT_SALT, X25519_PRIVATE_KEY_SIZE);
  },

  publicKey(privateKey) {
    requireLength("X25519 private key", privateKey, X25519_PRIVATE_KEY_SIZE);
    return noble.getPublicKey(privateKey);
  },

  sharedKey(privateKey, publicKey) {
    requireLength("X25519 private key", privateKey, X25519_PRIVATE_KEY_SIZE);
    requireLength("X25519 public key", publicKey, X25519_PUBLIC_KEY_SIZE);
    return hkdfSha256(noble.getSharedSecret(privateKey, publicKey), AGREEMENT_SALT, 32);
  },
};
