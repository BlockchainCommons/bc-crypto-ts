/**
 * Ed25519 signatures.
 *
 * @module ed25519
 */
import { ed25519 as noble } from "@noble/curves/ed25519.js";
import { randomBytes, secureRng } from "@blockchaincommons/rand";
import { requireLength } from "./error.js";
import type { KeygenOptions } from "./x25519.js";

export const ED25519_PUBLIC_KEY_SIZE = 32;
export const ED25519_PRIVATE_KEY_SIZE = 32;
export const ED25519_SIGNATURE_SIZE = 64;

/** The {@link ed25519} family. */
export interface Ed25519 {
  readonly PRIVATE_KEY_SIZE: 32;
  readonly PUBLIC_KEY_SIZE: 32;
  readonly SIGNATURE_SIZE: 64;
  /** 32 random bytes from `options.rng` (default secure). */
  generatePrivateKey(options?: KeygenOptions): Uint8Array<ArrayBuffer>;
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
  /** `(publicKey, signature, message)`, the same order as `ecdsa.verify` and `schnorr.verify`. */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}

export const ed25519: Ed25519 = {
  PRIVATE_KEY_SIZE: 32,
  PUBLIC_KEY_SIZE: 32,
  SIGNATURE_SIZE: 64,

  generatePrivateKey(options) {
    return randomBytes(ED25519_PRIVATE_KEY_SIZE, { rng: options?.rng ?? secureRng() });
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
      return noble.verify(signature, message, publicKey);
    } catch {
      return false;
    }
  },
};
