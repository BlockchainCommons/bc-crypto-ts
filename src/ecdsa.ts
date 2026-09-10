/**
 * secp256k1: ECDSA keys and signatures, and BIP-340 Schnorr.
 *
 * @module ecdsa
 */
import { secp256k1, schnorr as nobleSchnorr } from "@noble/curves/secp256k1.js";
import { type RandomNumberGenerator, randomBytes, secureRng } from "@blockchaincommons/rand";
import { doubleSha256, hkdfSha256 } from "./hash.js";
import { CryptoError, requireLength } from "./error.js";
import type { KeygenOptions } from "./x25519.js";

export const ECDSA_PRIVATE_KEY_SIZE = 32;
export const ECDSA_PUBLIC_KEY_SIZE = 33;
export const ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
export const ECDSA_MESSAGE_HASH_SIZE = 32;
export const ECDSA_SIGNATURE_SIZE = 64;
export const SCHNORR_PUBLIC_KEY_SIZE = 32;
export const SCHNORR_SIGNATURE_SIZE = 64;

const SIGNING_SALT = new TextEncoder().encode("signing");

/** The {@link ecdsa} family. */
export interface Ecdsa {
  readonly PRIVATE_KEY_SIZE: 32;
  readonly PUBLIC_KEY_SIZE: 33;
  readonly UNCOMPRESSED_PUBLIC_KEY_SIZE: 65;
  readonly MESSAGE_HASH_SIZE: 32;
  readonly SIGNATURE_SIZE: 64;
  /** 32 random bytes from `options.rng` (default secure), unvalidated. */
  generatePrivateKey(options?: KeygenOptions): Uint8Array<ArrayBuffer>;
  /** HKDF-SHA-256(keyMaterial, salt "signing") → 32 bytes, unvalidated. */
  derivePrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer>;
  /** Compressed (33-byte) public key. */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  decompressPublicKey(compressed: Uint8Array): Uint8Array<ArrayBuffer>;
  compressPublicKey(uncompressed: Uint8Array): Uint8Array<ArrayBuffer>;
  /** Deterministic (RFC 6979) signature over `doubleSha256(message)`; 64-byte compact form. */
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
  /** `false` on an invalid signature; throws only on wrong-length inputs. */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}

export const ecdsa: Ecdsa = {
  PRIVATE_KEY_SIZE: 32,
  PUBLIC_KEY_SIZE: 33,
  UNCOMPRESSED_PUBLIC_KEY_SIZE: 65,
  MESSAGE_HASH_SIZE: 32,
  SIGNATURE_SIZE: 64,

  generatePrivateKey(options) {
    return randomBytes(ECDSA_PRIVATE_KEY_SIZE, { rng: options?.rng ?? secureRng() });
  },

  derivePrivateKey(keyMaterial) {
    return hkdfSha256(keyMaterial, SIGNING_SALT, ECDSA_PRIVATE_KEY_SIZE);
  },

  publicKey(privateKey) {
    requireLength("ECDSA private key", privateKey, ECDSA_PRIVATE_KEY_SIZE);
    return secp256k1.getPublicKey(privateKey, true);
  },

  decompressPublicKey(compressed) {
    requireLength("compressed public key", compressed, ECDSA_PUBLIC_KEY_SIZE);
    return secp256k1.Point.fromBytes(compressed).toBytes(false);
  },

  compressPublicKey(uncompressed) {
    requireLength("uncompressed public key", uncompressed, ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE);
    return secp256k1.Point.fromBytes(uncompressed).toBytes(true);
  },

  sign(privateKey, message) {
    requireLength("ECDSA private key", privateKey, ECDSA_PRIVATE_KEY_SIZE);
    return secp256k1.sign(doubleSha256(message), privateKey, {
      prehash: false,
    });
  },

  verify(publicKey, signature, message) {
    requireLength("ECDSA public key", publicKey, ECDSA_PUBLIC_KEY_SIZE);
    requireLength("ECDSA signature", signature, ECDSA_SIGNATURE_SIZE);
    try {
      return secp256k1.verify(signature, doubleSha256(message), publicKey, { prehash: false });
    } catch {
      return false;
    }
  },
};

/** Options for `schnorr.sign`: explicit aux-rand bytes, or a generator to draw them from. */
export interface SchnorrSignOptions {
  /** 32 bytes of auxiliary randomness (BIP-340). Takes precedence over `rng`. */
  readonly auxRand?: Uint8Array | undefined;
  /** Generator to draw 32 aux-rand bytes from. Default: secure. */
  readonly rng?: RandomNumberGenerator | undefined;
}

/** The {@link schnorr} family. */
export interface Schnorr {
  readonly PUBLIC_KEY_SIZE: 32;
  readonly SIGNATURE_SIZE: 64;
  /** x-only (32-byte) public key of a secp256k1 private key. */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /** BIP-340 signature. Aux-rand comes from `options.auxRand`, else 32 bytes drawn from `options.rng`. */
  sign(
    privateKey: Uint8Array,
    message: Uint8Array,
    options?: SchnorrSignOptions,
  ): Uint8Array<ArrayBuffer>;
  /** `false` on an invalid signature; throws only on wrong-length inputs. */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}

export const schnorr: Schnorr = {
  PUBLIC_KEY_SIZE: 32,
  SIGNATURE_SIZE: 64,

  publicKey(privateKey) {
    requireLength("ECDSA private key", privateKey, ECDSA_PRIVATE_KEY_SIZE);
    return secp256k1.getPublicKey(privateKey, false).slice(1, 33);
  },

  sign(privateKey, message, options) {
    requireLength("ECDSA private key", privateKey, ECDSA_PRIVATE_KEY_SIZE);
    const auxRand = options?.auxRand ?? randomBytes(32, { rng: options?.rng ?? secureRng() });
    if (auxRand.length !== 32)
      throw CryptoError.invalidSize("auxiliary randomness", 32, auxRand.length);
    return nobleSchnorr.sign(message, privateKey, auxRand);
  },

  verify(publicKey, signature, message) {
    requireLength("Schnorr public key", publicKey, SCHNORR_PUBLIC_KEY_SIZE);
    requireLength("Schnorr signature", signature, SCHNORR_SIGNATURE_SIZE);
    try {
      return nobleSchnorr.verify(signature, message, publicKey);
    } catch {
      return false;
    }
  },
};
