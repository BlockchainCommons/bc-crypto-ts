/**
 * secp256k1: ECDSA keys and signatures, and BIP-340 Schnorr.
 *
 * @module ecdsa
 */
import { secp256k1, schnorr as nobleSchnorr } from "@noble/curves/secp256k1.js";
import {
  type RandomNumberGenerator,
  type RngOptions,
  randomBytes,
  secureRng,
} from "@blockchaincommons/rand";
import { doubleSha256 } from "./hash.js";
import { CryptoError, requireLength } from "./error.js";
import { guard } from "./domain.js";

const ECDSA_PRIVATE_KEY_SIZE = 32;
const ECDSA_PUBLIC_KEY_SIZE = 33;
const ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
const ECDSA_SIGNATURE_SIZE = 64;
const SCHNORR_PUBLIC_KEY_SIZE = 32;
const SCHNORR_SIGNATURE_SIZE = 64;

const invalidScalar =
  (what: string) =>
  (cause: unknown): CryptoError =>
    CryptoError.invalidData(what, `${what} is not a valid scalar (must be in [1, n - 1])`, cause);
const invalidPoint =
  (what: string) =>
  (cause: unknown): CryptoError =>
    CryptoError.invalidData(what, `${what} is not a point on the curve`, cause);

/** The shape of the {@link ecdsa} family. */
export interface Ecdsa {
  /** Private key (scalar) length in bytes. */
  readonly PRIVATE_KEY_SIZE: 32;
  /** Compressed public key length in bytes. */
  readonly PUBLIC_KEY_SIZE: 33;
  /** Uncompressed (`04 ‖ x ‖ y`) public key length in bytes. */
  readonly UNCOMPRESSED_PUBLIC_KEY_SIZE: 65;
  /** Length of the message hash that is signed (double SHA-256). */
  readonly MESSAGE_HASH_SIZE: 32;
  /** Compact (`r ‖ s`) signature length in bytes. */
  readonly SIGNATURE_SIZE: 64;
  /** 32 random bytes from `options.rng` (default secure), unvalidated. */
  generatePrivateKey(options?: RngOptions): Uint8Array<ArrayBuffer>;
  /**
   * Compressed (33-byte) public key.
   * @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar (0 or ≥ n).
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /** @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the bytes are not a point on the curve. */
  decompressPublicKey(compressed: Uint8Array): Uint8Array<ArrayBuffer>;
  /** @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the bytes are not a point on the curve. */
  compressPublicKey(uncompressed: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * Deterministic (RFC 6979) signature over `doubleSha256(message)`; 64-byte compact form.
   * @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar.
   */
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
  /** `false` on an invalid signature; throws only on wrong-length inputs. */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}

/** secp256k1 ECDSA: keys, point compression, and RFC 6979 signatures over double SHA-256. */
export const ecdsa: Ecdsa = {
  PRIVATE_KEY_SIZE: 32,
  PUBLIC_KEY_SIZE: 33,
  UNCOMPRESSED_PUBLIC_KEY_SIZE: 65,
  MESSAGE_HASH_SIZE: 32,
  SIGNATURE_SIZE: 64,

  generatePrivateKey(options) {
    return randomBytes(ECDSA_PRIVATE_KEY_SIZE, { rng: options?.rng ?? secureRng() });
  },

  publicKey(privateKey) {
    requireLength("ECDSA private key", privateKey, ECDSA_PRIVATE_KEY_SIZE);
    return guard(
      () => secp256k1.getPublicKey(privateKey, true),
      invalidScalar("ECDSA private key"),
    );
  },

  decompressPublicKey(compressed) {
    requireLength("ECDSA compressed public key", compressed, ECDSA_PUBLIC_KEY_SIZE);
    return guard(
      () => secp256k1.Point.fromBytes(compressed).toBytes(false),
      invalidPoint("ECDSA compressed public key"),
    );
  },

  compressPublicKey(uncompressed) {
    requireLength(
      "ECDSA uncompressed public key",
      uncompressed,
      ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE,
    );
    return guard(
      () => secp256k1.Point.fromBytes(uncompressed).toBytes(true),
      invalidPoint("ECDSA uncompressed public key"),
    );
  },

  sign(privateKey, message) {
    requireLength("ECDSA private key", privateKey, ECDSA_PRIVATE_KEY_SIZE);
    return guard(
      () => secp256k1.sign(doubleSha256(message), privateKey, { prehash: false }),
      invalidScalar("ECDSA private key"),
    );
  },

  verify(publicKey, signature, message) {
    requireLength("ECDSA public key", publicKey, ECDSA_PUBLIC_KEY_SIZE);
    requireLength("ECDSA signature", signature, ECDSA_SIGNATURE_SIZE);
    try {
      return secp256k1.verify(signature, doubleSha256(message), publicKey, {
        prehash: false,
        lowS: true,
      });
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

/** The shape of the {@link schnorr} family. */
export interface Schnorr {
  /** x-only public key length in bytes. */
  readonly PUBLIC_KEY_SIZE: 32;
  /** BIP-340 signature length in bytes. */
  readonly SIGNATURE_SIZE: 64;
  /**
   * x-only (32-byte) public key of a secp256k1 private key.
   * @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar.
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * BIP-340 signature. Aux-rand comes from `options.auxRand`, else 32 bytes drawn from `options.rng`.
   * @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar.
   */
  sign(
    privateKey: Uint8Array,
    message: Uint8Array,
    options?: SchnorrSignOptions,
  ): Uint8Array<ArrayBuffer>;
  /**
   * `false` on an invalid signature or a malformed key (BIP-340 vectors 5–14).
   * @throws {CryptoError} `InvalidSize` on a wrong-length key or signature.
   */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}

/** BIP-340 Schnorr signatures over secp256k1, with the two aux-rand paths. */
export const schnorr: Schnorr = {
  PUBLIC_KEY_SIZE: 32,
  SIGNATURE_SIZE: 64,

  publicKey(privateKey) {
    requireLength("Schnorr private key", privateKey, ECDSA_PRIVATE_KEY_SIZE);
    return guard(() => nobleSchnorr.getPublicKey(privateKey), invalidScalar("Schnorr private key"));
  },

  sign(privateKey, message, options) {
    requireLength("Schnorr private key", privateKey, ECDSA_PRIVATE_KEY_SIZE);
    const auxRand = options?.auxRand ?? randomBytes(32, { rng: options?.rng ?? secureRng() });
    if (auxRand.length !== 32)
      throw CryptoError.invalidSize("Schnorr auxiliary randomness", 32, auxRand.length);
    return guard(
      () => nobleSchnorr.sign(message, privateKey, auxRand),
      invalidScalar("Schnorr private key"),
    );
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
