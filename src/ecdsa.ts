/**
 * secp256k1: ECDSA keys and signatures, and BIP-340 Schnorr.
 *
 * @module ecdsa
 */
import { secp256k1, schnorr as nobleSchnorr } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE } from "@noble/curves/utils.js";
import {
  type RandomNumberGenerator,
  type RngOptions,
  randomBytes,
  secureRng,
} from "@blockchaincommons/rand";
import { doubleSha256 } from "./hash.js";
import { CryptoError, requireBytes, requireLength, requireOptions } from "./error.js";
import { guard, invalidPoint } from "./domain.js";

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

const CURVE_ORDER = secp256k1.Point.Fn.ORDER;

/**
 * The reference's `Signature::from_compact` is `.expect`ed, and libsecp256k1's
 * `secp256k1_ecdsa_signature_parse_compact` fails only when r or s overflows
 * n: that is `InvalidData` here. r or s = 0 parses, and then does not verify.
 */
function requireCompactScalars(what: string, signature: Uint8Array): void {
  const r = bytesToNumberBE(signature.subarray(0, 32));
  const s = bytesToNumberBE(signature.subarray(32));
  if (r >= CURVE_ORDER || s >= CURVE_ORDER) {
    throw CryptoError.invalidData(what, `${what} has r or s outside [0, n - 1]`);
  }
}

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
  /**
   * 32 random bytes from `options.rng` (default secure), unvalidated; the
   * reference's `ecdsa_new_private_key_using` (`random_data`). A generator's
   * own error, including rand's `InvalidGenerator`, propagates unwrapped.
   * @throws {CryptoError} `InvalidParameter` unless `options` is an object or absent.
   */
  generatePrivateKey(options?: RngOptions): Uint8Array<ArrayBuffer>;
  /**
   * Compressed (33-byte) public key.
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar (0 or ≥ n).
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /** @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong length; `InvalidData` when the bytes are not a point on the curve. */
  decompressPublicKey(compressed: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * 65 bytes: `04 ‖ x ‖ y`, or the hybrid `06`/`07` forms, whose low bit must
   * equal the parity of y (libsecp256k1's parser, which the reference uses).
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong length; `InvalidData` when the bytes are not a point on the curve or a hybrid prefix disagrees with y.
   */
  compressPublicKey(uncompressed: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * Deterministic (RFC 6979) signature over `doubleSha256(message)`; 64-byte compact form.
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar.
   */
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * `false` on a signature that does not verify, r or s = 0 and a high s
   * included (libsecp256k1's `secp256k1_ecdsa_verify`).
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong-length key or signature; `InvalidData` when the key is not a point on the curve or r or s ≥ n, the reference's `.expect`ed parses (`PublicKey::from_slice`, `Signature::from_compact`).
   */
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
    requireOptions("ECDSA options", options, true);
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
    const head = uncompressed[0];
    return guard(() => {
      if (head === 0x06 || head === 0x07) {
        // libsecp256k1 (`secp256k1_eckey_pubkey_parse`) accepts the hybrid
        // prefixes when the low bit states y's parity; noble parses `04` only.
        const plain = Uint8Array.from(uncompressed);
        plain[0] = 0x04;
        const point = secp256k1.Point.fromBytes(plain);
        if ((point.toAffine().y & 1n) !== BigInt(head & 1)) {
          // A CryptoError passes through `guard`; the point is on the curve,
          // so `invalidPoint`'s message would be wrong here. The reference
          // does not distinguish the two: both are `InvalidPublicKey`.
          throw CryptoError.invalidData(
            "ECDSA uncompressed public key",
            "ECDSA uncompressed public key has a hybrid prefix that does not match the parity of y",
          );
        }
        return point.toBytes(true);
      }
      return secp256k1.Point.fromBytes(uncompressed).toBytes(true);
    }, invalidPoint("ECDSA uncompressed public key"));
  },

  sign(privateKey, message) {
    requireLength("ECDSA private key", privateKey, ECDSA_PRIVATE_KEY_SIZE);
    requireBytes("ECDSA message", message);
    return guard(
      () => secp256k1.sign(doubleSha256(message), privateKey, { prehash: false }),
      invalidScalar("ECDSA private key"),
    );
  },

  verify(publicKey, signature, message) {
    requireLength("ECDSA public key", publicKey, ECDSA_PUBLIC_KEY_SIZE);
    requireLength("ECDSA signature", signature, ECDSA_SIGNATURE_SIZE);
    requireBytes("ECDSA message", message);
    // The reference parses with `.expect`, the key first: an undecodable key
    // or an r or s ≥ n is a panic. A parsed pair that does not verify is `false`.
    guard(() => secp256k1.Point.fromBytes(publicKey), invalidPoint("ECDSA public key"));
    requireCompactScalars("ECDSA signature", signature);
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
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar.
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * BIP-340 signature. Aux-rand comes from `options.auxRand`, else 32 bytes
   * drawn from `options.rng` (the reference's `schnorr_sign_using`,
   * `random_data(32)`); a generator's own error propagates unwrapped.
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array` or a non-object `options`; `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar.
   */
  sign(
    privateKey: Uint8Array,
    message: Uint8Array,
    options?: SchnorrSignOptions,
  ): Uint8Array<ArrayBuffer>;
  /**
   * `false` on a signature that does not verify (BIP-340 vectors 6–13).
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong-length key or signature; `InvalidData` when the key is not the x of a point on the curve (BIP-340 vectors 5 and 14), the reference's `.expect`ed `XOnlyPublicKey::from_byte_array`.
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
    requireBytes("Schnorr message", message);
    requireOptions("Schnorr options", options, true);
    const given = options?.auxRand;
    if (given !== undefined) requireBytes("Schnorr auxiliary randomness", given);
    const auxRand = given ?? randomBytes(32, { rng: options?.rng ?? secureRng() });
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
    requireBytes("Schnorr message", message);
    // The reference `.expect`s the key (`secp256k1_xonly_pubkey_parse`: x < p
    // and on the curve, which is what `02 ‖ x` decodes under); any 64 bytes
    // are a signature, which then verifies or not.
    guard(
      () => secp256k1.Point.fromBytes(Uint8Array.of(0x02, ...publicKey)),
      invalidPoint("Schnorr public key"),
    );
    try {
      return nobleSchnorr.verify(signature, message, publicKey);
    } catch {
      return false;
    }
  },
};
