/**
 * Ed25519 signatures.
 *
 * @module ed25519
 */
import { ed25519 as noble } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, equalBytes } from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";
import {
  type RandomNumberGenerator,
  type RngOptions,
  RandError,
  fillRandomBytes,
  secureRng,
} from "@blockchaincommons/rand";
import { requireBytes, requireLength, requireOptions } from "./error.js";
import { guard, invalidPoint } from "./domain.js";

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
  /**
   * 32 random bytes from `options.rng` (default secure). The reference's
   * `ed25519_new_private_key_using` draws through `rand_core`'s `fill_bytes`,
   * so the generator's `fillBytesPacked` is used when it has one (the packed
   * stream of `SeededRng`), else `fillBytes` through rand's `fillRandomBytes`.
   * A generator's own error propagates unwrapped; a `fillBytesPacked` that is
   * present but not a function is rand's `RandError` `InvalidGenerator`.
   * @throws {CryptoError} `InvalidParameter` unless `options` is an object or absent.
   */
  generatePrivateKey(options?: RngOptions): Uint8Array<ArrayBuffer>;
  /**
   * The public key of the 32-byte seed `privateKey` (RFC 8032).
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong-length key.
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * Deterministic RFC 8032 signature (64 bytes).
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong-length key.
   */
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * `(publicKey, signature, message)`, the same order as `ecdsa.verify` and `schnorr.verify`.
   *
   * Uses the reference's uncofactored verification equation (`verify_strict`):
   * `false` for a small-order key or `R`, a non-canonical `R`, an `s` ≥ L,
   * or a signature that does not verify. The key is decoded as the
   * reference's `VerifyingKey::from_bytes` decodes it (a non-canonical y is
   * reduced), and its `.unwrap()` on a key with no point is a panic.
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array`; `InvalidSize` on a wrong-length key or signature; `InvalidData` when the key is not a point on the curve.
   */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}

/** Ed25519 (RFC 8032) signatures with strict verification. */
export const ed25519: Ed25519 = {
  PRIVATE_KEY_SIZE: 32,
  PUBLIC_KEY_SIZE: 32,
  SIGNATURE_SIZE: 64,

  generatePrivateKey(options) {
    requireOptions("Ed25519 options", options, true);
    // The reference's `ed25519_new_private_key_using` reaches the generator
    // through rand_core generics (`SigningKey::generate` → `fill_bytes`): the
    // packed stream where a generator distinguishes one, else the same bytes
    // as `randomBytes`.
    const rng: RandomNumberGenerator = options?.rng ?? secureRng();
    const key = new Uint8Array(ED25519_PRIVATE_KEY_SIZE);
    // Read once. rand never calls this optional member, so its contract is
    // checked here, with rand's own error, as rand checks the members it calls.
    // The single read is deliberate; the call below rebinds `this` to `rng`.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const packed: unknown = rng.fillBytesPacked;
    if (packed === undefined) {
      fillRandomBytes(key, { rng });
    } else if (typeof packed === "function") {
      (packed as (dest: Uint8Array) => void).call(rng, key);
    } else {
      throw RandError.invalidGenerator("fillBytesPacked", packed);
    }
    return key;
  },

  publicKey(privateKey) {
    requireLength("Ed25519 private key", privateKey, ED25519_PRIVATE_KEY_SIZE);
    return noble.getPublicKey(privateKey);
  },

  sign(privateKey, message) {
    requireLength("Ed25519 private key", privateKey, ED25519_PRIVATE_KEY_SIZE);
    requireBytes("Ed25519 message", message);
    return noble.sign(message, privateKey);
  },

  verify(publicKey, signature, message) {
    requireLength("Ed25519 public key", publicKey, ED25519_PUBLIC_KEY_SIZE);
    requireLength("Ed25519 signature", signature, ED25519_SIGNATURE_SIZE);
    requireBytes("Ed25519 message", message);
    // dalek's `CompressedEdwardsY::decompress` reduces a non-canonical y and
    // fails only when the reduced y has no x: noble's `zip215 = true` rule.
    // The reference `.unwrap()`s it.
    const a = guard(
      () => noble.Point.fromBytes(publicKey, true),
      invalidPoint("Ed25519 public key"),
    );
    try {
      // Canonical decoding (zip215 = false) of R, then the small-order checks
      // `verify_strict` makes, then the equation. A decodable non-canonical
      // key is small-order (rejected below and by `verify_strict`) or a point
      // whose discrete logarithm nobody knows, so it is `false` on both sides.
      const r = noble.Point.fromBytes(signature.subarray(0, 32), false);
      if (a.isSmallOrder() || r.isSmallOrder()) return false;
      const order = noble.Point.Fn.ORDER;
      const s = bytesToNumberLE(signature.subarray(32));
      if (s >= order) return false;
      // Hash the original encodings. Clearing the cofactor here would accept
      // mixed-order R values that dalek's verify_strict rejects.
      const k =
        bytesToNumberLE(
          sha512
            .create()
            .update(signature.subarray(0, 32))
            .update(publicKey)
            .update(message)
            .digest(),
        ) % order;
      const expectedR = noble.Point.BASE.multiplyUnsafe(s).subtract(a.multiplyUnsafe(k));
      return equalBytes(expectedR.toBytes(), signature.subarray(0, 32));
    } catch {
      return false;
    }
  },
};
