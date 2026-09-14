/**
 * Hashes, MACs, key derivation, and CRC-32.
 *
 * @module hash
 */
import { sha256 as nobleSha256, sha512 as nobleSha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { expectBool, requireBytes, requireOptions } from "./error.js";
import { backendRejected, expectInt, guard, U32_MAX } from "./domain.js";

/** Bytes in a CRC-32 checksum. */
export const CRC32_SIZE = 4;
/** Bytes in a SHA-256 digest. */
export const SHA256_SIZE = 32;
/** Bytes in a SHA-512 digest. */
export const SHA512_SIZE = 64;

// CRC-32 lookup table (IEEE polynomial 0xedb88320), built once.
const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let crc = i;
  for (let j = 0; j < 8; j++) crc = (crc & 1) !== 0 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  CRC32_TABLE[i] = crc >>> 0;
}

/**
 * CRC-32 (IEEE 802.3 / ISO-HDLC) as an unsigned 32-bit integer.
 * @throws {CryptoError} `InvalidParameter` unless `data` is a `Uint8Array`.
 */
export function crc32(data: Uint8Array): number {
  requireBytes("crc32 data", data);
  let crc = 0xffffffff;
  // Indexed loop: the iterator protocol over a typed array is 2× slower here.
  // eslint-disable-next-line @typescript-eslint/prefer-for-of
  for (let i = 0; i < data.length; i++) {
    crc = CRC32_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** Options for {@link crc32Bytes}. */
export interface Crc32Options {
  /** Emit the checksum little-endian. Default: big-endian. */
  readonly littleEndian?: boolean | undefined;
}

/**
 * CRC-32 as four bytes, big-endian unless `littleEndian` is set.
 * @throws {CryptoError} `InvalidParameter` unless `data` is a `Uint8Array`,
 * `options` an object (or absent) and `littleEndian` a boolean (or absent).
 */
export function crc32Bytes(data: Uint8Array, options?: Crc32Options): Uint8Array<ArrayBuffer> {
  requireBytes("crc32 data", data);
  requireOptions("crc32 options", options, true);
  const littleEndian = expectBool("crc32 littleEndian", options?.littleEndian) ?? false;
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, crc32(data), littleEndian);
  return result;
}

/**
 * SHA-256 of `data` (32 bytes).
 * @throws {CryptoError} `InvalidParameter` unless `data` is a `Uint8Array`.
 */
export function sha256(data: Uint8Array): Uint8Array<ArrayBuffer> {
  requireBytes("sha256 data", data);
  return nobleSha256(data);
}

/**
 * `sha256(sha256(data))`, the Bitcoin message hash.
 * @throws {CryptoError} `InvalidParameter` unless `data` is a `Uint8Array`.
 */
export function doubleSha256(data: Uint8Array): Uint8Array<ArrayBuffer> {
  requireBytes("doubleSha256 data", data);
  return nobleSha256(nobleSha256(data));
}

/**
 * SHA-512 of `data` (64 bytes).
 * @throws {CryptoError} `InvalidParameter` unless `data` is a `Uint8Array`.
 */
export function sha512(data: Uint8Array): Uint8Array<ArrayBuffer> {
  requireBytes("sha512 data", data);
  return nobleSha512(data);
}

/**
 * HMAC-SHA-256 of `message` under `key` (32 bytes).
 * @throws {CryptoError} `InvalidParameter` unless both arguments are `Uint8Array`s.
 */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer> {
  requireBytes("hmacSha256 key", key);
  requireBytes("hmacSha256 message", message);
  return hmac(nobleSha256, key, message);
}

/**
 * HMAC-SHA-512 of `message` under `key` (64 bytes).
 * @throws {CryptoError} `InvalidParameter` unless both arguments are `Uint8Array`s.
 */
export function hmacSha512(key: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer> {
  requireBytes("hmacSha512 key", key);
  requireBytes("hmacSha512 message", message);
  return hmac(nobleSha512, key, message);
}

/** Options for the PBKDF2 functions. */
export interface Pbkdf2Options {
  /**
   * PBKDF2 iteration count; an integer in [1, 2^32 − 1]. The reference asserts
   * `iterations > 0`, including for empty output, so 0 is `InvalidParameter`.
   */
  readonly iterations: number;
  /**
   * Derived key length in bytes; an integer in [0, (2^32 − 1) · hLen]
   * (RFC 8018 §5.2, hLen 32 or 64). 0 is an empty key on both sides. An
   * allocation the host cannot make surfaces as `InvalidParameter` with the
   * engine error as `cause`.
   */
  readonly dkLen: number;
}

const pbkdf2Domain = (options: Pbkdf2Options, hLen: number): { c: number; dkLen: number } => ({
  // Checked before the empty-output return: the reference's `assert!(iterations > 0)`
  // comes before its allocation, so it fires for empty output too.
  c: expectInt("pbkdf2 iterations", options.iterations, 1, U32_MAX),
  // `dkLen: 0` is an empty key on both sides (the reference fills a zero-length Vec).
  dkLen: expectInt("pbkdf2 dkLen", options.dkLen, 0, U32_MAX * hLen),
});

/**
 * PBKDF2-HMAC-SHA-256.
 * @throws {CryptoError} `InvalidParameter` unless `password` and `salt` are
 * `Uint8Array`s, `options` is an object, `iterations` an integer in
 * [1, 2^32 − 1] and `dkLen` an integer in [0, (2^32 − 1) · 32].
 */
export function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  options: Pbkdf2Options,
): Uint8Array<ArrayBuffer> {
  requireBytes("pbkdf2 password", password);
  requireBytes("pbkdf2 salt", salt);
  requireOptions("pbkdf2 options", options, false);
  const domain = pbkdf2Domain(options, SHA256_SIZE);
  if (domain.dkLen === 0) return new Uint8Array(0);
  return guard(
    () => pbkdf2(nobleSha256, password, salt, domain),
    backendRejected("pbkdf2 parameters"),
  );
}

/**
 * PBKDF2-HMAC-SHA-512.
 * @throws {CryptoError} `InvalidParameter` unless `password` and `salt` are
 * `Uint8Array`s, `options` is an object, `iterations` an integer in
 * [1, 2^32 − 1] and `dkLen` an integer in [0, (2^32 − 1) · 64].
 */
export function pbkdf2Sha512(
  password: Uint8Array,
  salt: Uint8Array,
  options: Pbkdf2Options,
): Uint8Array<ArrayBuffer> {
  requireBytes("pbkdf2 password", password);
  requireBytes("pbkdf2 salt", salt);
  requireOptions("pbkdf2 options", options, false);
  const domain = pbkdf2Domain(options, SHA512_SIZE);
  if (domain.dkLen === 0) return new Uint8Array(0);
  return guard(
    () => pbkdf2(nobleSha512, password, salt, domain),
    backendRejected("pbkdf2 parameters"),
  );
}

/** Options for the HKDF functions. */
export interface HkdfOptions {
  /** Derived key length in bytes; at most 255 × the hash length. */
  readonly dkLen: number;
}

/**
 * HKDF-SHA-256 with no `info`, `dkLen` output bytes.
 * @throws {CryptoError} `InvalidParameter` unless `keyMaterial` and `salt`
 * are `Uint8Array`s, `options` is an object and `dkLen` an integer in [0, 255 · 32].
 */
export function hkdfSha256(
  keyMaterial: Uint8Array,
  salt: Uint8Array,
  options: HkdfOptions,
): Uint8Array<ArrayBuffer> {
  requireBytes("hkdf key material", keyMaterial);
  requireBytes("hkdf salt", salt);
  requireOptions("hkdf options", options, false);
  const dkLen = expectInt("hkdf dkLen", options.dkLen, 0, 255 * SHA256_SIZE);
  return guard(
    () => hkdf(nobleSha256, keyMaterial, salt, undefined, dkLen),
    backendRejected("hkdf parameters"),
  );
}

/**
 * HKDF-SHA-512 with no `info`, `dkLen` output bytes.
 * @throws {CryptoError} `InvalidParameter` unless `keyMaterial` and `salt`
 * are `Uint8Array`s, `options` is an object and `dkLen` an integer in [0, 255 · 64].
 */
export function hkdfSha512(
  keyMaterial: Uint8Array,
  salt: Uint8Array,
  options: HkdfOptions,
): Uint8Array<ArrayBuffer> {
  requireBytes("hkdf key material", keyMaterial);
  requireBytes("hkdf salt", salt);
  requireOptions("hkdf options", options, false);
  const dkLen = expectInt("hkdf dkLen", options.dkLen, 0, 255 * SHA512_SIZE);
  return guard(
    () => hkdf(nobleSha512, keyMaterial, salt, undefined, dkLen),
    backendRejected("hkdf parameters"),
  );
}
