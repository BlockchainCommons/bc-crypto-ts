/**
 * Hashes, MACs, key derivation, and CRC-32.
 *
 * @module hash
 */
import { sha256 as nobleSha256, sha512 as nobleSha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
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

/** CRC-32 (IEEE 802.3 / ISO-HDLC) as an unsigned 32-bit integer. */
export function crc32(data: Uint8Array): number {
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

/** CRC-32 as four bytes, big-endian unless `littleEndian` is set. */
export function crc32Bytes(data: Uint8Array, options?: Crc32Options): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, crc32(data), options?.littleEndian ?? false);
  return result;
}

/** SHA-256 of `data` (32 bytes). */
export function sha256(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return nobleSha256(data);
}

/** `sha256(sha256(data))`, the Bitcoin message hash. */
export function doubleSha256(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return sha256(sha256(data));
}

/** SHA-512 of `data` (64 bytes). */
export function sha512(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return nobleSha512(data);
}

/** HMAC-SHA-256 of `message` under `key` (32 bytes). */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer> {
  return hmac(nobleSha256, key, message);
}

/** HMAC-SHA-512 of `message` under `key` (64 bytes). */
export function hmacSha512(key: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer> {
  return hmac(nobleSha512, key, message);
}

/** Options for the PBKDF2 functions. */
export interface Pbkdf2Options {
  /** PBKDF2 iteration count; an integer ≥ 1. */
  readonly iterations: number;
  /** Derived key length in bytes. */
  readonly dkLen: number;
}

const pbkdf2Domain = (options: Pbkdf2Options): { c: number; dkLen: number } => ({
  c: expectInt("pbkdf2 iterations", options.iterations, 1, U32_MAX),
  dkLen: expectInt("pbkdf2 dkLen", options.dkLen, 1, U32_MAX),
});

/** @throws {CryptoError} `InvalidParameter` unless `iterations` and `dkLen` are integers ≥ 1. */
export function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  options: Pbkdf2Options,
): Uint8Array<ArrayBuffer> {
  const domain = pbkdf2Domain(options);
  return guard(
    () => pbkdf2(nobleSha256, password, salt, domain),
    backendRejected("pbkdf2 parameters"),
  );
}

/** @throws {CryptoError} `InvalidParameter` unless `iterations` and `dkLen` are integers ≥ 1. */
export function pbkdf2Sha512(
  password: Uint8Array,
  salt: Uint8Array,
  options: Pbkdf2Options,
): Uint8Array<ArrayBuffer> {
  const domain = pbkdf2Domain(options);
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
 * @throws {CryptoError} `InvalidParameter` unless `dkLen` is an integer in [0, 255 · 32].
 */
export function hkdfSha256(
  keyMaterial: Uint8Array,
  salt: Uint8Array,
  options: HkdfOptions,
): Uint8Array<ArrayBuffer> {
  const dkLen = expectInt("hkdf dkLen", options.dkLen, 0, 255 * SHA256_SIZE);
  return guard(
    () => hkdf(nobleSha256, keyMaterial, salt, undefined, dkLen),
    backendRejected("hkdf parameters"),
  );
}

/**
 * HKDF-SHA-512 with no `info`, `dkLen` output bytes.
 * @throws {CryptoError} `InvalidParameter` unless `dkLen` is an integer in [0, 255 · 64].
 */
export function hkdfSha512(
  keyMaterial: Uint8Array,
  salt: Uint8Array,
  options: HkdfOptions,
): Uint8Array<ArrayBuffer> {
  const dkLen = expectInt("hkdf dkLen", options.dkLen, 0, 255 * SHA512_SIZE);
  return guard(
    () => hkdf(nobleSha512, keyMaterial, salt, undefined, dkLen),
    backendRejected("hkdf parameters"),
  );
}
