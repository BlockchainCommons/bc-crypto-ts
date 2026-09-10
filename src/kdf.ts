/**
 * Password-based key derivation: scrypt and Argon2id.
 *
 * @module kdf
 */
import { scrypt as nobleScrypt } from "@noble/hashes/scrypt.js";
import { argon2id as nobleArgon2id } from "@noble/hashes/argon2.js";
import { CryptoError } from "./error.js";

/** Options for {@link scrypt}. Defaults are the reference parameters. */
export interface ScryptOptions {
  /** Derived key length in bytes. */
  readonly dkLen: number;
  /** log₂ of the CPU/memory cost `N`. Default 17 (N = 131072). Must be < 64. */
  readonly logN?: number | undefined;
  /** Block size. Default 8. */
  readonly r?: number | undefined;
  /** Parallelism. Default 1. */
  readonly p?: number | undefined;
}

export function scrypt(
  password: Uint8Array,
  salt: Uint8Array,
  options: ScryptOptions,
): Uint8Array<ArrayBuffer> {
  const logN = options.logN ?? 17;
  const r = options.r ?? 8;
  const p = options.p ?? 1;
  if (logN >= 64) throw CryptoError.unsupported("scrypt logN must be < 64");
  if (r === 0) throw CryptoError.unsupported("scrypt r must be > 0");
  if (p === 0) throw CryptoError.unsupported("scrypt p must be > 0");
  return nobleScrypt(password, salt, {
    N: 1 << logN,
    r,
    p,
    dkLen: options.dkLen,
  });
}

/** Options for {@link argon2id}. Defaults are the reference parameters. */
export interface Argon2idOptions {
  /** Derived key length in bytes. */
  readonly dkLen: number;
  /** Iterations. Default 2. */
  readonly t?: number | undefined;
  /** Memory in KiB. Default 19456. */
  readonly m?: number | undefined;
  /** Parallelism. Default 1. */
  readonly p?: number | undefined;
}

export function argon2id(
  password: Uint8Array,
  salt: Uint8Array,
  options: Argon2idOptions,
): Uint8Array<ArrayBuffer> {
  return nobleArgon2id(password, salt, {
    t: options.t ?? 2,
    m: options.m ?? 19456,
    p: options.p ?? 1,
    dkLen: options.dkLen,
  });
}
