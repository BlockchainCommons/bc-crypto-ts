/**
 * Password-based key derivation: scrypt and Argon2id.
 *
 * @module kdf
 */
import { scrypt as nobleScrypt } from "@noble/hashes/scrypt.js";
import { argon2id as nobleArgon2id } from "@noble/hashes/argon2.js";
import { backendRejected, expectInt, expectMinLength, guard, U32_MAX } from "./domain.js";

/** Options for {@link scrypt}. Defaults are the reference parameters. */
export interface ScryptOptions {
  /** Derived key length in bytes. */
  readonly dkLen: number;
  /** log₂ of the CPU/memory cost `N`. Default 17 (N = 131072). An integer in [1, 63]. */
  readonly logN?: number | undefined;
  /** Block size. Default 8. */
  readonly r?: number | undefined;
  /** Parallelism. Default 1. */
  readonly p?: number | undefined;
}

/**
 * @throws {CryptoError} `InvalidParameter` when `dkLen` is not an integer ≥ 1,
 * `logN` not in [1, 63], `r` or `p` not ≥ 1, or the parameters exceed the
 * backend's memory limit.
 */
export function scrypt(
  password: Uint8Array,
  salt: Uint8Array,
  options: ScryptOptions,
): Uint8Array<ArrayBuffer> {
  const dkLen = expectInt("scrypt dkLen", options.dkLen, 1, U32_MAX);
  const logN = expectInt("scrypt logN", options.logN ?? 17, 1, 63);
  const r = expectInt("scrypt r", options.r ?? 8, 1, U32_MAX);
  const p = expectInt("scrypt p", options.p ?? 1, 1, U32_MAX);
  return guard(
    () => nobleScrypt(password, salt, { N: 2 ** logN, r, p, dkLen }),
    backendRejected("scrypt parameters"),
  );
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

/**
 * @throws {CryptoError} `InvalidParameter` when `dkLen` is not an integer ≥ 4,
 * `salt` is shorter than 8 bytes, `t` is not ≥ 1, `p` not in [1, 2^24 - 1],
 * or `m` is not ≥ 8·p.
 */
export function argon2id(
  password: Uint8Array,
  salt: Uint8Array,
  options: Argon2idOptions,
): Uint8Array<ArrayBuffer> {
  const dkLen = expectInt("argon2id dkLen", options.dkLen, 4, U32_MAX);
  expectMinLength("argon2id salt", salt, 8);
  const t = expectInt("argon2id t", options.t ?? 2, 1, U32_MAX);
  const p = expectInt("argon2id p", options.p ?? 1, 1, 0xffffff);
  const m = expectInt("argon2id m", options.m ?? 19456, 8 * p, U32_MAX);
  return guard(
    () => nobleArgon2id(password, salt, { t, m, p, dkLen }),
    backendRejected("argon2id parameters"),
  );
}
