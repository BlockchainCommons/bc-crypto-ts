/**
 * Password-based key derivation: scrypt and Argon2id.
 *
 * @module kdf
 */
import { scrypt as nobleScrypt } from "@noble/hashes/scrypt.js";
import { argon2id as nobleArgon2id } from "@noble/hashes/argon2.js";
import { CryptoError, requireBytes, requireOptions } from "./error.js";
import { backendRejected, expectInt, expectMinLength, guard, U32_MAX } from "./domain.js";
import { scryptCore } from "./scrypt-core.js";

/**
 * A working buffer larger than this goes to the paged core: every engine
 * can hold 2^31 bytes in one typed array, JavaScriptCore no more than 2^32.
 */
const SINGLE_BUFFER_LIMIT = 2 ** 31;

/** Options for {@link scrypt}. Defaults are the reference parameters. */
export interface ScryptOptions {
  /**
   * Derived key length in bytes. With any of `logN`, `r`, `p` given it must
   * be in `[10, 64]` (the reference's parameterised path, `scrypt::Params::new`);
   * with the defaults any length ≥ 1 is accepted (the reference's default path).
   */
  readonly dkLen: number;
  /**
   * log₂ of the CPU/memory cost `N`. Default 17 (N = 131072). An integer in
   * [1, 32] and below `16·r`; the reference asserts `log_n > 0`, and its
   * panic is `InvalidParameter` here. Values above 32 need at least 3.3 TiB.
   */
  readonly logN?: number | undefined;
  /** Block size. Default 8. */
  readonly r?: number | undefined;
  /** Parallelism. Default 1. `r·p` must be below 2^30. */
  readonly p?: number | undefined;
  /**
   * An optional ceiling in bytes on the working memory, `128·r·(N + p + 1)`.
   * By default there is none, as in the reference, which allocates whatever
   * the parameters imply; a parameter set above the ceiling is
   * `InvalidParameter`. A ceiling does not bypass the `logN` limit or the
   * runtime's allocation limits.
   */
  readonly maxmem?: number | undefined;
}

/** The output length `scrypt::scrypt` accepts: `(2^32 − 1) · 32`. */
const SCRYPT_MAX_DKLEN = 0xffffffff * 32;

/**
 * @throws {CryptoError} `InvalidParameter` unless `password` and `salt` are
 * `Uint8Array`s and `options` an object; when `dkLen` is outside its domain
 * (see {@link ScryptOptions.dkLen}), `logN` not in [1, 32] or not below `16·r`
 * (scrypt requires `N < 2^(128·r/8)`), `r` or `p` not ≥ 1, `r·p` not below
 * 2^30, or the parameters exceed `maxmem`.
 */
export function scrypt(
  password: Uint8Array,
  salt: Uint8Array,
  options: ScryptOptions,
): Uint8Array<ArrayBuffer> {
  requireBytes("scrypt password", password);
  requireBytes("scrypt salt", salt);
  requireOptions("scrypt options", options, false);
  const parameterised =
    options.logN !== undefined || options.r !== undefined || options.p !== undefined;
  const dkLen = parameterised
    ? expectInt("scrypt dkLen", options.dkLen, 10, 64)
    : expectInt("scrypt dkLen", options.dkLen, 1, SCRYPT_MAX_DKLEN);
  const logN = expectInt("scrypt logN", options.logN ?? 17, 1, 32);
  const r = expectInt("scrypt r", options.r ?? 8, 1, U32_MAX);
  const p = expectInt("scrypt p", options.p ?? 1, 1, U32_MAX);
  // The two shape rules of RFC 7914 §2 that the reference's `scrypt::Params::new` enforces.
  if (logN >= 16 * r) {
    throw CryptoError.invalidParameter(
      "scrypt logN",
      `scrypt logN must be below 16·r (N < 2^(128·r/8)), got logN ${logN} with r ${r}`,
    );
  }
  if (r * p >= 2 ** 30) {
    throw CryptoError.invalidParameter("scrypt p", `scrypt r·p must be below 2^30, got ${r * p}`);
  }
  // No ceiling unless asked: the reference has none. noble's own default (~1 GiB)
  // would reject parameter sets the reference derives with.
  const maxmem =
    options.maxmem === undefined
      ? Number.MAX_SAFE_INTEGER
      : expectInt("scrypt maxmem", options.maxmem, 1, Number.MAX_SAFE_INTEGER);
  const N = 2 ** logN;
  const blockBytes = 128 * r;
  if (blockBytes * N > SINGLE_BUFFER_LIMIT || blockBytes * p > SINGLE_BUFFER_LIMIT) {
    // Too large for one typed array on JavaScriptCore: the paged core, with
    // the same `maxmem` rule and error shape as noble's.
    const memUsed = blockBytes * (N + p + 1);
    if (memUsed > maxmem) {
      throw backendRejected("scrypt parameters")(
        new Error(`"maxmem" limit was hit: memUsed(128*r*(N+p+1))=${memUsed}, maxmem=${maxmem}`),
      );
    }
    return guard(
      () => scryptCore(password, salt, { N, r, p, dkLen }),
      backendRejected("scrypt parameters"),
    );
  }
  return guard(
    () => nobleScrypt(password, salt, { N, r, p, dkLen, maxmem }),
    backendRejected("scrypt parameters"),
  );
}

/** Options for {@link argon2id}. */
export interface Argon2idOptions {
  /** Derived key length in bytes; at least 4. */
  readonly dkLen: number;
}

// The reference's `Argon2::default()`: Argon2id, version 0x13, m = 19456 KiB,
// t = 2, p = 1. There are no other costs: the wire (`Argon2idParams`) carries
// a salt only, so nothing else could be reproduced by another implementation.
const ARGON2ID_T = 2;
const ARGON2ID_M = 19456;
const ARGON2ID_P = 1;

/**
 * Argon2id with the reference's fixed parameters (m 19456 KiB, t 2, p 1).
 * @throws {CryptoError} `InvalidParameter` unless `password` and `salt` are
 * `Uint8Array`s and `options` an object; when `dkLen` is not an integer ≥ 4
 * or `salt` is shorter than 8 bytes.
 */
export function argon2id(
  password: Uint8Array,
  salt: Uint8Array,
  options: Argon2idOptions,
): Uint8Array<ArrayBuffer> {
  requireBytes("argon2id password", password);
  requireBytes("argon2id salt", salt);
  requireOptions("argon2id options", options, false);
  const dkLen = expectInt("argon2id dkLen", options.dkLen, 4, U32_MAX);
  expectMinLength("argon2id salt", salt, 8);
  return guard(
    () => nobleArgon2id(password, salt, { t: ARGON2ID_T, m: ARGON2ID_M, p: ARGON2ID_P, dkLen }),
    backendRejected("argon2id parameters"),
  );
}
