/**
 * The single error type thrown by this package.
 *
 * @module error
 */
import { isBytes } from "@noble/hashes/utils.js";

/** Machine-readable discriminant for a {@link CryptoError}. */
export type CryptoErrorCode =
  | "InvalidSize"
  | "InvalidData"
  | "InvalidParameter"
  | "NonContributoryKey"
  | "AuthenticationFailed";

/**
 * The structured payload of a {@link CryptoError}, discriminated by `code`:
 * `e.details.code === "InvalidSize"` narrows to `{ what, expected, actual }`.
 */
export type CryptoErrorDetails =
  | {
      /** A key, nonce, signature, tag or sealed buffer had the wrong length. */
      readonly code: "InvalidSize";
      /** The argument, e.g. `"ECDSA private key"`. */
      readonly what: string;
      /** The required length in bytes. */
      readonly expected: number;
      /** The length received. */
      readonly actual: number;
    }
  | {
      /** A key, point or signature of the right length that is not valid. */
      readonly code: "InvalidData";
      /** The argument, e.g. `"ECDSA compressed public key"`. */
      readonly what: string;
    }
  | {
      /**
       * An argument outside its domain: a number that is not an integer of
       * the Rust width, an options object that is not an object, a boolean
       * option that is not a boolean, or a byte argument that is not a
       * `Uint8Array`. Also a KDF parameter set the backend rejects.
       */
      readonly code: "InvalidParameter";
      /** The argument, e.g. `"scrypt logN"` or `"ECDSA message"`. */
      readonly what: string;
    }
  | {
      /**
       * `x25519.sharedKey` was given a low-order peer key, so the shared
       * secret would be all zero (the reference's `Error::NonContributoryKey`).
       */
      readonly code: "NonContributoryKey";
      /** The argument: `"X25519 public key"`. */
      readonly what: string;
    }
  | {
      /** AEAD authentication failed: wrong key, nonce or aad, or tampered data. */
      readonly code: "AuthenticationFailed";
    };

/**
 * Thrown for wrong-length keys, nonces, signatures and public keys
 * (`InvalidSize`), a key, point or signature of the right length that is not
 * valid (`InvalidData`), an argument outside its domain, including a value
 * of the wrong type (`InvalidParameter`), a low-order X25519 peer key
 * (`NonContributoryKey`), and AEAD tag mismatch (`AuthenticationFailed`).
 *
 * Every failure of an argument or of a primitive is a `CryptoError`; when a
 * backend error is what was caught, it is the `cause`. Two things propagate
 * unwrapped, because they are not this package's: a generator's own error
 * (`RandError` from `@blockchaincommons/rand`, including `InvalidGenerator`
 * for a generator that lacks a method the draw calls), and an allocation
 * failure outside the KDFs (`RangeError` from the engine). Instances come
 * from the static factories only.
 *
 * @example
 * ```ts
 * try {
 *   chacha20Poly1305.decrypt(key, nonce, sealed);
 * } catch (e) {
 *   if (CryptoError.isCryptoError(e) && e.is("AuthenticationFailed")) {
 *     // tampered
 *   }
 * }
 * ```
 */
export class CryptoError extends Error {
  /** Always `"CryptoError"`; the cross-copy identity {@link CryptoError.isCryptoError} checks. */
  override readonly name = "CryptoError";
  /** The discriminant; equals `details.code`. */
  readonly code: CryptoErrorCode;
  /** The structured payload, discriminated by `code`. */
  readonly details: CryptoErrorDetails;

  private constructor(message: string, details: CryptoErrorDetails, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.code = details.code;
    this.details = details;
  }

  /** Type guard for a `CryptoError`, including one from another copy of this package. */
  static isCryptoError(value: unknown): value is CryptoError {
    return value instanceof Error && value.name === "CryptoError" && "code" in value;
  }

  /** `true` when `code` is this error's code. */
  is(code: CryptoErrorCode): boolean {
    return this.code === code;
  }

  /** `what` had `actual` bytes; `expected` were required. */
  static invalidSize(what: string, expected: number, actual: number): CryptoError {
    return new CryptoError(`${what} must be ${expected} bytes, got ${actual}`, {
      code: "InvalidSize",
      what,
      expected,
      actual,
    });
  }

  /** `what` has the right length but is not a valid key, point or signature. */
  static invalidData(what: string, message: string, cause?: unknown): CryptoError {
    return new CryptoError(message, { code: "InvalidData", what }, cause);
  }

  /** `what` (a number, an options object or a byte argument) is outside its domain. */
  static invalidParameter(what: string, message: string, cause?: unknown): CryptoError {
    return new CryptoError(message, { code: "InvalidParameter", what }, cause);
  }

  /**
   * The X25519 peer key is a low-order point, so the shared secret would be
   * all zero. The message is the reference's `Error::NonContributoryKey`
   * Display text.
   */
  static nonContributoryKey(cause?: unknown): CryptoError {
    return new CryptoError(
      "X25519 peer key produces an all-zero shared secret",
      { code: "NonContributoryKey", what: "X25519 public key" },
      cause,
    );
  }

  /** AEAD authentication failed (wrong key, nonce, aad, or tampered data). */
  static authenticationFailed(cause?: unknown): CryptoError {
    // The reference's `Error::Aead` displays as "AEAD error".
    return new CryptoError("AEAD error", { code: "AuthenticationFailed" }, cause);
  }
}

/** @internal A short description of a rejected value for `got …` clauses. */
export function describeValue(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return `Array(${value.length})`;
  if (typeof value !== "object") return typeof value;
  const proto = Object.getPrototypeOf(value) as { constructor?: { name?: unknown } } | null;
  const name = proto?.constructor?.name;
  return typeof name === "string" && name !== "" ? name : "object";
}

/**
 * @internal `value` must be a `Uint8Array` (from any realm; a `Buffer` is
 * one). Every byte argument is checked this way before any other precondition,
 * so a string, array or `ArrayBuffer` is `InvalidParameter` naming `what`.
 */
export function requireBytes(what: string, value: unknown): asserts value is Uint8Array {
  if (!isBytes(value)) {
    throw CryptoError.invalidParameter(
      what,
      `${what} must be a Uint8Array, got ${describeValue(value)}`,
    );
  }
}

/**
 * @internal An options argument must be an object. An optional one may be
 * `undefined`; a required one may not.
 */
export function requireOptions(
  what: string,
  value: unknown,
  optional: boolean,
): asserts value is object | undefined {
  if (value === undefined && optional) return;
  if (typeof value !== "object" || value === null) {
    throw CryptoError.invalidParameter(
      what,
      `${what} must be an object, got ${describeValue(value)}`,
    );
  }
}

/** @internal A boolean option: `undefined` (absent) or a boolean. Returns it. */
export function expectBool(what: string, value: unknown): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") {
    throw CryptoError.invalidParameter(
      what,
      `${what} must be a boolean, got ${describeValue(value)}`,
    );
  }
  return value;
}

/**
 * @internal Length precondition shared by the key and signature functions.
 * The type check comes first, so a non-`Uint8Array` is `InvalidParameter`
 * and a wrong length is `InvalidSize`.
 */
export function requireLength(
  what: string,
  bytes: unknown,
  expected: number,
): asserts bytes is Uint8Array {
  requireBytes(what, bytes);
  if (bytes.length !== expected) throw CryptoError.invalidSize(what, expected, bytes.length);
}
