/**
 * The single error type thrown by this package.
 *
 * @module error
 */

/** Machine-readable discriminant for a {@link CryptoError}. */
export type CryptoErrorCode =
  "InvalidSize" | "InvalidData" | "InvalidParameter" | "AuthenticationFailed";

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
      /** The argument, e.g. `"X25519 public key"`. */
      readonly what: string;
    }
  | {
      /** A KDF or counter argument outside its domain. */
      readonly code: "InvalidParameter";
      /** The argument, e.g. `"scrypt logN"`. */
      readonly what: string;
    }
  | {
      /** AEAD authentication failed: wrong key, nonce or aad, or tampered data. */
      readonly code: "AuthenticationFailed";
    };

/**
 * Thrown for wrong-length keys, nonces, signatures and public keys
 * (`InvalidSize`), a key, point or signature of the right length that is not
 * valid (`InvalidData`), a KDF or counter argument outside its domain
 * (`InvalidParameter`), and AEAD tag mismatch (`AuthenticationFailed`).
 *
 * Every failure raised by this package is a `CryptoError`; when a backend
 * error is what was caught, it is the `cause`. Instances come from the static
 * factories only.
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

  /** `what` (a KDF or counter argument) is outside its domain. */
  static invalidParameter(what: string, message: string, cause?: unknown): CryptoError {
    return new CryptoError(message, { code: "InvalidParameter", what }, cause);
  }

  /** AEAD authentication failed (wrong key, nonce, aad, or tampered data). */
  static authenticationFailed(cause?: unknown): CryptoError {
    return new CryptoError("AEAD authentication failed", { code: "AuthenticationFailed" }, cause);
  }
}

/** @internal Length precondition shared by the key and signature functions. */
export function requireLength(what: string, bytes: Uint8Array, expected: number): void {
  if (bytes.length !== expected) throw CryptoError.invalidSize(what, expected, bytes.length);
}
