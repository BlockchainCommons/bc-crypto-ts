/**
 * The single error type thrown by this package.
 *
 * @module error
 */

/** Machine-readable discriminant for a {@link CryptoError}. */
export type CryptoErrorCode =
  "InvalidSize" | "InvalidData" | "AuthenticationFailed" | "Unsupported";

/** The structured payload each code carries. */
export interface CryptoErrorDetailsByCode {
  InvalidSize: { readonly what: string; readonly expected: number; readonly actual: number };
  InvalidData: { readonly what: string };
  AuthenticationFailed: unknown;
  Unsupported: unknown;
}

/** A {@link CryptoError} whose `details` are discriminated by its `code`. */
export type CryptoErrorTyped<C extends CryptoErrorCode = CryptoErrorCode> =
  C extends CryptoErrorCode
    ? CryptoError & { readonly code: C; readonly details: Readonly<CryptoErrorDetailsByCode[C]> }
    : never;

const captureStackTrace = (
  Error as unknown as { captureStackTrace?: (target: object, ctor: unknown) => void }
).captureStackTrace;

/**
 * Thrown for wrong-length keys, nonces, signatures and public keys
 * (`InvalidSize`), malformed input (`InvalidData`), AEAD tag mismatch
 * (`AuthenticationFailed`), and unsupported parameters (`Unsupported`).
 */
export class CryptoError extends Error {
  readonly code: CryptoErrorCode;
  readonly details: unknown;

  constructor(
    code: CryptoErrorCode,
    message: string,
    details: unknown = undefined,
    cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "CryptoError";
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
    if (typeof captureStackTrace === "function") captureStackTrace(this, CryptoError);
  }

  /** Type guard narrowing to the code-discriminated union. */
  static isCryptoError(value: unknown): value is CryptoErrorTyped {
    return value instanceof CryptoError;
  }

  /** `what` had `actual` bytes; `expected` were required. */
  static invalidSize(
    what: string,
    expected: number,
    actual: number,
  ): CryptoErrorTyped<"InvalidSize"> {
    return new CryptoError("InvalidSize", `${what} must be ${expected} bytes, got ${actual}`, {
      what,
      expected,
      actual,
    }) as CryptoErrorTyped<"InvalidSize">;
  }

  static invalidData(what: string, message: string): CryptoErrorTyped<"InvalidData"> {
    return new CryptoError("InvalidData", message, { what }) as CryptoErrorTyped<"InvalidData">;
  }

  /** AEAD authentication failed (wrong key, nonce, aad, or tampered data). */
  static authenticationFailed(cause?: unknown): CryptoErrorTyped<"AuthenticationFailed"> {
    return new CryptoError(
      "AuthenticationFailed",
      "AEAD authentication failed",
      undefined,
      cause,
    ) as CryptoErrorTyped<"AuthenticationFailed">;
  }

  static unsupported(message: string): CryptoErrorTyped<"Unsupported"> {
    return new CryptoError("Unsupported", message) as CryptoErrorTyped<"Unsupported">;
  }
}

/** @internal Length precondition shared by the key and signature functions. */
export function requireLength(what: string, bytes: Uint8Array, expected: number): void {
  if (bytes.length !== expected) throw CryptoError.invalidSize(what, expected, bytes.length);
}
