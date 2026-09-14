/**
 * Argument-domain checks and the boundary that turns a backend's throw into
 * a {@link CryptoError}.
 *
 * TypeScript has no integer widths: a `u32` parameter is a `number` that must
 * be an integer in `[0, 2^32 - 1]`. Every check names the argument and uses
 * one message shape, `"<what> must be an integer in [<min>, <max>], got <value>"`.
 *
 * @module domain
 */
import { CryptoError } from "./error.js";

/** Throws `InvalidParameter` unless `value` is an integer `number` in `[min, max]`. Returns it. */
export function expectInt(what: string, value: number, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw CryptoError.invalidParameter(
      what,
      `${what} must be an integer in [${min}, ${max}], got ${String(value)}`,
    );
  }
  return value;
}

/** Throws `InvalidParameter` unless `bytes` has at least `min` bytes. Returns it. */
export function expectMinLength(what: string, bytes: Uint8Array, min: number): Uint8Array {
  if (bytes.length < min) {
    throw CryptoError.invalidParameter(
      what,
      `${what} must be at least ${min} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

/**
 * Runs `fn`; a throw that is not already a {@link CryptoError} is replaced by
 * `wrap(cause)`, so no backend error crosses the package boundary.
 */
export function guard<T>(fn: () => T, wrap: (cause: unknown) => CryptoError): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof CryptoError) throw e;
    throw wrap(e);
  }
}

/** The wrap for a KDF backend that rejects parameters the domain checks let through (e.g. scrypt's memory limit). */
export const backendRejected =
  (what: string) =>
  (cause: unknown): CryptoError =>
    CryptoError.invalidParameter(
      what,
      `${what} rejected by the backend: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );

/** The wrap for a point decoder: bytes of the right length that are not a point on the curve. */
export const invalidPoint =
  (what: string) =>
  (cause: unknown): CryptoError =>
    CryptoError.invalidData(what, `${what} is not a point on the curve`, cause);

export const U32_MAX = 0xffffffff;
