/**
 * Best-effort zeroing of secret buffers.
 *
 * @module memzero
 */
import { CryptoError, describeValue } from "./error.js";

/** The typed arrays {@link memzero} zeroes: every numeric kind, not `BigInt64Array`/`BigUint64Array` or a `DataView`. */
export type NumericTypedArray =
  | Uint8Array
  | Uint8ClampedArray
  | Uint16Array
  | Uint32Array
  | Int8Array
  | Int16Array
  | Int32Array
  | Float32Array
  | Float64Array;

// Cross-realm safe: the tag comes from `Symbol.toStringTag`, not from `instanceof`.
const NUMERIC_TYPED_ARRAY_TAGS = new Set([
  "[object Uint8Array]",
  "[object Uint8ClampedArray]",
  "[object Uint16Array]",
  "[object Uint32Array]",
  "[object Int8Array]",
  "[object Int16Array]",
  "[object Int32Array]",
  "[object Float32Array]",
  "[object Float64Array]",
]);

function requireNumericTypedArray(
  what: string,
  value: unknown,
): asserts value is NumericTypedArray {
  if (!NUMERIC_TYPED_ARRAY_TAGS.has(Object.prototype.toString.call(value))) {
    throw CryptoError.invalidParameter(
      what,
      `${what} must be a numeric typed array, got ${describeValue(value)}`,
    );
  }
}

/**
 * Overwrite every element with zero.
 * @throws {CryptoError} `InvalidParameter` unless `data` is a numeric typed array.
 */
export function memzero(data: NumericTypedArray): void {
  requireNumericTypedArray("memzero data", data);
  data.fill(0);
}

/**
 * {@link memzero} each array.
 * @throws {CryptoError} `InvalidParameter` unless `arrays` is an array of numeric typed arrays.
 */
export function memzeroAll(arrays: readonly NumericTypedArray[]): void {
  const list: unknown = arrays;
  if (!Array.isArray(list)) {
    throw CryptoError.invalidParameter(
      "memzeroAll arrays",
      `memzeroAll arrays must be an array, got ${describeValue(list)}`,
    );
  }
  for (const arr of list as readonly unknown[]) memzero(arr as NumericTypedArray);
}
