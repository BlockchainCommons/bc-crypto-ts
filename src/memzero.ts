/**
 * Best-effort zeroing of secret buffers.
 *
 * @module memzero
 */
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

/** Overwrite every element with zero. */
export function memzero(data: NumericTypedArray): void {
  data.fill(0);
}

/** {@link memzero} each array. */
export function memzeroAll(arrays: readonly NumericTypedArray[]): void {
  for (const arr of arrays) memzero(arr);
}
