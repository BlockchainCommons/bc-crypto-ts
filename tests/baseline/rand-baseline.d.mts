//#region src/widening.d.ts
/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 */
/**
 * Wide multiplication result type - returns (low, high) parts.
 * For a multiplication of two N-bit values, the result is 2N bits
 * split into two N-bit parts.
 */
type WideMulResult = [bigint, bigint];
/**
 * Performs wide multiplication for unsigned integers.
 * Returns (low, high) parts of the full-width result.
 *
 * This is equivalent to Rust's widening_mul for unsigned types.
 */
declare function wideMul(a: bigint, b: bigint, bits: number): WideMulResult;
/**
 * Wide multiplication for 8-bit unsigned integers.
 * @param a - First 8-bit value
 * @param b - Second 8-bit value
 * @returns Tuple of (low 8 bits, high 8 bits)
 */
declare function wideMulU8(a: number, b: number): [number, number];
/**
 * Wide multiplication for 16-bit unsigned integers.
 * @param a - First 16-bit value
 * @param b - Second 16-bit value
 * @returns Tuple of (low 16 bits, high 16 bits)
 */
declare function wideMulU16(a: number, b: number): [number, number];
/**
 * Wide multiplication for 32-bit unsigned integers.
 * @param a - First 32-bit value
 * @param b - Second 32-bit value
 * @returns Tuple of (low 32 bits, high 32 bits) as bigints
 */
declare function wideMulU32(a: number, b: number): [bigint, bigint];
/**
 * Wide multiplication for 64-bit unsigned integers.
 * @param a - First 64-bit value as bigint
 * @param b - Second 64-bit value as bigint
 * @returns Tuple of (low 64 bits, high 64 bits) as bigints
 */
declare function wideMulU64(a: bigint, b: bigint): [bigint, bigint];
//#endregion
//#region src/magnitude.d.ts
/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 */
/**
 * Converts a signed integer to its unsigned magnitude.
 * For positive numbers, returns the number unchanged.
 * For negative numbers, returns the absolute value (wrapping for MIN values).
 *
 * This matches Rust's wrapping_abs() behavior.
 */
declare function toMagnitude(value: number, bits: 8 | 16 | 32): number;
/**
 * Converts a signed bigint to its unsigned magnitude for 64-bit values.
 */
declare function toMagnitude64(value: bigint): bigint;
/**
 * Converts an unsigned magnitude back to a signed value.
 * Simply reinterprets the bits.
 */
declare function fromMagnitude(magnitude: number, bits: 8 | 16 | 32): number;
/**
 * Converts an unsigned 64-bit magnitude back to a signed bigint.
 */
declare function fromMagnitude64(magnitude: bigint): bigint;
//#endregion
//#region src/random-number-generator.d.ts
/**
 * Interface for random number generators.
 *
 * The TypeScript equivalent of Rust's `RandomNumberGenerator` trait
 * (which extends `RngCore + CryptoRng`).
 */
interface RandomNumberGenerator {
  /** Returns the next random 32-bit unsigned integer. */
  nextU32(): number;
  /** Returns the next random 64-bit unsigned integer as a bigint. */
  nextU64(): bigint;
  /** Fills the given Uint8Array with random bytes. */
  fillBytes(dest: Uint8Array): void;
  /** Returns a Uint8Array of random bytes of the given size. */
  randomData(size: number): Uint8Array;
  /** Fills the given Uint8Array with random bytes. Alias for fillBytes. */
  fillRandomData(data: Uint8Array): void;
}
/**
 * Returns a Uint8Array of random bytes of the given size.
 */
declare function rngRandomData(rng: RandomNumberGenerator, size: number): Uint8Array;
/**
 * Fills the given Uint8Array with random bytes.
 */
declare function rngFillRandomData(rng: RandomNumberGenerator, data: Uint8Array): void;
/**
 * Returns a random `u8` value strictly less than `upperBound`.
 */
declare function rngNextWithUpperBoundU8(rng: RandomNumberGenerator, upperBound: number): number;
/**
 * Returns a random `u16` value strictly less than `upperBound`.
 */
declare function rngNextWithUpperBoundU16(rng: RandomNumberGenerator, upperBound: number): number;
/**
 * Returns a random `u32` value strictly less than `upperBound`.
 */
declare function rngNextWithUpperBoundU32(rng: RandomNumberGenerator, upperBound: number): number;
/**
 * Returns a random `u64` value strictly less than `upperBound`.
 */
declare function rngNextWithUpperBoundU64(rng: RandomNumberGenerator, upperBound: bigint): bigint;
/**
 * Alias of `rngNextWithUpperBoundU64`. Kept for API backwards compatibility.
 *
 * @deprecated Prefer the explicit-width name `rngNextWithUpperBoundU64`.
 */
declare const rngNextWithUpperBound: (rng: RandomNumberGenerator, upperBound: bigint) => bigint;
/** Random `u8` in the half-open range [start, end). */
declare function rngNextInRangeU8(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `u16` in the half-open range [start, end). */
declare function rngNextInRangeU16(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `u32` in the half-open range [start, end). */
declare function rngNextInRangeU32(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `u64` in the half-open range [start, end). */
declare function rngNextInRangeU64(rng: RandomNumberGenerator, start: bigint, end: bigint): bigint;
/**
 * Alias of `rngNextInRangeU64`. Kept for API backwards compatibility.
 *
 * @deprecated Prefer the explicit-width name `rngNextInRangeU64`.
 */
declare const rngNextInRange: (rng: RandomNumberGenerator, start: bigint, end: bigint) => bigint;
/** Random `i8` in the half-open range [start, end). */
declare function rngNextInRangeI8(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `i16` in the half-open range [start, end). */
declare function rngNextInRangeI16(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `i32` in the half-open range [start, end). */
declare function rngNextInRangeI32(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `i64` in the half-open range [start, end). */
declare function rngNextInRangeI64(rng: RandomNumberGenerator, start: bigint, end: bigint): bigint;
/** Random `u8` in the closed range [start, end]. */
declare function rngNextInClosedRangeU8(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `u16` in the closed range [start, end]. */
declare function rngNextInClosedRangeU16(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `u32` in the closed range [start, end]. */
declare function rngNextInClosedRangeU32(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `u64` in the closed range [start, end]. */
declare function rngNextInClosedRangeU64(rng: RandomNumberGenerator, start: bigint, end: bigint): bigint;
/**
 * Alias of `rngNextInClosedRangeU64`. Kept for API backwards compatibility.
 *
 * @deprecated Prefer the explicit-width name `rngNextInClosedRangeU64`.
 */
declare const rngNextInClosedRange: (rng: RandomNumberGenerator, start: bigint, end: bigint) => bigint;
/** Random `i8` in the closed range [start, end]. */
declare function rngNextInClosedRangeI8(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `i16` in the closed range [start, end]. */
declare function rngNextInClosedRangeI16(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `i32` in the closed range [start, end]. */
declare function rngNextInClosedRangeI32(rng: RandomNumberGenerator, start: number, end: number): number;
/** Random `i64` in the closed range [start, end]. */
declare function rngNextInClosedRangeI64(rng: RandomNumberGenerator, start: bigint, end: bigint): bigint;
/**
 * Returns a random fixed-size byte array.
 *
 * Mirrors Rust's `rng_random_array<const N: usize>()` but takes the size at
 * runtime since JavaScript lacks const generics.
 */
declare function rngRandomArray(rng: RandomNumberGenerator, size: number): Uint8Array;
/**
 * Returns a random boolean. Mirrors Rust's `rng_random_bool` which tests
 * whether `next_u32()` is a multiple of 2.
 */
declare function rngRandomBool(rng: RandomNumberGenerator): boolean;
/**
 * Returns a random 32-bit unsigned integer.
 */
declare function rngRandomU32(rng: RandomNumberGenerator): number;
//#endregion
//#region src/secure-random.d.ts
/**
 * Generate a Uint8Array of cryptographically strong random bytes of the given size.
 */
declare function randomData(size: number): Uint8Array;
/**
 * Fill the given Uint8Array with cryptographically strong random bytes.
 */
declare function fillRandomData(data: Uint8Array): void;
/**
 * A random number generator that can be used as a source of
 * cryptographically-strong randomness.
 *
 * Uses the Web Crypto API (crypto.getRandomValues) which is available
 * in both browsers and Node.js >= 15.
 */
declare class SecureRandomNumberGenerator implements RandomNumberGenerator {
  /**
   * Returns the next random 32-bit unsigned integer.
   *
   * Mirrors Rust's `next_u32` impl which returns `next_u64() as u32` —
   * the low 32 bits of a 64-bit draw.
   */
  nextU32(): number;
  /**
   * Returns the next random 64-bit unsigned integer as a bigint.
   */
  nextU64(): bigint;
  /**
   * Fills the given Uint8Array with random bytes.
   */
  fillBytes(dest: Uint8Array): void;
  /**
   * Returns a Uint8Array of random bytes of the given size.
   */
  randomData(size: number): Uint8Array;
  /**
   * Fills the given Uint8Array with random bytes.
   */
  fillRandomData(data: Uint8Array): void;
}
/**
 * Returns a thread-local cryptographically-strong RNG. Mirrors Rust's
 * `thread_rng()`. In TypeScript there are no thread-locals, so this returns
 * a fresh `SecureRandomNumberGenerator` — every instance backs onto the
 * same Web Crypto source, so the effect is equivalent.
 */
declare function threadRng(): SecureRandomNumberGenerator;
//#endregion
//#region src/seeded-random.d.ts
/**
 * A random number generator that can be used as a source of deterministic
 * pseudo-randomness for testing purposes.
 *
 * Uses the Xoshiro256** algorithm, which is the same algorithm used by
 * rand_xoshiro in Rust. This ensures cross-platform compatibility with
 * the Rust implementation.
 *
 * WARNING: This is NOT cryptographically secure and should only be used
 * for testing purposes.
 */
declare class SeededRandomNumberGenerator implements RandomNumberGenerator {
  private readonly state;
  /**
   * Creates a new seeded random number generator.
   *
   * The seed should be a 256-bit value, represented as an array of 4 64-bit
   * integers (as bigints). For the output distribution to look random, the seed
   * should not have any obvious patterns, like all zeroes or all ones.
   *
   * This is not cryptographically secure, and should only be used for
   * testing purposes.
   *
   * @param seed - Array of 4 64-bit unsigned integers as bigints
   */
  constructor(seed: [bigint, bigint, bigint, bigint]);
  /**
   * Returns the next random 64-bit unsigned integer as a bigint.
   */
  nextU64(): bigint;
  /**
   * Returns the next random 32-bit unsigned integer.
   */
  nextU32(): number;
  /**
   * Fills the given Uint8Array with random bytes.
   *
   * Note: This implementation matches the Rust behavior exactly -
   * it uses one nextU64() call per byte (taking only the low byte),
   * which matches the Swift version's behavior.
   */
  fillBytes(dest: Uint8Array): void;
  /**
   * Returns a Uint8Array of random bytes of the given size.
   *
   * This might not be the most efficient implementation,
   * but it works the same as the Swift version.
   */
  randomData(size: number): Uint8Array;
  /**
   * Fills the given Uint8Array with random bytes.
   */
  fillRandomData(data: Uint8Array): void;
}
/**
 * Creates a seeded random number generator with a fixed seed.
 * This is useful for reproducible testing across different platforms.
 */
declare function makeFakeRandomNumberGenerator(): SeededRandomNumberGenerator;
/**
 * Creates a Uint8Array of random data with a fixed seed.
 * This is useful for reproducible testing.
 *
 * @param size - The number of bytes to generate
 * @returns A Uint8Array of pseudo-random bytes
 */
declare function fakeRandomData(size: number): Uint8Array;
//#endregion
export { type RandomNumberGenerator, SecureRandomNumberGenerator, SeededRandomNumberGenerator, type WideMulResult, fakeRandomData, fillRandomData, fromMagnitude, fromMagnitude64, makeFakeRandomNumberGenerator, randomData, rngFillRandomData, rngNextInClosedRange, rngNextInClosedRangeI16, rngNextInClosedRangeI32, rngNextInClosedRangeI64, rngNextInClosedRangeI8, rngNextInClosedRangeU16, rngNextInClosedRangeU32, rngNextInClosedRangeU64, rngNextInClosedRangeU8, rngNextInRange, rngNextInRangeI16, rngNextInRangeI32, rngNextInRangeI64, rngNextInRangeI8, rngNextInRangeU16, rngNextInRangeU32, rngNextInRangeU64, rngNextInRangeU8, rngNextWithUpperBound, rngNextWithUpperBoundU16, rngNextWithUpperBoundU32, rngNextWithUpperBoundU64, rngNextWithUpperBoundU8, rngRandomArray, rngRandomBool, rngRandomData, rngRandomU32, threadRng, toMagnitude, toMagnitude64, wideMul, wideMulU16, wideMulU32, wideMulU64, wideMulU8 };
//# sourceMappingURL=index.d.mts.map