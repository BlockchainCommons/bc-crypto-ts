//#region src/widening.ts
/**
* Performs wide multiplication for unsigned integers.
* Returns (low, high) parts of the full-width result.
*
* This is equivalent to Rust's widening_mul for unsigned types.
*/
function wideMul(a, b, bits) {
	const mask = (1n << BigInt(bits)) - 1n;
	const wide = (a & mask) * (b & mask);
	return [wide & mask, wide >> BigInt(bits)];
}
/**
* Wide multiplication for 8-bit unsigned integers.
* @param a - First 8-bit value
* @param b - Second 8-bit value
* @returns Tuple of (low 8 bits, high 8 bits)
*/
function wideMulU8(a, b) {
	const wide = (a & 255) * (b & 255);
	return [wide & 255, wide >> 8 & 255];
}
/**
* Wide multiplication for 16-bit unsigned integers.
* @param a - First 16-bit value
* @param b - Second 16-bit value
* @returns Tuple of (low 16 bits, high 16 bits)
*/
function wideMulU16(a, b) {
	const wide = (a & 65535) * (b & 65535);
	return [wide & 65535, wide >>> 16 & 65535];
}
/**
* Wide multiplication for 32-bit unsigned integers.
* @param a - First 32-bit value
* @param b - Second 32-bit value
* @returns Tuple of (low 32 bits, high 32 bits) as bigints
*/
function wideMulU32(a, b) {
	const wide = BigInt(a >>> 0) * BigInt(b >>> 0);
	return [wide & 4294967295n, wide >> 32n];
}
/**
* Wide multiplication for 64-bit unsigned integers.
* @param a - First 64-bit value as bigint
* @param b - Second 64-bit value as bigint
* @returns Tuple of (low 64 bits, high 64 bits) as bigints
*/
function wideMulU64(a, b) {
	const mask64 = 18446744073709551615n;
	const wide = (a & mask64) * (b & mask64);
	return [wide & mask64, wide >> 64n];
}
//#endregion
//#region src/magnitude.ts
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
function toMagnitude(value, bits) {
	switch (bits) {
		case 8: {
			const i8Value = value << 24 >> 24;
			return Math.abs(i8Value) & 255;
		}
		case 16: {
			const i16Value = value << 16 >> 16;
			return Math.abs(i16Value) & 65535;
		}
		case 32: {
			const i32Value = value | 0;
			if (i32Value === -2147483648) return 2147483648;
			return Math.abs(i32Value) >>> 0;
		}
	}
}
/**
* Converts a signed bigint to its unsigned magnitude for 64-bit values.
*/
function toMagnitude64(value) {
	const mask = 18446744073709551615n;
	if (value < 0n) return -value & mask;
	return value & mask;
}
/**
* Converts an unsigned magnitude back to a signed value.
* Simply reinterprets the bits.
*/
function fromMagnitude(magnitude, bits) {
	switch (bits) {
		case 8: return magnitude << 24 >> 24;
		case 16: return magnitude << 16 >> 16;
		case 32: return magnitude | 0;
	}
}
/**
* Converts an unsigned 64-bit magnitude back to a signed bigint.
*/
function fromMagnitude64(magnitude) {
	const mask = 18446744073709551615n;
	const signBit = 1n << 63n;
	const maskedMag = magnitude & mask;
	if ((maskedMag & signBit) !== 0n) return maskedMag - (1n << 64n);
	return maskedMag;
}
//#endregion
//#region src/random-number-generator.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
/**
* Returns a Uint8Array of random bytes of the given size.
*/
function rngRandomData(rng, size) {
	const data = new Uint8Array(size);
	rng.fillRandomData(data);
	return data;
}
/**
* Fills the given Uint8Array with random bytes.
*/
function rngFillRandomData(rng, data) {
	rng.fillRandomData(data);
}
/**
* Returns a random `u8` value strictly less than `upperBound`.
*/
function rngNextWithUpperBoundU8(rng, upperBound) {
	if (upperBound === 0) throw new Error("upperBound must be non-zero");
	const ub = upperBound & 255;
	let random = Number(rng.nextU64() & 255n);
	let m = wideMulU8(random, ub);
	if (m[0] < ub) {
		const t = (256 - ub & 255) % ub;
		while (m[0] < t) {
			random = Number(rng.nextU64() & 255n);
			m = wideMulU8(random, ub);
		}
	}
	return m[1];
}
/**
* Returns a random `u16` value strictly less than `upperBound`.
*/
function rngNextWithUpperBoundU16(rng, upperBound) {
	if (upperBound === 0) throw new Error("upperBound must be non-zero");
	const ub = upperBound & 65535;
	let random = Number(rng.nextU64() & 65535n);
	let m = wideMulU16(random, ub);
	if (m[0] < ub) {
		const t = (65536 - ub & 65535) % ub;
		while (m[0] < t) {
			random = Number(rng.nextU64() & 65535n);
			m = wideMulU16(random, ub);
		}
	}
	return m[1];
}
/**
* Returns a random `u32` value strictly less than `upperBound`.
*/
function rngNextWithUpperBoundU32(rng, upperBound) {
	if (upperBound === 0) throw new Error("upperBound must be non-zero");
	const ub = upperBound >>> 0;
	let random = Number(rng.nextU64() & 4294967295n);
	let m = wideMulU32(random, ub);
	if (Number(m[0]) < ub) {
		const t = (4294967296 - ub >>> 0) % ub;
		while (Number(m[0]) < t) {
			random = Number(rng.nextU64() & 4294967295n);
			m = wideMulU32(random, ub);
		}
	}
	return Number(m[1]);
}
/**
* Returns a random `u64` value strictly less than `upperBound`.
*/
function rngNextWithUpperBoundU64(rng, upperBound) {
	if (upperBound === 0n) throw new Error("upperBound must be non-zero");
	const mask64 = 18446744073709551615n;
	const ub = upperBound & mask64;
	let random = rng.nextU64() & mask64;
	let m = wideMulU64(random, ub);
	if (m[0] < ub) {
		const t = (18446744073709551616n - ub & mask64) % ub;
		while (m[0] < t) {
			random = rng.nextU64() & mask64;
			m = wideMulU64(random, ub);
		}
	}
	return m[1];
}
/**
* Alias of `rngNextWithUpperBoundU64`. Kept for API backwards compatibility.
*
* @deprecated Prefer the explicit-width name `rngNextWithUpperBoundU64`.
*/
const rngNextWithUpperBound = rngNextWithUpperBoundU64;
function fromU64ThrowsIfAbove(value, max) {
	if (value > max) throw new Error("from_u64 conversion overflow");
	return value;
}
/** Random `u8` in the half-open range [start, end). */
function rngNextInRangeU8(rng, start, end) {
	if (start >= end) throw new Error("start must be less than end");
	const lo = start & 255;
	const delta = (end & 255) - lo & 255;
	if (delta === 255) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 255n));
	return lo + rngNextWithUpperBoundU8(rng, delta) & 255;
}
/** Random `u16` in the half-open range [start, end). */
function rngNextInRangeU16(rng, start, end) {
	if (start >= end) throw new Error("start must be less than end");
	const lo = start & 65535;
	const delta = (end & 65535) - lo & 65535;
	if (delta === 65535) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 65535n));
	return lo + rngNextWithUpperBoundU16(rng, delta) & 65535;
}
/** Random `u32` in the half-open range [start, end). */
function rngNextInRangeU32(rng, start, end) {
	if (start >= end) throw new Error("start must be less than end");
	const lo = start >>> 0;
	const delta = (end >>> 0) - lo >>> 0;
	if (delta === 4294967295) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 4294967295n));
	return lo + rngNextWithUpperBoundU32(rng, delta) >>> 0;
}
/** Random `u64` in the half-open range [start, end). */
function rngNextInRangeU64(rng, start, end) {
	if (start >= end) throw new Error("start must be less than end");
	const mask64 = 18446744073709551615n;
	const delta = end - start & mask64;
	if (delta === mask64) return rng.nextU64();
	return start + rngNextWithUpperBoundU64(rng, delta) & mask64;
}
/**
* Alias of `rngNextInRangeU64`. Kept for API backwards compatibility.
*
* @deprecated Prefer the explicit-width name `rngNextInRangeU64`.
*/
const rngNextInRange = rngNextInRangeU64;
/** Random `i8` in the half-open range [start, end). */
function rngNextInRangeI8(rng, start, end) {
	if (start >= end) throw new Error("start must be less than end");
	const lo = start << 24 >> 24;
	const delta = toMagnitude((end << 24 >> 24) - lo, 8);
	if (delta === 255) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 127n));
	return lo + rngNextWithUpperBoundU8(rng, delta) << 24 >> 24;
}
/** Random `i16` in the half-open range [start, end). */
function rngNextInRangeI16(rng, start, end) {
	if (start >= end) throw new Error("start must be less than end");
	const lo = start << 16 >> 16;
	const delta = toMagnitude((end << 16 >> 16) - lo, 16);
	if (delta === 65535) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 32767n));
	return lo + rngNextWithUpperBoundU16(rng, delta) << 16 >> 16;
}
/** Random `i32` in the half-open range [start, end). */
function rngNextInRangeI32(rng, start, end) {
	if (start >= end) throw new Error("start must be less than end");
	const lo = start | 0;
	const delta = toMagnitude((end | 0) - lo, 32);
	if (delta === 4294967295) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 2147483647n));
	return lo + rngNextWithUpperBoundU32(rng, delta) | 0;
}
/** Random `i64` in the half-open range [start, end). */
function rngNextInRangeI64(rng, start, end) {
	if (start >= end) throw new Error("start must be less than end");
	const delta = toMagnitude64(end - start);
	const mask64 = 18446744073709551615n;
	if (delta === mask64) return fromU64ThrowsIfAbove(rng.nextU64(), 9223372036854775807n);
	const random = rngNextWithUpperBoundU64(rng, delta);
	return fromMagnitude64(toMagnitude64(start) + random & mask64);
}
/** Random `u8` in the closed range [start, end]. */
function rngNextInClosedRangeU8(rng, start, end) {
	if (start > end) throw new Error("start must be less than or equal to end");
	const lo = start & 255;
	const delta = (end & 255) - lo & 255;
	if (delta === 255) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 255n));
	return lo + rngNextWithUpperBoundU8(rng, delta + 1) & 255;
}
/** Random `u16` in the closed range [start, end]. */
function rngNextInClosedRangeU16(rng, start, end) {
	if (start > end) throw new Error("start must be less than or equal to end");
	const lo = start & 65535;
	const delta = (end & 65535) - lo & 65535;
	if (delta === 65535) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 65535n));
	return lo + rngNextWithUpperBoundU16(rng, delta + 1) & 65535;
}
/** Random `u32` in the closed range [start, end]. */
function rngNextInClosedRangeU32(rng, start, end) {
	if (start > end) throw new Error("start must be less than or equal to end");
	const lo = start >>> 0;
	const delta = (end >>> 0) - lo >>> 0;
	if (delta === 4294967295) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 4294967295n));
	return lo + rngNextWithUpperBoundU32(rng, delta + 1) >>> 0;
}
/** Random `u64` in the closed range [start, end]. */
function rngNextInClosedRangeU64(rng, start, end) {
	if (start > end) throw new Error("start must be less than or equal to end");
	const mask64 = 18446744073709551615n;
	const delta = end - start & mask64;
	if (delta === mask64) return rng.nextU64();
	return start + rngNextWithUpperBoundU64(rng, delta + 1n) & mask64;
}
/**
* Alias of `rngNextInClosedRangeU64`. Kept for API backwards compatibility.
*
* @deprecated Prefer the explicit-width name `rngNextInClosedRangeU64`.
*/
const rngNextInClosedRange = rngNextInClosedRangeU64;
/** Random `i8` in the closed range [start, end]. */
function rngNextInClosedRangeI8(rng, start, end) {
	if (start > end) throw new Error("start must be less than or equal to end");
	const lo = start << 24 >> 24;
	const delta = toMagnitude((end << 24 >> 24) - lo, 8);
	if (delta === 255) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 127n));
	return lo + rngNextWithUpperBoundU8(rng, delta + 1) << 24 >> 24;
}
/** Random `i16` in the closed range [start, end]. */
function rngNextInClosedRangeI16(rng, start, end) {
	if (start > end) throw new Error("start must be less than or equal to end");
	const lo = start << 16 >> 16;
	const delta = toMagnitude((end << 16 >> 16) - lo, 16);
	if (delta === 65535) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 32767n));
	return lo + rngNextWithUpperBoundU16(rng, delta + 1) << 16 >> 16;
}
/** Random `i32` in the closed range [start, end]. */
function rngNextInClosedRangeI32(rng, start, end) {
	if (start > end) throw new Error("start must be less than or equal to end");
	const lo = start | 0;
	const delta = toMagnitude((end | 0) - lo, 32);
	if (delta === 4294967295) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 2147483647n));
	return lo + rngNextWithUpperBoundU32(rng, delta + 1) | 0;
}
/** Random `i64` in the closed range [start, end]. */
function rngNextInClosedRangeI64(rng, start, end) {
	if (start > end) throw new Error("start must be less than or equal to end");
	const delta = toMagnitude64(end - start);
	const mask64 = 18446744073709551615n;
	if (delta === mask64) return fromU64ThrowsIfAbove(rng.nextU64(), 9223372036854775807n);
	const random = rngNextWithUpperBoundU64(rng, delta + 1n);
	return fromMagnitude64(toMagnitude64(start) + random & mask64);
}
/**
* Returns a random fixed-size byte array.
*
* Mirrors Rust's `rng_random_array<const N: usize>()` but takes the size at
* runtime since JavaScript lacks const generics.
*/
function rngRandomArray(rng, size) {
	const data = new Uint8Array(size);
	rng.fillRandomData(data);
	return data;
}
/**
* Returns a random boolean. Mirrors Rust's `rng_random_bool` which tests
* whether `next_u32()` is a multiple of 2.
*/
function rngRandomBool(rng) {
	return (rng.nextU32() & 1) === 0;
}
/**
* Returns a random 32-bit unsigned integer.
*/
function rngRandomU32(rng) {
	return rng.nextU32();
}
//#endregion
//#region src/secure-random.ts
/**
* Returns the Web Crypto API for the current environment. Available natively
* in browsers and in Node.js >= 15 via `globalThis.crypto`.
*/
function getCrypto() {
	if (typeof globalThis !== "undefined" && globalThis.crypto != null) return globalThis.crypto;
	throw new Error("No crypto API available in this environment");
}
/**
* Generate a Uint8Array of cryptographically strong random bytes of the given size.
*/
function randomData(size) {
	const data = new Uint8Array(size);
	fillRandomData(data);
	return data;
}
/**
* Fill the given Uint8Array with cryptographically strong random bytes.
*/
function fillRandomData(data) {
	getCrypto().getRandomValues(data);
}
/**
* Returns the next cryptographically strong random 64-bit unsigned integer.
*
* This mirrors Rust's module-private `secure_random::next_u64()` and is not
* re-exported from the package surface (matches Rust `lib.rs` behavior).
*/
function nextU64() {
	const data = /* @__PURE__ */ new Uint8Array(8);
	fillRandomData(data);
	return new DataView(data.buffer).getBigUint64(0, true);
}
/**
* A random number generator that can be used as a source of
* cryptographically-strong randomness.
*
* Uses the Web Crypto API (crypto.getRandomValues) which is available
* in both browsers and Node.js >= 15.
*/
var SecureRandomNumberGenerator = class {
	/**
	* Returns the next random 32-bit unsigned integer.
	*
	* Mirrors Rust's `next_u32` impl which returns `next_u64() as u32` —
	* the low 32 bits of a 64-bit draw.
	*/
	nextU32() {
		return Number(this.nextU64() & 4294967295n) >>> 0;
	}
	/**
	* Returns the next random 64-bit unsigned integer as a bigint.
	*/
	nextU64() {
		return nextU64();
	}
	/**
	* Fills the given Uint8Array with random bytes.
	*/
	fillBytes(dest) {
		fillRandomData(dest);
	}
	/**
	* Returns a Uint8Array of random bytes of the given size.
	*/
	randomData(size) {
		return randomData(size);
	}
	/**
	* Fills the given Uint8Array with random bytes.
	*/
	fillRandomData(data) {
		fillRandomData(data);
	}
};
/**
* Returns a thread-local cryptographically-strong RNG. Mirrors Rust's
* `thread_rng()`. In TypeScript there are no thread-locals, so this returns
* a fresh `SecureRandomNumberGenerator` — every instance backs onto the
* same Web Crypto source, so the effect is equivalent.
*/
function threadRng() {
	return new SecureRandomNumberGenerator();
}
//#endregion
//#region src/seeded-random.ts
/**
* Rotate left for 64-bit bigint
*/
function rotl(x, k) {
	return (x << BigInt(k) | x >> BigInt(64 - k)) & 18446744073709551615n;
}
/**
* Xoshiro256** PRNG implementation
* This is the same algorithm used by rand_xoshiro in Rust
*/
function xoshiro256StarStar(state) {
	const mask = 18446744073709551615n;
	const result = rotl(state.s1 * 5n & mask, 7) * 9n & mask;
	const t = state.s1 << 17n & mask;
	state.s2 ^= state.s0;
	state.s3 ^= state.s1;
	state.s1 ^= state.s2;
	state.s0 ^= state.s3;
	state.s2 ^= t;
	state.s3 = rotl(state.s3, 45);
	return result;
}
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
var SeededRandomNumberGenerator = class {
	state;
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
	constructor(seed) {
		this.state = {
			s0: seed[0] & 18446744073709551615n,
			s1: seed[1] & 18446744073709551615n,
			s2: seed[2] & 18446744073709551615n,
			s3: seed[3] & 18446744073709551615n
		};
	}
	/**
	* Returns the next random 64-bit unsigned integer as a bigint.
	*/
	nextU64() {
		return xoshiro256StarStar(this.state);
	}
	/**
	* Returns the next random 32-bit unsigned integer.
	*/
	nextU32() {
		return Number(this.nextU64() & 4294967295n) >>> 0;
	}
	/**
	* Fills the given Uint8Array with random bytes.
	*
	* Note: This implementation matches the Rust behavior exactly -
	* it uses one nextU64() call per byte (taking only the low byte),
	* which matches the Swift version's behavior.
	*/
	fillBytes(dest) {
		for (let i = 0; i < dest.length; i++) dest[i] = Number(this.nextU64() & 255n);
	}
	/**
	* Returns a Uint8Array of random bytes of the given size.
	*
	* This might not be the most efficient implementation,
	* but it works the same as the Swift version.
	*/
	randomData(size) {
		const data = new Uint8Array(size);
		for (let i = 0; i < size; i++) data[i] = Number(this.nextU64() & 255n);
		return data;
	}
	/**
	* Fills the given Uint8Array with random bytes.
	*/
	fillRandomData(data) {
		this.fillBytes(data);
	}
};
/**
* Standard test seed for `makeFakeRandomNumberGenerator`. Module-private to
* mirror Rust where the equivalent constant lives inside `mod tests`.
*/
const TEST_SEED = [
	17295166580085024720n,
	422929670265678780n,
	5577237070365765850n,
	7953171132032326923n
];
/**
* Creates a seeded random number generator with a fixed seed.
* This is useful for reproducible testing across different platforms.
*/
function makeFakeRandomNumberGenerator() {
	return new SeededRandomNumberGenerator(TEST_SEED);
}
/**
* Creates a Uint8Array of random data with a fixed seed.
* This is useful for reproducible testing.
*
* @param size - The number of bytes to generate
* @returns A Uint8Array of pseudo-random bytes
*/
function fakeRandomData(size) {
	return makeFakeRandomNumberGenerator().randomData(size);
}
//#endregion
export { SecureRandomNumberGenerator, SeededRandomNumberGenerator, fakeRandomData, fillRandomData, fromMagnitude, fromMagnitude64, makeFakeRandomNumberGenerator, randomData, rngFillRandomData, rngNextInClosedRange, rngNextInClosedRangeI16, rngNextInClosedRangeI32, rngNextInClosedRangeI64, rngNextInClosedRangeI8, rngNextInClosedRangeU16, rngNextInClosedRangeU32, rngNextInClosedRangeU64, rngNextInClosedRangeU8, rngNextInRange, rngNextInRangeI16, rngNextInRangeI32, rngNextInRangeI64, rngNextInRangeI8, rngNextInRangeU16, rngNextInRangeU32, rngNextInRangeU64, rngNextInRangeU8, rngNextWithUpperBound, rngNextWithUpperBoundU16, rngNextWithUpperBoundU32, rngNextWithUpperBoundU64, rngNextWithUpperBoundU8, rngRandomArray, rngRandomBool, rngRandomData, rngRandomU32, threadRng, toMagnitude, toMagnitude64, wideMul, wideMulU16, wideMulU32, wideMulU64, wideMulU8 };

