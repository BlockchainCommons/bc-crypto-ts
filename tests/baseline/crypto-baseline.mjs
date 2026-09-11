import { sha256 as sha256$1, sha512 as sha512$1 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { scrypt as scrypt$1 } from "@noble/hashes/scrypt.js";
import { argon2id as argon2id$1 } from "@noble/hashes/argon2.js";

//#region \0rolldown/runtime.js
var __defProp = Object.defineProperty;
var __exportAll = (all, no_symbols) => {
	let target = {};
	for (var name in all) {
		__defProp(target, name, {
			get: all[name],
			enumerable: true
		});
	}
	if (!no_symbols) {
		__defProp(target, Symbol.toStringTag, { value: "Module" });
	}
	return target;
};

//#endregion
//#region src/hash.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
var hash_exports = /* @__PURE__ */ __exportAll({
	CRC32_SIZE: () => 4,
	SHA256_SIZE: () => 32,
	SHA512_SIZE: () => 64,
	crc32: () => crc32,
	crc32Data: () => crc32Data,
	crc32DataOpt: () => crc32DataOpt,
	doubleSha256: () => doubleSha256,
	hkdfHmacSha256: () => hkdfHmacSha256,
	hkdfHmacSha512: () => hkdfHmacSha512,
	hmacSha256: () => hmacSha256,
	hmacSha512: () => hmacSha512,
	pbkdf2HmacSha256: () => pbkdf2HmacSha256,
	pbkdf2HmacSha512: () => pbkdf2HmacSha512,
	sha256: () => sha256,
	sha512: () => sha512
});
const CRC32_SIZE = 4;
const SHA256_SIZE = 32;
const SHA512_SIZE = 64;
const CRC32_TABLE = /* @__PURE__ */ new Uint32Array(256);
for (let i = 0; i < 256; i++) {
	let crc = i;
	for (let j = 0; j < 8; j++) crc = (crc & 1) !== 0 ? crc >>> 1 ^ 3988292384 : crc >>> 1;
	CRC32_TABLE[i] = crc >>> 0;
}
/**
* Calculate CRC-32 checksum
*/
function crc32(data) {
	let crc = 4294967295;
	for (const byte of data) crc = CRC32_TABLE[(crc ^ byte) & 255] ^ crc >>> 8;
	return (crc ^ 4294967295) >>> 0;
}
/**
* Calculate CRC-32 checksum and return as a 4-byte big-endian array
*/
function crc32Data(data) {
	return crc32DataOpt(data, false);
}
/**
* Calculate CRC-32 checksum and return as a 4-byte array
* @param data - Input data
* @param littleEndian - If true, returns little-endian; otherwise big-endian
*/
function crc32DataOpt(data, littleEndian) {
	const checksum = crc32(data);
	const result = /* @__PURE__ */ new Uint8Array(4);
	new DataView(result.buffer).setUint32(0, checksum, littleEndian);
	return result;
}
/**
* Calculate SHA-256 hash
*/
function sha256(data) {
	return sha256$1(data);
}
/**
* Calculate double SHA-256 hash (SHA-256 of SHA-256)
* This is the standard Bitcoin hashing function
*/
function doubleSha256(message) {
	return sha256(sha256(message));
}
/**
* Calculate SHA-512 hash
*/
function sha512(data) {
	return sha512$1(data);
}
/**
* Calculate HMAC-SHA-256
*/
function hmacSha256(key, message) {
	return hmac(sha256$1, key, message);
}
/**
* Calculate HMAC-SHA-512
*/
function hmacSha512(key, message) {
	return hmac(sha512$1, key, message);
}
/**
* Derive a key using PBKDF2 with HMAC-SHA-256
*/
function pbkdf2HmacSha256(password, salt, iterations, keyLen) {
	return pbkdf2(sha256$1, password, salt, {
		c: iterations,
		dkLen: keyLen
	});
}
/**
* Derive a key using PBKDF2 with HMAC-SHA-512
*/
function pbkdf2HmacSha512(password, salt, iterations, keyLen) {
	return pbkdf2(sha512$1, password, salt, {
		c: iterations,
		dkLen: keyLen
	});
}
/**
* Derive a key using HKDF with HMAC-SHA-256
*/
function hkdfHmacSha256(keyMaterial, salt, keyLen) {
	return hkdf(sha256$1, keyMaterial, salt, void 0, keyLen);
}
/**
* Derive a key using HKDF with HMAC-SHA-512
*/
function hkdfHmacSha512(keyMaterial, salt, keyLen) {
	return hkdf(sha512$1, keyMaterial, salt, void 0, keyLen);
}

//#endregion
//#region src/error.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
/**
* AEAD-specific error for authentication failures
*/
var AeadError = class extends Error {
	constructor(message = "AEAD authentication failed") {
		super(message);
		this.name = "AeadError";
	}
};
/**
* Generic crypto error type
*/
var CryptoError = class CryptoError extends Error {
	cause;
	constructor(message, cause) {
		super(message);
		this.name = "CryptoError";
		this.cause = cause;
	}
	/**
	* Create a CryptoError for AEAD authentication failures.
	*
	* @param error - Optional underlying AeadError
	* @returns A CryptoError wrapping the AEAD error
	*/
	static aead(error) {
		return new CryptoError("AEAD error", error ?? new AeadError());
	}
	/**
	* Create a CryptoError for invalid parameter values.
	*
	* **TS-specific.** Rust's `bc_crypto::Error` enum has no
	* `InvalidParameter` variant; size validation in Rust is enforced at
	* compile time via fixed-size array references (e.g. `&[u8; 32]`) or
	* via `panic!`/`expect(...)` for runtime checks. The TS port has no
	* fixed-size array types, so it surfaces those same conditions through
	* a thrown `CryptoError.invalidParameter(...)`. Catching this is
	* equivalent to defensive guards around an `expect`-style panic on the
	* Rust side.
	*
	* @param message - Description of the invalid parameter
	* @returns A CryptoError describing the invalid parameter
	*/
	static invalidParameter(message) {
		return new CryptoError(`Invalid parameter: ${message}`);
	}
};

//#endregion
//#region src/memzero.ts
/**
* Securely zero out a typed array.
*
* Mirrors Rust `bc_crypto::memzero<T>(s: &mut [T])`. The Rust impl uses
* `std::ptr::write_volatile()` to guarantee the writes survive optimization;
* JavaScript has no equivalent primitive, so this is **best-effort** — JIT
* compilers may still elide the loop, though the post-hoc verification
* check forces the engine to keep the writes observable.
*
* For truly sensitive cryptographic operations, consider using the Web
* Crypto API's `crypto.subtle` with non-extractable keys when possible, as
* it provides stronger guarantees than what can be achieved with pure
* JavaScript.
*
* Accepts any of the standard numeric typed arrays — `Uint8Array`,
* `Uint8ClampedArray`, `Uint16Array`, `Uint32Array`, `Int8Array`,
* `Int16Array`, `Int32Array`, `Float32Array`, `Float64Array` — matching
* Rust's generic `&mut [T]`. (`BigInt64Array` / `BigUint64Array` are
* excluded because their elements are `bigint`, not `number`; if that
* support is needed, add a dedicated overload.)
*/
function memzero(data) {
	const len = data.length;
	for (let i = 0; i < len; i++) data[i] = 0;
	if (data.length > 0 && data[0] !== 0) throw new Error("memzero failed");
}
/**
* Securely zero out an array of Uint8Arrays.
*/
function memzeroVecVecU8(arrays) {
	for (const arr of arrays) memzero(arr);
}

//#endregion
//#region src/symmetric-encryption.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
const SYMMETRIC_KEY_SIZE = 32;
const SYMMETRIC_NONCE_SIZE = 12;
const SYMMETRIC_AUTH_SIZE = 16;
/**
* Encrypt data using ChaCha20-Poly1305 AEAD cipher.
*
* **Security Warning**: The nonce MUST be unique for every encryption operation
* with the same key. Reusing a nonce completely breaks the security of the
* encryption scheme and can reveal plaintext.
*
* @param plaintext - The data to encrypt
* @param key - 32-byte encryption key
* @param nonce - 12-byte nonce (MUST be unique per encryption with the same key)
* @returns Tuple of [ciphertext, authTag] where authTag is 16 bytes
* @throws {CryptoError} If key is not 32 bytes or nonce is not 12 bytes
*/
function aeadChaCha20Poly1305Encrypt(plaintext, key, nonce) {
	return aeadChaCha20Poly1305EncryptWithAad(plaintext, key, nonce, /* @__PURE__ */ new Uint8Array(0));
}
/**
* Encrypt data using ChaCha20-Poly1305 AEAD cipher with additional authenticated data.
*
* **Security Warning**: The nonce MUST be unique for every encryption operation
* with the same key. Reusing a nonce completely breaks the security of the
* encryption scheme and can reveal plaintext.
*
* @param plaintext - The data to encrypt
* @param key - 32-byte encryption key
* @param nonce - 12-byte nonce (MUST be unique per encryption with the same key)
* @param aad - Additional authenticated data (not encrypted, but integrity-protected)
* @returns Tuple of [ciphertext, authTag] where authTag is 16 bytes
* @throws {CryptoError} If key is not 32 bytes or nonce is not 12 bytes
*/
function aeadChaCha20Poly1305EncryptWithAad(plaintext, key, nonce, aad) {
	if (key.length !== 32) throw CryptoError.invalidParameter(`Key must be ${32} bytes`);
	if (nonce.length !== 12) throw CryptoError.invalidParameter(`Nonce must be ${12} bytes`);
	const sealed = chacha20poly1305(key, nonce, aad).encrypt(plaintext);
	return [sealed.slice(0, sealed.length - 16), sealed.slice(sealed.length - 16)];
}
/**
* Decrypt data using ChaCha20-Poly1305 AEAD cipher.
*
* @param ciphertext - The encrypted data
* @param key - 32-byte encryption key (must match key used for encryption)
* @param nonce - 12-byte nonce (must match nonce used for encryption)
* @param authTag - 16-byte authentication tag from encryption
* @returns Decrypted plaintext
* @throws {CryptoError} If key/nonce/authTag sizes are invalid
* @throws {CryptoError} If authentication fails (tampered data or wrong key/nonce)
*/
function aeadChaCha20Poly1305Decrypt(ciphertext, key, nonce, authTag) {
	return aeadChaCha20Poly1305DecryptWithAad(ciphertext, key, nonce, /* @__PURE__ */ new Uint8Array(0), authTag);
}
/**
* Decrypt data using ChaCha20-Poly1305 AEAD cipher with additional authenticated data.
*
* @param ciphertext - The encrypted data
* @param key - 32-byte encryption key (must match key used for encryption)
* @param nonce - 12-byte nonce (must match nonce used for encryption)
* @param aad - Additional authenticated data (must exactly match AAD used for encryption)
* @param authTag - 16-byte authentication tag from encryption
* @returns Decrypted plaintext
* @throws {CryptoError} If key/nonce/authTag sizes are invalid
* @throws {CryptoError} If authentication fails (tampered data, wrong key/nonce, or AAD mismatch)
*/
function aeadChaCha20Poly1305DecryptWithAad(ciphertext, key, nonce, aad, authTag) {
	if (key.length !== 32) throw CryptoError.invalidParameter(`Key must be ${32} bytes`);
	if (nonce.length !== 12) throw CryptoError.invalidParameter(`Nonce must be ${12} bytes`);
	if (authTag.length !== 16) throw CryptoError.invalidParameter(`Auth tag must be ${16} bytes`);
	const sealed = new Uint8Array(ciphertext.length + authTag.length);
	sealed.set(ciphertext);
	sealed.set(authTag, ciphertext.length);
	try {
		return chacha20poly1305(key, nonce, aad).decrypt(sealed);
	} catch (error) {
		const aeadError = new AeadError(`Decryption failed: ${error instanceof Error ? error.message : "authentication error"}`);
		throw CryptoError.aead(aeadError);
	}
}

//#endregion
//#region src/public-key-encryption.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
const X25519_PRIVATE_KEY_SIZE = 32;
const X25519_PUBLIC_KEY_SIZE = 32;
/**
* Derive an X25519 agreement private key from key material.
* Uses HKDF with "agreement" as domain separation salt.
*/
function deriveAgreementPrivateKey(keyMaterial) {
	const salt = new TextEncoder().encode("agreement");
	return hkdfHmacSha256(keyMaterial, salt, 32);
}
/**
* Derive a signing private key from key material.
* Uses HKDF with "signing" as domain separation salt.
*/
function deriveSigningPrivateKey(keyMaterial) {
	const salt = new TextEncoder().encode("signing");
	return hkdfHmacSha256(keyMaterial, salt, 32);
}
/**
* Generate a new random X25519 private key.
*/
function x25519NewPrivateKeyUsing(rng) {
	return rng.randomData(32);
}
/**
* Derive an X25519 public key from a private key.
*/
function x25519PublicKeyFromPrivateKey(privateKey) {
	if (privateKey.length !== 32) throw new Error(`Private key must be ${32} bytes`);
	return x25519.getPublicKey(privateKey);
}
const SYMMETRIC_KEY_SIZE$1 = 32;
/**
* Compute a shared symmetric key using X25519 key agreement (ECDH).
*
* This function performs X25519 Diffie-Hellman key agreement and then
* derives a symmetric key using HKDF-SHA256 with "agreement" as the salt.
* This matches the Rust bc-crypto implementation for cross-platform compatibility.
*
* **Low-order public key handling.** The underlying `@noble/curves` X25519
* implementation rejects low-order public keys (where the u-coordinate is
* `0`) by throwing `'invalid private or public key received'`. Rust's
* `x25519-dalek` (v2.0-rc.2) instead silently produces the all-zero shared
* secret. This means an adversarial low-order public key fed in via TS
* surfaces as an exception, while in Rust it would yield an HKDF-derived
* key from a zero shared secret. For honest inputs both implementations
* produce byte-identical results; the TS port's stricter behaviour is a
* security improvement, not a parity bug.
*
* @param x25519Private - 32-byte X25519 private key
* @param x25519Public - 32-byte X25519 public key from the other party
* @returns 32-byte derived symmetric key
* @throws {Error} If private key is not 32 bytes or public key is not 32 bytes
* @throws {Error} If the public key is low-order (`@noble/curves`-specific guard)
*/
function x25519SharedKey(x25519Private, x25519Public) {
	if (x25519Private.length !== 32) throw new Error(`Private key must be ${32} bytes`);
	if (x25519Public.length !== 32) throw new Error(`Public key must be ${32} bytes`);
	const rawSharedSecret = x25519.getSharedSecret(x25519Private, x25519Public);
	const salt = new TextEncoder().encode("agreement");
	return hkdfHmacSha256(rawSharedSecret, salt, SYMMETRIC_KEY_SIZE$1);
}

//#endregion
//#region src/ecdsa-keys.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
const ECDSA_PRIVATE_KEY_SIZE = 32;
const ECDSA_PUBLIC_KEY_SIZE = 33;
const ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
const ECDSA_MESSAGE_HASH_SIZE = 32;
const ECDSA_SIGNATURE_SIZE = 64;
const SCHNORR_PUBLIC_KEY_SIZE = 32;
/**
* Generate a new random ECDSA private key using secp256k1.
*
* Note: Unlike some implementations, this directly returns the random bytes
* without validation. The secp256k1 library will handle any edge cases when
* the key is used.
*/
function ecdsaNewPrivateKeyUsing(rng) {
	return rng.randomData(32);
}
/**
* Derive a compressed ECDSA public key from a private key.
*/
function ecdsaPublicKeyFromPrivateKey(privateKey) {
	if (privateKey.length !== 32) throw new Error(`Private key must be ${32} bytes`);
	return secp256k1.getPublicKey(privateKey, true);
}
/**
* Decompress a compressed public key to uncompressed format.
*/
function ecdsaDecompressPublicKey(compressed) {
	if (compressed.length !== 33) throw new Error(`Compressed public key must be ${33} bytes`);
	return secp256k1.Point.fromBytes(compressed).toBytes(false);
}
/**
* Compress an uncompressed public key.
*/
function ecdsaCompressPublicKey(uncompressed) {
	if (uncompressed.length !== 65) throw new Error(`Uncompressed public key must be ${65} bytes`);
	return secp256k1.Point.fromBytes(uncompressed).toBytes(true);
}
/**
* Derive an ECDSA private key from key material using HKDF.
*
* Note: This directly returns the HKDF output without validation,
* matching the Rust reference implementation behavior.
*/
function ecdsaDerivePrivateKey(keyMaterial) {
	const salt = new TextEncoder().encode("signing");
	return hkdfHmacSha256(keyMaterial, salt, 32);
}
/**
* Extract the x-only (Schnorr) public key from a private key.
* This is used for BIP-340 Schnorr signatures.
*/
function schnorrPublicKeyFromPrivateKey(privateKey) {
	if (privateKey.length !== 32) throw new Error(`Private key must be ${32} bytes`);
	return secp256k1.getPublicKey(privateKey, false).slice(1, 33);
}

//#endregion
//#region src/ecdsa-signing.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
/**
* Sign a message using ECDSA with secp256k1.
*
* The message is hashed with double SHA-256 before signing (Bitcoin standard).
*
* **Security Note**: The private key must be kept secret. ECDSA requires
* cryptographically secure random nonces internally; this is handled by
* the underlying library using RFC 6979 deterministic nonces.
*
* @param privateKey - 32-byte secp256k1 private key
* @param message - Message to sign (any length, will be double-SHA256 hashed)
* @returns 64-byte compact signature (r || s format)
* @throws {Error} If private key is not 32 bytes
*/
function ecdsaSign(privateKey, message) {
	if (privateKey.length !== 32) throw new Error(`Private key must be ${32} bytes`);
	const messageHash = doubleSha256(message);
	return secp256k1.sign(messageHash, privateKey, { prehash: false });
}
/**
* Verify an ECDSA signature with secp256k1.
*
* The message is hashed with double SHA-256 before verification (Bitcoin standard).
*
* @param publicKey - 33-byte compressed secp256k1 public key
* @param signature - 64-byte compact signature (r || s format)
* @param message - Original message that was signed
* @returns `true` if signature is valid, `false` if signature verification fails
* @throws {Error} If public key is not 33 bytes or signature is not 64 bytes
*/
function ecdsaVerify(publicKey, signature, message) {
	if (publicKey.length !== 33) throw new Error(`Public key must be ${33} bytes`);
	if (signature.length !== 64) throw new Error(`Signature must be ${64} bytes`);
	try {
		const messageHash = doubleSha256(message);
		return secp256k1.verify(signature, messageHash, publicKey, { prehash: false });
	} catch {
		return false;
	}
}

//#endregion
//#region ../bc-rand-ts/tests/baseline/rand-baseline.mjs
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

//#endregion
//#region src/schnorr-signing.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
const SCHNORR_SIGNATURE_SIZE = 64;
/**
* Sign a message using Schnorr signature (BIP-340).
* Uses secure random auxiliary randomness.
*
* @param ecdsaPrivateKey - 32-byte private key
* @param message - Message to sign (not pre-hashed, per BIP-340)
* @returns 64-byte Schnorr signature
*/
function schnorrSign(ecdsaPrivateKey, message) {
	return schnorrSignUsing(ecdsaPrivateKey, message, new SecureRandomNumberGenerator());
}
/**
* Sign a message using Schnorr signature with a custom RNG.
*
* @param ecdsaPrivateKey - 32-byte private key
* @param message - Message to sign
* @param rng - Random number generator for auxiliary randomness
* @returns 64-byte Schnorr signature
*/
function schnorrSignUsing(ecdsaPrivateKey, message, rng) {
	return schnorrSignWithAuxRand(ecdsaPrivateKey, message, rng.randomData(32));
}
/**
* Sign a message using Schnorr signature with specific auxiliary randomness.
* This is useful for deterministic signing in tests.
*
* @param ecdsaPrivateKey - 32-byte private key
* @param message - Message to sign
* @param auxRand - 32-byte auxiliary randomness (per BIP-340)
* @returns 64-byte Schnorr signature
*/
function schnorrSignWithAuxRand(ecdsaPrivateKey, message, auxRand) {
	if (ecdsaPrivateKey.length !== 32) throw new Error(`Private key must be ${32} bytes`);
	if (auxRand.length !== 32) throw new Error("Auxiliary randomness must be 32 bytes");
	return schnorr.sign(message, ecdsaPrivateKey, auxRand);
}
/**
* Verify a Schnorr signature (BIP-340).
*
* @param schnorrPublicKey - 32-byte x-only public key
* @param signature - 64-byte Schnorr signature
* @param message - Original message
* @returns true if signature is valid
*/
function schnorrVerify(schnorrPublicKey, signature, message) {
	if (schnorrPublicKey.length !== 32) throw new Error(`Public key must be ${32} bytes`);
	if (signature.length !== 64) throw new Error(`Signature must be ${64} bytes`);
	try {
		return schnorr.verify(signature, message, schnorrPublicKey);
	} catch {
		return false;
	}
}

//#endregion
//#region src/ed25519-signing.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
const ED25519_PUBLIC_KEY_SIZE = 32;
const ED25519_PRIVATE_KEY_SIZE = 32;
const ED25519_SIGNATURE_SIZE = 64;
/**
* Generate a new random Ed25519 private key.
*/
function ed25519NewPrivateKeyUsing(rng) {
	return rng.randomData(32);
}
/**
* Derive an Ed25519 public key from a private key.
*/
function ed25519PublicKeyFromPrivateKey(privateKey) {
	if (privateKey.length !== 32) throw new Error(`Private key must be ${32} bytes`);
	return ed25519.getPublicKey(privateKey);
}
/**
* Sign a message using Ed25519.
*
* **Security Note**: The private key must be kept secret. The same private key
* can safely sign multiple messages.
*
* @param privateKey - 32-byte Ed25519 private key
* @param message - Message to sign (any length)
* @returns 64-byte Ed25519 signature
* @throws {Error} If private key is not 32 bytes
*/
function ed25519Sign(privateKey, message) {
	if (privateKey.length !== 32) throw new Error(`Private key must be ${32} bytes`);
	return ed25519.sign(message, privateKey);
}
/**
* Verify an Ed25519 signature.
*
* @param publicKey - 32-byte Ed25519 public key
* @param message - Original message that was signed
* @param signature - 64-byte Ed25519 signature
* @returns `true` if signature is valid, `false` if signature verification fails
* @throws {Error} If public key is not 32 bytes or signature is not 64 bytes
*/
function ed25519Verify(publicKey, message, signature) {
	if (publicKey.length !== 32) throw new Error(`Public key must be ${32} bytes`);
	if (signature.length !== 64) throw new Error(`Signature must be ${64} bytes`);
	try {
		return ed25519.verify(signature, message, publicKey);
	} catch {
		return false;
	}
}

//#endregion
//#region src/scrypt.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
/**
* Derive a key using Scrypt with recommended parameters.
*
* Mirrors Rust `bc_crypto::scrypt` which calls `scrypt::Params::recommended()`.
* The recommended parameters per the upstream `scrypt` crate are
* `log_n = 17` (N = 2^17 = 131072), `r = 8`, `p = 1`.
*
* @param password - Password or passphrase
* @param salt - Salt value
* @param outputLen - Desired output length
* @returns Derived key
*/
function scrypt(password, salt, outputLen) {
	return scryptOpt(password, salt, outputLen, 17, 8, 1);
}
/**
* Derive a key using Scrypt with custom parameters.
*
* @param password - Password or passphrase
* @param salt - Salt value
* @param outputLen - Desired output length
* @param logN - Log2 of the CPU/memory cost parameter N (must be <64)
* @param r - Block size parameter (must be >0)
* @param p - Parallelization parameter (must be >0)
* @returns Derived key
*/
function scryptOpt(password, salt, outputLen, logN, r, p) {
	if (logN >= 64) throw new Error("logN must be <64");
	if (r === 0) throw new Error("r must be >0");
	if (p === 0) throw new Error("p must be >0");
	const N = 1 << logN;
	return scrypt$1(password, salt, {
		N,
		r,
		p,
		dkLen: outputLen
	});
}

//#endregion
//#region src/argon.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
*
*/
/**
* Derive a key using Argon2id with default parameters.
*
* Mirrors Rust `bc_crypto::argon2id` which calls `Argon2::default()`. The
* upstream `argon2` crate's defaults are `t = 2` iterations, `m = 19 * 1024
* = 19456` KiB of memory, `p = 1` lane (per `argon2-0.5.x/src/params.rs`).
*
* @param password - Password or passphrase
* @param salt - Salt value (must be at least 8 bytes)
* @param outputLen - Desired output length
* @returns Derived key
*/
function argon2id(password, salt, outputLen) {
	return argon2idHashOpt(password, salt, outputLen, 2, 19456, 1);
}
/**
* Derive a key using Argon2id with custom parameters.
*
* @param password - Password or passphrase
* @param salt - Salt value (must be at least 8 bytes)
* @param outputLen - Desired output length
* @param iterations - Number of iterations (t)
* @param memory - Memory in KiB (m)
* @param parallelism - Degree of parallelism (p)
* @returns Derived key
*/
function argon2idHashOpt(password, salt, outputLen, iterations, memory, parallelism) {
	return argon2id$1(password, salt, {
		t: iterations,
		m: memory,
		p: parallelism,
		dkLen: outputLen
	});
}

//#endregion
export { AeadError, CRC32_SIZE, CryptoError, ECDSA_MESSAGE_HASH_SIZE, ECDSA_PRIVATE_KEY_SIZE, ECDSA_PUBLIC_KEY_SIZE, ECDSA_SIGNATURE_SIZE, ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE, ED25519_PRIVATE_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE, SCHNORR_PUBLIC_KEY_SIZE, SCHNORR_SIGNATURE_SIZE, SHA256_SIZE, SHA512_SIZE, SYMMETRIC_AUTH_SIZE, SYMMETRIC_KEY_SIZE, SYMMETRIC_NONCE_SIZE, X25519_PRIVATE_KEY_SIZE, X25519_PUBLIC_KEY_SIZE, aeadChaCha20Poly1305Decrypt, aeadChaCha20Poly1305DecryptWithAad, aeadChaCha20Poly1305Encrypt, aeadChaCha20Poly1305EncryptWithAad, argon2id, deriveAgreementPrivateKey, deriveSigningPrivateKey, doubleSha256, ecdsaCompressPublicKey, ecdsaDecompressPublicKey, ecdsaDerivePrivateKey, ecdsaNewPrivateKeyUsing, ecdsaPublicKeyFromPrivateKey, ecdsaSign, ecdsaVerify, ed25519NewPrivateKeyUsing, ed25519PublicKeyFromPrivateKey, ed25519Sign, ed25519Verify, hash_exports as hash, hkdfHmacSha256, hmacSha256, hmacSha512, memzero, memzeroVecVecU8, pbkdf2HmacSha256, schnorrPublicKeyFromPrivateKey, schnorrSign, schnorrSignUsing, schnorrSignWithAuxRand, schnorrVerify, scrypt, scryptOpt, sha256, sha512, x25519NewPrivateKeyUsing, x25519PublicKeyFromPrivateKey, x25519SharedKey };