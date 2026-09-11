import { RandomNumberGenerator, RngOptions, RngOptions as RngOptions$1 } from "@blockchaincommons/rand";
//#region src/error.d.ts
/**
 * The single error type thrown by this package.
 *
 * @module error
 */
/** Machine-readable discriminant for a {@link CryptoError}. */
type CryptoErrorCode = "InvalidSize" | "InvalidData" | "InvalidParameter" | "AuthenticationFailed";
/**
 * The structured payload of a {@link CryptoError}, discriminated by `code`:
 * `e.details.code === "InvalidSize"` narrows to `{ what, expected, actual }`.
 */
type CryptoErrorDetails = {
  /** A key, nonce, signature, tag or sealed buffer had the wrong length. */
  readonly code: "InvalidSize";
  /** The argument, e.g. `"ECDSA private key"`. */
  readonly what: string;
  /** The required length in bytes. */
  readonly expected: number;
  /** The length received. */
  readonly actual: number;
} | {
  /** A key, point or signature of the right length that is not valid. */
  readonly code: "InvalidData";
  /** The argument, e.g. `"X25519 public key"`. */
  readonly what: string;
} | {
  /** A KDF or counter argument outside its domain. */
  readonly code: "InvalidParameter";
  /** The argument, e.g. `"scrypt logN"`. */
  readonly what: string;
} | {
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
declare class CryptoError extends Error {
  /** Always `"CryptoError"`; the cross-copy identity {@link CryptoError.isCryptoError} checks. */
  override readonly name = "CryptoError";
  /** The discriminant; equals `details.code`. */
  readonly code: CryptoErrorCode;
  /** The structured payload, discriminated by `code`. */
  readonly details: CryptoErrorDetails;
  private constructor();
  /** Type guard for a `CryptoError`, including one from another copy of this package. */
  static isCryptoError(value: unknown): value is CryptoError;
  /** `true` when `code` is this error's code. */
  is(code: CryptoErrorCode): boolean;
  /** `what` had `actual` bytes; `expected` were required. */
  static invalidSize(what: string, expected: number, actual: number): CryptoError;
  /** `what` has the right length but is not a valid key, point or signature. */
  static invalidData(what: string, message: string, cause?: unknown): CryptoError;
  /** `what` (a KDF or counter argument) is outside its domain. */
  static invalidParameter(what: string, message: string, cause?: unknown): CryptoError;
  /** AEAD authentication failed (wrong key, nonce, aad, or tampered data). */
  static authenticationFailed(cause?: unknown): CryptoError;
}
//#endregion
//#region src/memzero.d.ts
/**
 * Best-effort zeroing of secret buffers.
 *
 * @module memzero
 */
type NumericTypedArray = Uint8Array | Uint8ClampedArray | Uint16Array | Uint32Array | Int8Array | Int16Array | Int32Array | Float32Array | Float64Array;
/** Overwrite every element with zero. */
declare function memzero(data: NumericTypedArray): void;
/** {@link memzero} each array. */
declare function memzeroAll(arrays: readonly NumericTypedArray[]): void;
//#endregion
//#region src/hash.d.ts
/** Bytes in a CRC-32 checksum. */
declare const CRC32_SIZE = 4;
/** Bytes in a SHA-256 digest. */
declare const SHA256_SIZE = 32;
/** Bytes in a SHA-512 digest. */
declare const SHA512_SIZE = 64;
/** CRC-32 (IEEE 802.3 / ISO-HDLC) as an unsigned 32-bit integer. */
declare function crc32(data: Uint8Array): number;
/** Options for {@link crc32Bytes}. */
interface Crc32Options {
  /** Emit the checksum little-endian. Default: big-endian. */
  readonly littleEndian?: boolean | undefined;
}
/** CRC-32 as four bytes, big-endian unless `littleEndian` is set. */
declare function crc32Bytes(data: Uint8Array, options?: Crc32Options): Uint8Array<ArrayBuffer>;
/** SHA-256 of `data` (32 bytes). */
declare function sha256(data: Uint8Array): Uint8Array<ArrayBuffer>;
/** `sha256(sha256(data))`, the Bitcoin message hash. */
declare function doubleSha256(data: Uint8Array): Uint8Array<ArrayBuffer>;
/** SHA-512 of `data` (64 bytes). */
declare function sha512(data: Uint8Array): Uint8Array<ArrayBuffer>;
/** HMAC-SHA-256 of `message` under `key` (32 bytes). */
declare function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
/** HMAC-SHA-512 of `message` under `key` (64 bytes). */
declare function hmacSha512(key: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
/** Options for the PBKDF2 functions. */
interface Pbkdf2Options {
  /** PBKDF2 iteration count; an integer ≥ 1. */
  readonly iterations: number;
  /** Derived key length in bytes. */
  readonly dkLen: number;
}
/** @throws {CryptoError} `InvalidParameter` unless `iterations` and `dkLen` are integers ≥ 1. */
declare function pbkdf2Sha256(password: Uint8Array, salt: Uint8Array, options: Pbkdf2Options): Uint8Array<ArrayBuffer>;
/** @throws {CryptoError} `InvalidParameter` unless `iterations` and `dkLen` are integers ≥ 1. */
declare function pbkdf2Sha512(password: Uint8Array, salt: Uint8Array, options: Pbkdf2Options): Uint8Array<ArrayBuffer>;
/** Options for the HKDF functions. */
interface HkdfOptions {
  /** Derived key length in bytes; at most 255 × the hash length. */
  readonly dkLen: number;
}
/**
 * HKDF-SHA-256 with no `info`, `dkLen` output bytes.
 * @throws {CryptoError} `InvalidParameter` unless `dkLen` is an integer in [0, 255 · 32].
 */
declare function hkdfSha256(keyMaterial: Uint8Array, salt: Uint8Array, options: HkdfOptions): Uint8Array<ArrayBuffer>;
/**
 * HKDF-SHA-512 with no `info`, `dkLen` output bytes.
 * @throws {CryptoError} `InvalidParameter` unless `dkLen` is an integer in [0, 255 · 64].
 */
declare function hkdfSha512(keyMaterial: Uint8Array, salt: Uint8Array, options: HkdfOptions): Uint8Array<ArrayBuffer>;
//#endregion
//#region src/kdf.d.ts
/** Options for {@link scrypt}. Defaults are the reference parameters. */
interface ScryptOptions {
  /** Derived key length in bytes. */
  readonly dkLen: number;
  /** log₂ of the CPU/memory cost `N`. Default 17 (N = 131072). An integer in [1, 63]. */
  readonly logN?: number | undefined;
  /** Block size. Default 8. */
  readonly r?: number | undefined;
  /** Parallelism. Default 1. */
  readonly p?: number | undefined;
}
/**
 * @throws {CryptoError} `InvalidParameter` when `dkLen` is not an integer ≥ 1,
 * `logN` not in [1, 63], `r` or `p` not ≥ 1, or the parameters exceed the
 * backend's memory limit.
 */
declare function scrypt(password: Uint8Array, salt: Uint8Array, options: ScryptOptions): Uint8Array<ArrayBuffer>;
/** Options for {@link argon2id}. Defaults are the reference parameters. */
interface Argon2idOptions {
  /** Derived key length in bytes. */
  readonly dkLen: number;
  /** Iterations. Default 2. */
  readonly t?: number | undefined;
  /** Memory in KiB. Default 19456. */
  readonly m?: number | undefined;
  /** Parallelism. Default 1. */
  readonly p?: number | undefined;
}
/**
 * @throws {CryptoError} `InvalidParameter` when `dkLen` is not an integer ≥ 4,
 * `salt` is shorter than 8 bytes, `t` is not ≥ 1, `p` not in [1, 2^24 - 1],
 * or `m` is not ≥ 8·p.
 */
declare function argon2id(password: Uint8Array, salt: Uint8Array, options: Argon2idOptions): Uint8Array<ArrayBuffer>;
//#endregion
//#region src/aead.d.ts
/** Options for {@link chacha20Poly1305}. */
interface AeadOptions {
  /** Additional authenticated data; authenticated but not encrypted. */
  readonly aad?: Uint8Array | undefined;
}
/** The {@link chacha20Poly1305} family. */
interface Chacha20Poly1305 {
  /** Key length in bytes. */
  readonly KEY_SIZE: 32;
  /** Nonce length in bytes (IETF, 96-bit). */
  readonly NONCE_SIZE: 12;
  /** Poly1305 tag length in bytes; the trailing bytes of a sealed buffer. */
  readonly TAG_SIZE: 16;
  /** Returns `ciphertext || tag`; the tag is the trailing 16 bytes. */
  encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, options?: AeadOptions): Uint8Array<ArrayBuffer>;
  /** Takes `ciphertext || tag`. @throws {CryptoError} `AuthenticationFailed` on tag mismatch. */
  decrypt(key: Uint8Array, nonce: Uint8Array, sealed: Uint8Array, options?: AeadOptions): Uint8Array<ArrayBuffer>;
}
/** ChaCha20-Poly1305 (RFC 8439). */
declare const chacha20Poly1305: Chacha20Poly1305;
//#endregion
//#region src/x25519.d.ts
/**
 * The stack's signing-key derivation: HKDF-SHA-256(keyMaterial, salt "signing")
 * → 32 bytes, used for ECDSA, Schnorr and Ed25519 private keys alike
 * (the reference's `derive_signing_private_key` ≡ `ecdsa_derive_private_key`).
 */
declare function deriveSigningPrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer>;
/**
 * The stack's agreement-key derivation: HKDF-SHA-256(keyMaterial, salt
 * "agreement") → 32 bytes, an X25519 private key.
 */
declare function deriveAgreementPrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer>;
/** The shape of the {@link x25519} family. */
interface X25519 {
  /** Private key length in bytes. */
  readonly PRIVATE_KEY_SIZE: 32;
  /** Public key length in bytes. */
  readonly PUBLIC_KEY_SIZE: 32;
  /** 32 random bytes from `options.rng` (default secure), unvalidated. */
  generatePrivateKey(options?: RngOptions$1): Uint8Array<ArrayBuffer>;
  /**
   * The X25519 public key of `privateKey` (clamped per RFC 7748).
   * @throws {CryptoError} `InvalidSize` on a wrong-length key.
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * X25519 Diffie-Hellman, then HKDF-SHA-256 with salt "agreement" → 32 bytes.
   * @throws {CryptoError} `InvalidData` when `publicKey` is a low-order point
   * (the reference derives a predictable key instead; divergence D2).
   */
  sharedKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array<ArrayBuffer>;
}
/** X25519 key agreement: key generation, public keys and the salted shared key. */
declare const x25519: X25519;
//#endregion
//#region src/ecdsa.d.ts
/** The shape of the {@link ecdsa} family. */
interface Ecdsa {
  /** Private key (scalar) length in bytes. */
  readonly PRIVATE_KEY_SIZE: 32;
  /** Compressed public key length in bytes. */
  readonly PUBLIC_KEY_SIZE: 33;
  /** Uncompressed (`04 ‖ x ‖ y`) public key length in bytes. */
  readonly UNCOMPRESSED_PUBLIC_KEY_SIZE: 65;
  /** Length of the message hash that is signed (double SHA-256). */
  readonly MESSAGE_HASH_SIZE: 32;
  /** Compact (`r ‖ s`) signature length in bytes. */
  readonly SIGNATURE_SIZE: 64;
  /** 32 random bytes from `options.rng` (default secure), unvalidated. */
  generatePrivateKey(options?: RngOptions$1): Uint8Array<ArrayBuffer>;
  /**
   * Compressed (33-byte) public key.
   * @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar (0 or ≥ n).
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /** @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the bytes are not a point on the curve. */
  decompressPublicKey(compressed: Uint8Array): Uint8Array<ArrayBuffer>;
  /** @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the bytes are not a point on the curve. */
  compressPublicKey(uncompressed: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * Deterministic (RFC 6979) signature over `doubleSha256(message)`; 64-byte compact form.
   * @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar.
   */
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
  /** `false` on an invalid signature; throws only on wrong-length inputs. */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}
/** secp256k1 ECDSA: keys, point compression, and RFC 6979 signatures over double SHA-256. */
declare const ecdsa: Ecdsa;
/** Options for `schnorr.sign`: explicit aux-rand bytes, or a generator to draw them from. */
interface SchnorrSignOptions {
  /** 32 bytes of auxiliary randomness (BIP-340). Takes precedence over `rng`. */
  readonly auxRand?: Uint8Array | undefined;
  /** Generator to draw 32 aux-rand bytes from. Default: secure. */
  readonly rng?: RandomNumberGenerator | undefined;
}
/** The shape of the {@link schnorr} family. */
interface Schnorr {
  /** x-only public key length in bytes. */
  readonly PUBLIC_KEY_SIZE: 32;
  /** BIP-340 signature length in bytes. */
  readonly SIGNATURE_SIZE: 64;
  /**
   * x-only (32-byte) public key of a secp256k1 private key.
   * @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar.
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * BIP-340 signature. Aux-rand comes from `options.auxRand`, else 32 bytes drawn from `options.rng`.
   * @throws {CryptoError} `InvalidSize` on a wrong length; `InvalidData` when the key is not a valid scalar.
   */
  sign(privateKey: Uint8Array, message: Uint8Array, options?: SchnorrSignOptions): Uint8Array<ArrayBuffer>;
  /**
   * `false` on an invalid signature or a malformed key (BIP-340 vectors 5–14).
   * @throws {CryptoError} `InvalidSize` on a wrong-length key or signature.
   */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}
/** BIP-340 Schnorr signatures over secp256k1, with the two aux-rand paths. */
declare const schnorr: Schnorr;
//#endregion
//#region src/ed25519.d.ts
/** The shape of the {@link ed25519} family. */
interface Ed25519 {
  /** Private key (seed) length in bytes. */
  readonly PRIVATE_KEY_SIZE: 32;
  /** Public key length in bytes. */
  readonly PUBLIC_KEY_SIZE: 32;
  /** Signature length in bytes. */
  readonly SIGNATURE_SIZE: 64;
  /** 32 random bytes from `options.rng` (default secure). */
  generatePrivateKey(options?: RngOptions$1): Uint8Array<ArrayBuffer>;
  /**
   * The public key of the 32-byte seed `privateKey` (RFC 8032).
   * @throws {CryptoError} `InvalidSize` on a wrong-length key.
   */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * Deterministic RFC 8032 signature (64 bytes).
   * @throws {CryptoError} `InvalidSize` on a wrong-length key.
   */
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
  /**
   * `(publicKey, signature, message)`, the same order as `ecdsa.verify` and `schnorr.verify`.
   *
   * Strict (the reference's `verify_strict`): only canonical point
   * encodings are accepted, and a small-order public key or `R` never
   * verifies. `false` on any invalid or malformed input of the right length.
   * @throws {CryptoError} `InvalidSize` on a wrong-length key or signature.
   */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}
/** Ed25519 (RFC 8032) signatures with strict verification. */
declare const ed25519: Ed25519;
//#endregion
//#region src/stream.d.ts
/** Options for {@link chacha20}. */
interface Chacha20Options {
  /** The initial block counter (0 by default). */
  readonly counter?: number | undefined;
}
/**
 * XORs `data` with the ChaCha20 keystream for `key` (32 bytes) and `nonce`
 * (12 bytes), starting at block `counter`. Applying it twice restores the
 * input.
 * @throws {CryptoError} `InvalidSize` on a wrong-length key or nonce;
 * `InvalidParameter` unless `counter` is an integer in [0, 2^32 - 1].
 */
declare function chacha20(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, { counter }?: Chacha20Options): Uint8Array;
//#endregion
export { type AeadOptions, type Argon2idOptions, CRC32_SIZE, type Chacha20Options, type Chacha20Poly1305, type Crc32Options, CryptoError, type CryptoErrorCode, type CryptoErrorDetails, type Ecdsa, type Ed25519, type HkdfOptions, type NumericTypedArray, type Pbkdf2Options, type RngOptions, SHA256_SIZE, SHA512_SIZE, type Schnorr, type SchnorrSignOptions, type ScryptOptions, type X25519, argon2id, chacha20, chacha20Poly1305, crc32, crc32Bytes, deriveAgreementPrivateKey, deriveSigningPrivateKey, doubleSha256, ecdsa, ed25519, hkdfSha256, hkdfSha512, hmacSha256, hmacSha512, memzero, memzeroAll, pbkdf2Sha256, pbkdf2Sha512, schnorr, scrypt, sha256, sha512, x25519 };
//# sourceMappingURL=index.d.mts.map