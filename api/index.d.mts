import { RandomNumberGenerator } from "@blockchaincommons/rand";
//#region src/error.d.ts
/**
 * The single error type thrown by this package.
 *
 * @module error
 */
/** Machine-readable discriminant for a {@link CryptoError}. */
type CryptoErrorCode = "InvalidSize" | "InvalidData" | "AuthenticationFailed" | "Unsupported";
/** The structured payload each code carries. */
interface CryptoErrorDetailsByCode {
  InvalidSize: {
    readonly what: string;
    readonly expected: number;
    readonly actual: number;
  };
  InvalidData: {
    readonly what: string;
  };
  AuthenticationFailed: unknown;
  Unsupported: unknown;
}
/** A {@link CryptoError} whose `details` are discriminated by its `code`. */
type CryptoErrorTyped<C extends CryptoErrorCode = CryptoErrorCode> = C extends CryptoErrorCode ? CryptoError & {
  readonly code: C;
  readonly details: Readonly<CryptoErrorDetailsByCode[C]>;
} : never;
/**
 * Thrown for wrong-length keys, nonces, signatures and public keys
 * (`InvalidSize`), malformed input (`InvalidData`), AEAD tag mismatch
 * (`AuthenticationFailed`), and unsupported parameters (`Unsupported`).
 */
declare class CryptoError extends Error {
  readonly code: CryptoErrorCode;
  readonly details: unknown;
  constructor(code: CryptoErrorCode, message: string, details?: unknown, cause?: unknown);
  /** Type guard narrowing to the code-discriminated union. */
  static isCryptoError(value: unknown): value is CryptoErrorTyped;
  /** `what` had `actual` bytes; `expected` were required. */
  static invalidSize(what: string, expected: number, actual: number): CryptoErrorTyped<"InvalidSize">;
  static invalidData(what: string, message: string): CryptoErrorTyped<"InvalidData">;
  /** AEAD authentication failed (wrong key, nonce, aad, or tampered data). */
  static authenticationFailed(cause?: unknown): CryptoErrorTyped<"AuthenticationFailed">;
  static unsupported(message: string): CryptoErrorTyped<"Unsupported">;
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
declare const CRC32_SIZE = 4;
declare const SHA256_SIZE = 32;
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
declare function sha256(data: Uint8Array): Uint8Array<ArrayBuffer>;
/** `sha256(sha256(data))`, the Bitcoin message hash. */
declare function doubleSha256(data: Uint8Array): Uint8Array<ArrayBuffer>;
declare function sha512(data: Uint8Array): Uint8Array<ArrayBuffer>;
declare function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
declare function hmacSha512(key: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
/** Options for the PBKDF2 functions. */
interface Pbkdf2Options {
  readonly iterations: number;
  /** Derived key length in bytes. */
  readonly dkLen: number;
}
declare function pbkdf2Sha256(password: Uint8Array, salt: Uint8Array, options: Pbkdf2Options): Uint8Array<ArrayBuffer>;
declare function pbkdf2Sha512(password: Uint8Array, salt: Uint8Array, options: Pbkdf2Options): Uint8Array<ArrayBuffer>;
/** HKDF-SHA-256 with no `info`, `length` output bytes. */
declare function hkdfSha256(keyMaterial: Uint8Array, salt: Uint8Array, length: number): Uint8Array<ArrayBuffer>;
/** HKDF-SHA-512 with no `info`, `length` output bytes. */
declare function hkdfSha512(keyMaterial: Uint8Array, salt: Uint8Array, length: number): Uint8Array<ArrayBuffer>;
//#endregion
//#region src/kdf.d.ts
/** Options for {@link scrypt}. Defaults are the reference parameters. */
interface ScryptOptions {
  /** Derived key length in bytes. */
  readonly dkLen: number;
  /** log₂ of the CPU/memory cost `N`. Default 17 (N = 131072). Must be < 64. */
  readonly logN?: number | undefined;
  /** Block size. Default 8. */
  readonly r?: number | undefined;
  /** Parallelism. Default 1. */
  readonly p?: number | undefined;
}
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
declare function argon2id(password: Uint8Array, salt: Uint8Array, options: Argon2idOptions): Uint8Array<ArrayBuffer>;
//#endregion
//#region src/aead.d.ts
declare const SYMMETRIC_KEY_SIZE = 32;
declare const SYMMETRIC_NONCE_SIZE = 12;
declare const SYMMETRIC_AUTH_SIZE = 16;
/** Options for {@link chacha20Poly1305}. */
interface AeadOptions {
  /** Additional authenticated data; authenticated but not encrypted. */
  readonly aad?: Uint8Array | undefined;
}
/** The {@link chacha20Poly1305} family. */
interface Chacha20Poly1305 {
  readonly KEY_SIZE: 32;
  readonly NONCE_SIZE: 12;
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
declare const X25519_PRIVATE_KEY_SIZE = 32;
declare const X25519_PUBLIC_KEY_SIZE = 32;
/** Options for the key generators. */
interface KeygenOptions {
  /** Generator to draw the key from. Default: secure. */
  readonly rng?: RandomNumberGenerator | undefined;
}
/** HKDF-SHA-256(keyMaterial, salt "signing") → 32 bytes. */
declare function deriveSigningPrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer>;
/** The {@link x25519} family. */
interface X25519 {
  readonly PRIVATE_KEY_SIZE: 32;
  readonly PUBLIC_KEY_SIZE: 32;
  /** 32 random bytes from `options.rng` (default secure), unvalidated. */
  generatePrivateKey(options?: KeygenOptions): Uint8Array<ArrayBuffer>;
  /** HKDF-SHA-256(keyMaterial, salt "agreement") → 32 bytes. */
  deriveAgreementPrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer>;
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /** X25519 Diffie-Hellman, then HKDF-SHA-256 with salt "agreement" → 32 bytes. */
  sharedKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array<ArrayBuffer>;
}
declare const x25519: X25519;
//#endregion
//#region src/ecdsa.d.ts
declare const ECDSA_PRIVATE_KEY_SIZE = 32;
declare const ECDSA_PUBLIC_KEY_SIZE = 33;
declare const ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
declare const ECDSA_MESSAGE_HASH_SIZE = 32;
declare const ECDSA_SIGNATURE_SIZE = 64;
declare const SCHNORR_PUBLIC_KEY_SIZE = 32;
declare const SCHNORR_SIGNATURE_SIZE = 64;
/** The {@link ecdsa} family. */
interface Ecdsa {
  readonly PRIVATE_KEY_SIZE: 32;
  readonly PUBLIC_KEY_SIZE: 33;
  readonly UNCOMPRESSED_PUBLIC_KEY_SIZE: 65;
  readonly MESSAGE_HASH_SIZE: 32;
  readonly SIGNATURE_SIZE: 64;
  /** 32 random bytes from `options.rng` (default secure), unvalidated. */
  generatePrivateKey(options?: KeygenOptions): Uint8Array<ArrayBuffer>;
  /** HKDF-SHA-256(keyMaterial, salt "signing") → 32 bytes, unvalidated. */
  derivePrivateKey(keyMaterial: Uint8Array): Uint8Array<ArrayBuffer>;
  /** Compressed (33-byte) public key. */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  decompressPublicKey(compressed: Uint8Array): Uint8Array<ArrayBuffer>;
  compressPublicKey(uncompressed: Uint8Array): Uint8Array<ArrayBuffer>;
  /** Deterministic (RFC 6979) signature over `doubleSha256(message)`; 64-byte compact form. */
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
  /** `false` on an invalid signature; throws only on wrong-length inputs. */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}
declare const ecdsa: Ecdsa;
/** Options for `schnorr.sign`: explicit aux-rand bytes, or a generator to draw them from. */
interface SchnorrSignOptions {
  /** 32 bytes of auxiliary randomness (BIP-340). Takes precedence over `rng`. */
  readonly auxRand?: Uint8Array | undefined;
  /** Generator to draw 32 aux-rand bytes from. Default: secure. */
  readonly rng?: RandomNumberGenerator | undefined;
}
/** The {@link schnorr} family. */
interface Schnorr {
  readonly PUBLIC_KEY_SIZE: 32;
  readonly SIGNATURE_SIZE: 64;
  /** x-only (32-byte) public key of a secp256k1 private key. */
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  /** BIP-340 signature. Aux-rand comes from `options.auxRand`, else 32 bytes drawn from `options.rng`. */
  sign(privateKey: Uint8Array, message: Uint8Array, options?: SchnorrSignOptions): Uint8Array<ArrayBuffer>;
  /** `false` on an invalid signature; throws only on wrong-length inputs. */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}
declare const schnorr: Schnorr;
//#endregion
//#region src/ed25519.d.ts
declare const ED25519_PUBLIC_KEY_SIZE = 32;
declare const ED25519_PRIVATE_KEY_SIZE = 32;
declare const ED25519_SIGNATURE_SIZE = 64;
/** The {@link ed25519} family. */
interface Ed25519 {
  readonly PRIVATE_KEY_SIZE: 32;
  readonly PUBLIC_KEY_SIZE: 32;
  readonly SIGNATURE_SIZE: 64;
  /** 32 random bytes from `options.rng` (default secure). */
  generatePrivateKey(options?: KeygenOptions): Uint8Array<ArrayBuffer>;
  publicKey(privateKey: Uint8Array): Uint8Array<ArrayBuffer>;
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array<ArrayBuffer>;
  /** `(publicKey, signature, message)`, the same order as `ecdsa.verify` and `schnorr.verify`. */
  verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean;
}
declare const ed25519: Ed25519;
//#endregion
export { type AeadOptions, type Argon2idOptions, CRC32_SIZE, type Chacha20Poly1305, type Crc32Options, CryptoError, type CryptoErrorCode, type CryptoErrorDetailsByCode, type CryptoErrorTyped, ECDSA_MESSAGE_HASH_SIZE, ECDSA_PRIVATE_KEY_SIZE, ECDSA_PUBLIC_KEY_SIZE, ECDSA_SIGNATURE_SIZE, ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE, ED25519_PRIVATE_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE, type Ecdsa, type Ed25519, type KeygenOptions, type NumericTypedArray, type Pbkdf2Options, SCHNORR_PUBLIC_KEY_SIZE, SCHNORR_SIGNATURE_SIZE, SHA256_SIZE, SHA512_SIZE, SYMMETRIC_AUTH_SIZE, SYMMETRIC_KEY_SIZE, SYMMETRIC_NONCE_SIZE, type Schnorr, type SchnorrSignOptions, type ScryptOptions, type X25519, X25519_PRIVATE_KEY_SIZE, X25519_PUBLIC_KEY_SIZE, argon2id, chacha20Poly1305, crc32, crc32Bytes, deriveSigningPrivateKey, doubleSha256, ecdsa, ed25519, hkdfSha256, hkdfSha512, hmacSha256, hmacSha512, memzero, memzeroAll, pbkdf2Sha256, pbkdf2Sha512, schnorr, scrypt, sha256, sha512, x25519 };
//# sourceMappingURL=index.d.mts.map