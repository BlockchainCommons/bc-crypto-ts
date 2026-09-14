/**
 * ChaCha20-Poly1305 authenticated encryption.
 *
 * @module aead
 */
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { CryptoError, requireBytes, requireLength, requireOptions } from "./error.js";

const SYMMETRIC_KEY_SIZE = 32;
const SYMMETRIC_NONCE_SIZE = 12;
const SYMMETRIC_AUTH_SIZE = 16;

/** Options for {@link chacha20Poly1305}. */
export interface AeadOptions {
  /** Additional authenticated data; authenticated but not encrypted. */
  readonly aad?: Uint8Array | undefined;
}

const EMPTY = new Uint8Array(0);

/** The `aad` option, validated: `undefined` means none (the same as empty). */
function aadOf(options: AeadOptions | undefined): Uint8Array {
  requireOptions("ChaCha20-Poly1305 options", options, true);
  const aad = options?.aad;
  if (aad === undefined) return EMPTY;
  requireBytes("ChaCha20-Poly1305 aad", aad);
  return aad;
}

/** The {@link chacha20Poly1305} family. */
export interface Chacha20Poly1305 {
  /** Key length in bytes. */
  readonly KEY_SIZE: 32;
  /** Nonce length in bytes (IETF, 96-bit). */
  readonly NONCE_SIZE: 12;
  /** Poly1305 tag length in bytes; the trailing bytes of a sealed buffer. */
  readonly TAG_SIZE: 16;
  /**
   * Returns `ciphertext || tag`; the tag is the trailing 16 bytes.
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array` argument;
   * `InvalidSize` on a wrong-length key or nonce.
   */
  encrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    options?: AeadOptions,
  ): Uint8Array<ArrayBuffer>;
  /**
   * Takes `ciphertext || tag`.
   * @throws {CryptoError} `InvalidParameter` on a non-`Uint8Array` argument;
   * `InvalidSize` on a wrong-length key or nonce, or sealed data shorter
   * than the tag; `AuthenticationFailed` on tag mismatch.
   */
  decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    sealed: Uint8Array,
    options?: AeadOptions,
  ): Uint8Array<ArrayBuffer>;
}

/** ChaCha20-Poly1305 (RFC 8439). */
export const chacha20Poly1305: Chacha20Poly1305 = {
  KEY_SIZE: 32,
  NONCE_SIZE: 12,
  TAG_SIZE: 16,

  encrypt(key, nonce, plaintext, options) {
    requireLength("ChaCha20-Poly1305 key", key, SYMMETRIC_KEY_SIZE);
    requireLength("ChaCha20-Poly1305 nonce", nonce, SYMMETRIC_NONCE_SIZE);
    requireBytes("ChaCha20-Poly1305 plaintext", plaintext);
    const aad = aadOf(options);
    return chacha20poly1305(key, nonce, aad).encrypt(plaintext);
  },

  decrypt(key, nonce, sealed, options) {
    requireLength("ChaCha20-Poly1305 key", key, SYMMETRIC_KEY_SIZE);
    requireLength("ChaCha20-Poly1305 nonce", nonce, SYMMETRIC_NONCE_SIZE);
    requireBytes("ChaCha20-Poly1305 sealed data", sealed);
    const aad = aadOf(options);
    if (sealed.length < SYMMETRIC_AUTH_SIZE) {
      throw CryptoError.invalidSize(
        "ChaCha20-Poly1305 sealed data",
        SYMMETRIC_AUTH_SIZE,
        sealed.length,
      );
    }
    try {
      return chacha20poly1305(key, nonce, aad).decrypt(sealed);
    } catch (error) {
      throw CryptoError.authenticationFailed(error);
    }
  },
};
