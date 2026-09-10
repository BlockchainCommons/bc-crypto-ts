/**
 * ChaCha20-Poly1305 authenticated encryption.
 *
 * @module aead
 */
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { CryptoError, requireLength } from "./error.js";

export const SYMMETRIC_KEY_SIZE = 32;
export const SYMMETRIC_NONCE_SIZE = 12;
export const SYMMETRIC_AUTH_SIZE = 16;

/** Options for {@link chacha20Poly1305}. */
export interface AeadOptions {
  /** Additional authenticated data; authenticated but not encrypted. */
  readonly aad?: Uint8Array | undefined;
}

const EMPTY = new Uint8Array(0);

/** The {@link chacha20Poly1305} family. */
export interface Chacha20Poly1305 {
  readonly KEY_SIZE: 32;
  readonly NONCE_SIZE: 12;
  readonly TAG_SIZE: 16;
  /** Returns `ciphertext || tag`; the tag is the trailing 16 bytes. */
  encrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    options?: AeadOptions,
  ): Uint8Array<ArrayBuffer>;
  /** Takes `ciphertext || tag`. @throws {CryptoError} `AuthenticationFailed` on tag mismatch. */
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
    requireLength("key", key, SYMMETRIC_KEY_SIZE);
    requireLength("nonce", nonce, SYMMETRIC_NONCE_SIZE);
    return chacha20poly1305(key, nonce, options?.aad ?? EMPTY).encrypt(plaintext);
  },

  decrypt(key, nonce, sealed, options) {
    requireLength("key", key, SYMMETRIC_KEY_SIZE);
    requireLength("nonce", nonce, SYMMETRIC_NONCE_SIZE);
    if (sealed.length < SYMMETRIC_AUTH_SIZE) {
      throw CryptoError.invalidSize("sealed data", SYMMETRIC_AUTH_SIZE, sealed.length);
    }
    try {
      return chacha20poly1305(key, nonce, options?.aad ?? EMPTY).decrypt(sealed);
    } catch (error) {
      throw CryptoError.authenticationFailed(error);
    }
  },
};
