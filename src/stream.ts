/**
 * ChaCha20 as a keystream XOR (RFC 8439 §2.4), for callers that need the
 * raw cipher without Poly1305 — provenance marks obfuscate their tail with
 * it. Prefer {@link chacha20Poly1305} wherever authentication is possible.
 *
 * @module stream
 */
import { chacha20 as nobleChacha20 } from "@noble/ciphers/chacha.js";
import { requireLength } from "./error.js";
import { expectInt, U32_MAX } from "./domain.js";

/** Options for {@link chacha20}. */
export interface Chacha20Options {
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
export function chacha20(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  { counter = 0 }: Chacha20Options = {},
): Uint8Array {
  requireLength("ChaCha20 key", key, 32);
  requireLength("ChaCha20 nonce", nonce, 12);
  expectInt("ChaCha20 counter", counter, 0, U32_MAX);
  return nobleChacha20(key, nonce, data, undefined, counter);
}
