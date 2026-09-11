/**
 * Authenticated encryption with associated data, and the error codes.
 *
 *   bun run build && bun examples/aead.ts
 */
import { chacha20Poly1305, CryptoError, hkdfSha256, sha256 } from "@blockchaincommons/crypto";
import { SeededRng, randomBytes } from "@blockchaincommons/rand";

const rng = SeededRng.forTesting();
const key = hkdfSha256(randomBytes(32, { rng }), new TextEncoder().encode("example"), { dkLen: 32 });
const nonce = randomBytes(chacha20Poly1305.NONCE_SIZE, { rng });
const plaintext = new TextEncoder().encode("Gordian Envelope");
const aad = sha256(new TextEncoder().encode("header")); // authenticated, not encrypted

const sealed = chacha20Poly1305.encrypt(key, nonce, plaintext, { aad }); // ciphertext || tag
console.log("sealed", Buffer.from(sealed).toString("hex"));
console.log("opened", new TextDecoder().decode(chacha20Poly1305.decrypt(key, nonce, sealed, { aad })));

// Every failure is a CryptoError with a `code`.
const report = (f: () => unknown): string => {
  try {
    f();
    return "ok";
  } catch (e) {
    return CryptoError.isCryptoError(e) ? `${e.code}: ${e.message}` : String(e);
  }
};
console.log(report(() => chacha20Poly1305.decrypt(key, nonce, sealed))); // AuthenticationFailed (aad missing)
console.log(report(() => chacha20Poly1305.decrypt(key, nonce.subarray(0, 8), sealed, { aad }))); // InvalidSize
console.log(report(() => hkdfSha256(key, nonce, { dkLen: 1.5 }))); // InvalidParameter
