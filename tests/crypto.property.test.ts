/**
 * Property tests (Phase 0.3): round-trips and tamper detection over generated inputs.
 */
import fc from "fast-check";
import * as c from "../src";

const u8 = (max = 256) => fc.uint8Array({ maxLength: max });
const key = fc.uint8Array({ minLength: 32, maxLength: 32 });
const nonce = fc.uint8Array({ minLength: 12, maxLength: 12 });

describe("aead round-trips and tamper detection", () => {
  it("encrypt/decrypt with and without aad", () => {
    fc.assert(
      fc.property(u8(), key, nonce, u8(64), (pt, k, n, aad) => {
        const sealed = c.chacha20Poly1305.encrypt(k, n, pt, { aad });
        const back = c.chacha20Poly1305.decrypt(k, n, sealed, { aad });
        const sealed2 = c.chacha20Poly1305.encrypt(k, n, pt);
        return (
          Buffer.from(back).equals(Buffer.from(pt)) &&
          Buffer.from(c.chacha20Poly1305.decrypt(k, n, sealed2)).equals(Buffer.from(pt)) &&
          sealed.length === pt.length + 16
        );
      }),
      { numRuns: 200 },
    );
  });
  it("any flipped bit fails authentication", () => {
    fc.assert(
      fc.property(u8(), key, nonce, fc.nat(), (pt, k, n, i) => {
        const all = c.chacha20Poly1305.encrypt(k, n, pt);
        all[i % all.length] ^= 1 << (i % 8);
        try {
          c.chacha20Poly1305.decrypt(k, n, all);
          return false;
        } catch (e) {
          return c.CryptoError.isCryptoError(e) && e.code === "AuthenticationFailed";
        }
      }),
      { numRuns: 200 },
    );
  });
});

describe("signature round-trips", () => {
  const priv = fc
    .uint8Array({ minLength: 32, maxLength: 32 })
    .filter((k) => k.some((b) => b !== 0));
  it("ecdsa", () => {
    fc.assert(
      fc.property(priv, u8(), (k, m) => {
        const pub = c.ecdsa.publicKey(k);
        return c.ecdsa.verify(pub, c.ecdsa.sign(k, m), m);
      }),
      { numRuns: 60 },
    );
  });
  it("schnorr (aux-rand path)", () => {
    fc.assert(
      fc.property(priv, u8(), fc.uint8Array({ minLength: 32, maxLength: 32 }), (k, m, aux) => {
        const pub = c.schnorr.publicKey(k);
        return c.schnorr.verify(pub, c.schnorr.sign(k, m, { auxRand: aux }), m);
      }),
      { numRuns: 60 },
    );
  });
  it("ed25519", () => {
    fc.assert(
      fc.property(priv, u8(), (k, m) => {
        const pub = c.ed25519.publicKey(k);
        return c.ed25519.verify(pub, c.ed25519.sign(k, m), m);
      }),
      { numRuns: 60 },
    );
  });
  it("x25519 agreement is symmetric", () => {
    fc.assert(
      fc.property(priv, priv, (a, b) => {
        const A = c.x25519.publicKey(a),
          B = c.x25519.publicKey(b);
        return Buffer.from(c.x25519.sharedKey(a, B)).equals(Buffer.from(c.x25519.sharedKey(b, A)));
      }),
      { numRuns: 60 },
    );
  });
  it("ec key compression round-trips", () => {
    fc.assert(
      fc.property(priv, (k) => {
        const pub = c.ecdsa.publicKey(k);
        return Buffer.from(c.ecdsa.compressPublicKey(c.ecdsa.decompressPublicKey(pub))).equals(
          Buffer.from(pub),
        );
      }),
      { numRuns: 60 },
    );
  });
});
