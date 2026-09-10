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
        const [ct, tag] = c.aeadChaCha20Poly1305EncryptWithAad(pt, k, n, aad);
        const back = c.aeadChaCha20Poly1305DecryptWithAad(ct, k, n, aad, tag);
        const [ct2, tag2] = c.aeadChaCha20Poly1305Encrypt(pt, k, n);
        return (
          Buffer.from(back).equals(Buffer.from(pt)) &&
          Buffer.from(c.aeadChaCha20Poly1305Decrypt(ct2, k, n, tag2)).equals(Buffer.from(pt)) &&
          ct.length === pt.length &&
          tag.length === 16
        );
      }),
      { numRuns: 200 },
    );
  });
  it("any flipped bit fails authentication", () => {
    fc.assert(
      fc.property(u8(), key, nonce, fc.nat(), (pt, k, n, i) => {
        const [ct, tag] = c.aeadChaCha20Poly1305Encrypt(pt, k, n);
        const all = new Uint8Array([...ct, ...tag]);
        all[i % all.length] ^= 1 << (i % 8);
        try {
          c.aeadChaCha20Poly1305Decrypt(all.subarray(0, ct.length), k, n, all.subarray(ct.length));
          return false;
        } catch {
          return true;
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
        const pub = c.ecdsaPublicKeyFromPrivateKey(k);
        return c.ecdsaVerify(pub, c.ecdsaSign(k, m), m);
      }),
      { numRuns: 60 },
    );
  });
  it("schnorr (aux-rand path)", () => {
    fc.assert(
      fc.property(priv, u8(), fc.uint8Array({ minLength: 32, maxLength: 32 }), (k, m, aux) => {
        const pub = c.schnorrPublicKeyFromPrivateKey(k);
        return c.schnorrVerify(pub, c.schnorrSignWithAuxRand(k, m, aux), m);
      }),
      { numRuns: 60 },
    );
  });
  it("ed25519", () => {
    fc.assert(
      fc.property(priv, u8(), (k, m) => {
        const pub = c.ed25519PublicKeyFromPrivateKey(k);
        return c.ed25519Verify(pub, m, c.ed25519Sign(k, m));
      }),
      { numRuns: 60 },
    );
  });
  it("x25519 agreement is symmetric", () => {
    fc.assert(
      fc.property(priv, priv, (a, b) => {
        const A = c.x25519PublicKeyFromPrivateKey(a),
          B = c.x25519PublicKeyFromPrivateKey(b);
        return Buffer.from(c.x25519SharedKey(a, B)).equals(Buffer.from(c.x25519SharedKey(b, A)));
      }),
      { numRuns: 60 },
    );
  });
  it("ec key compression round-trips", () => {
    fc.assert(
      fc.property(priv, (k) => {
        const pub = c.ecdsaPublicKeyFromPrivateKey(k);
        return Buffer.from(c.ecdsaCompressPublicKey(c.ecdsaDecompressPublicKey(pub))).equals(
          Buffer.from(pub),
        );
      }),
      { numRuns: 60 },
    );
  });
});
