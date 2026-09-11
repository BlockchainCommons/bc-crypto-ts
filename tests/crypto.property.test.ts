/**
 * Property tests: round-trips and tamper detection over generated inputs.
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

describe("properties for B1, B2, B4", () => {
  const isCryptoError = (f: () => unknown): boolean => {
    try {
      f();
      return false;
    } catch (e) {
      return c.CryptoError.isCryptoError(e);
    }
  };
  it("every fault raised by the package is a CryptoError (B4)", () => {
    const zero = new Uint8Array(32);
    const n = Uint8Array.from(
      Buffer.from("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "hex"),
    );
    const pw = new Uint8Array(2);
    const salt = new Uint8Array(16);
    const k32 = new Uint8Array(32).fill(7);
    const faults: (() => unknown)[] = [
      () => c.ecdsa.publicKey(zero),
      () => c.ecdsa.publicKey(n),
      () => c.schnorr.publicKey(zero),
      () => c.ecdsa.sign(zero, pw),
      () => c.schnorr.sign(zero, pw, { auxRand: k32 }),
      () => c.ecdsa.decompressPublicKey(Uint8Array.from([2, ...new Uint8Array(32).fill(0xff)])),
      () => c.ecdsa.compressPublicKey(Uint8Array.from([4, ...new Uint8Array(64).fill(1)])),
      () => c.x25519.sharedKey(k32, zero),
      () => c.scrypt(pw, salt, { dkLen: 0 }),
      () => c.scrypt(pw, salt, { dkLen: 32, logN: 0 }),
      () => c.scrypt(pw, salt, { dkLen: 32, logN: 64 }),
      () => c.scrypt(pw, salt, { dkLen: 32, r: 1.5 }),
      () => c.scrypt(pw, salt, { dkLen: 32, p: 0 }),
      () => c.scrypt(pw, salt, { dkLen: 32, logN: 40 }), // in domain; the backend's memory limit
      () => c.argon2id(pw, salt, { dkLen: 3 }),
      () => c.argon2id(pw, salt.subarray(0, 4), { dkLen: 32 }),
      () => c.argon2id(pw, salt, { dkLen: 32, t: 0 }),
      () => c.hkdfSha256(salt, salt, { dkLen: 8161 }),
      () => c.hkdfSha256(salt, salt, { dkLen: 1.5 }),
      () => c.hkdfSha512(salt, salt, { dkLen: -1 }),
      () => c.pbkdf2Sha256(pw, salt, { iterations: 0, dkLen: 32 }),
      () => c.pbkdf2Sha512(pw, salt, { iterations: 1, dkLen: 0 }),
      () => c.chacha20(k32, salt.subarray(0, 12), pw, { counter: -1 }),
      () => c.chacha20(k32, salt.subarray(0, 12), pw, { counter: 2 ** 32 }),
    ];
    // Every entry must throw, and what it throws must be a CryptoError.
    expect(faults.map(isCryptoError)).toEqual(faults.map(() => true));
    // Generated: integers outside the KDF domains and non-integers.
    fc.assert(
      fc.property(
        fc.oneof(fc.integer({ max: 0 }), fc.double({ noInteger: true, noNaN: true })),
        (bad) =>
          isCryptoError(() => c.pbkdf2Sha256(pw, salt, { iterations: bad, dkLen: 32 })) &&
          isCryptoError(() => c.scrypt(pw, salt, { dkLen: 32, logN: 4, r: bad })) &&
          isCryptoError(() => c.hkdfSha256(salt, salt, { dkLen: bad < 0 ? bad : bad + 0.5 })),
      ),
      { numRuns: 100 },
    );
  });
  it("a backend rejection inside the domain is InvalidParameter with the cause attached", () => {
    let err: unknown;
    try {
      c.scrypt(new Uint8Array(2), new Uint8Array(16), { dkLen: 32, logN: 40 });
    } catch (e) {
      err = e;
    }
    expect(c.CryptoError.isCryptoError(err) && err.code === "InvalidParameter").toBe(true);
    expect((err as Error).cause).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/^scrypt parameters rejected by the backend: /);
    expect(c.CryptoError.isCryptoError(err) && err.is("InvalidParameter")).toBe(true);
    expect(
      c.CryptoError.isCryptoError(err) &&
        err.details.code === "InvalidParameter" &&
        err.details.what,
    ).toBe("scrypt parameters");
  });
  it("a small-order or non-canonical Ed25519 public key or R never verifies (B1)", () => {
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const nonCanonicalIdentity = new Uint8Array(32).fill(0xff);
    nonCanonicalIdentity[0] = 0xee;
    nonCanonicalIdentity[31] = 0x7f; // y = p + 1
    const zeroS = new Uint8Array(32);
    const sig = (r: Uint8Array): Uint8Array => Uint8Array.from([...r, ...zeroS]);
    fc.assert(
      fc.property(u8(64), (msg) => {
        return (
          !c.ed25519.verify(identity, sig(identity), msg) &&
          !c.ed25519.verify(nonCanonicalIdentity, sig(identity), msg) &&
          !c.ed25519.verify(identity, sig(nonCanonicalIdentity), msg)
        );
      }),
      { numRuns: 100 },
    );
    // Honest signatures are unaffected.
    fc.assert(
      fc.property(key, u8(), (priv, msg) => {
        const pub = c.ed25519.publicKey(priv);
        return c.ed25519.verify(pub, c.ed25519.sign(priv, msg), msg);
      }),
      { numRuns: 100 },
    );
  });
  it("x25519.sharedKey rejects a low-order public key with CryptoError InvalidData (B2)", () => {
    const one = new Uint8Array(32);
    one[0] = 1;
    for (const pub of [new Uint8Array(32), one]) {
      let err: unknown;
      try {
        c.x25519.sharedKey(new Uint8Array(32).fill(7), pub);
      } catch (e) {
        err = e;
      }
      expect(c.CryptoError.isCryptoError(err) && err.code === "InvalidData").toBe(true);
      expect((err as Error).cause).toBeInstanceOf(Error);
    }
  });
});
