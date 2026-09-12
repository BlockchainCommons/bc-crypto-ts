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
      () => c.scrypt(pw, salt, { dkLen: 32, logN: 4, maxmem: 1 }), // in domain; the backend's memory limit
      () => c.scrypt(pw, salt, { dkLen: 32, logN: 17, r: 1 }), // RFC 7914: logN must be below 16·r
      () => c.scrypt(pw, salt, { dkLen: 32, logN: 4, r: 32768, p: 32768 }), // r·p must be below 2^30
      () => c.scrypt(pw, salt, { dkLen: 9, logN: 4, r: 8, p: 1 }), // parameterised path: 10 ≤ dkLen ≤ 64
      () => c.scrypt(pw, salt, { dkLen: 65, logN: 4 }),
      () => c.scrypt(pw, salt, { dkLen: 32, logN: 4, maxmem: 0 }),
      () => c.argon2id(pw, salt, { dkLen: 3 }),
      () => c.argon2id(pw, salt.subarray(0, 4), { dkLen: 32 }),
      () => c.hkdfSha256(salt, salt, { dkLen: 8161 }),
      () => c.hkdfSha256(salt, salt, { dkLen: 1.5 }),
      () => c.hkdfSha512(salt, salt, { dkLen: -1 }),
      () => c.pbkdf2Sha256(pw, salt, { iterations: 0, dkLen: 32 }),
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
      c.scrypt(new Uint8Array(2), new Uint8Array(16), { dkLen: 32, logN: 4, maxmem: 1 });
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

describe("KDF domains mirrored from the reference's crates (1.0.0-beta.2)", () => {
  const pw = new Uint8Array(2);
  const salt = new Uint8Array(16).fill(0x50);
  it("scrypt: default and parameterised output-length rules", { timeout: 30_000 }, () => {
    expect(c.scrypt(pw, salt, { dkLen: 8 }).length).toBe(8);
    expect(c.scrypt(pw, salt, { dkLen: 65 }).length).toBe(65);
    expect(c.scrypt(pw, salt, { dkLen: 10, logN: 4 }).length).toBe(10);
    expect(c.scrypt(pw, salt, { dkLen: 64, logN: 4 }).length).toBe(64);
    expect(() => c.scrypt(pw, salt, { dkLen: 9, logN: 4 })).toThrow(
      "scrypt dkLen must be an integer in [10, 64], got 9",
    );
    expect(() => c.scrypt(pw, salt, { dkLen: 65, r: 8 })).toThrow("got 65");
  });
  it("scrypt: logN < 16·r and r·p < 2^30, named", () => {
    expect(() => c.scrypt(pw, salt, { dkLen: 32, logN: 16, r: 1 })).toThrow(
      "scrypt logN must be below 16·r",
    );
    expect(c.scrypt(pw, salt, { dkLen: 32, logN: 15, r: 1 }).length).toBe(32);
    expect(() => c.scrypt(pw, salt, { dkLen: 32, logN: 4, r: 32768, p: 32768 })).toThrow(
      "scrypt r·p must be below 2^30",
    );
  });
  it("scrypt: maxmem is validated and forwarded", () => {
    expect(() => c.scrypt(pw, salt, { dkLen: 32, logN: 4, maxmem: 1 })).toThrow(/maxmem/);
    expect(c.scrypt(pw, salt, { dkLen: 32, logN: 4, maxmem: 1 << 30 })).toEqual(
      c.scrypt(pw, salt, { dkLen: 32, logN: 4 }),
    );
    expect(() => c.scrypt(pw, salt, { dkLen: 32, logN: 4, maxmem: 1.5 })).toThrow("got 1.5");
  });
  it("pbkdf2: dkLen 0 is an empty key, as the reference returns", () => {
    expect(c.pbkdf2Sha256(pw, salt, { iterations: 1, dkLen: 0 })).toEqual(new Uint8Array(0));
    expect(c.pbkdf2Sha512(pw, salt, { iterations: 7, dkLen: 0 })).toEqual(new Uint8Array(0));
    expect(() => c.pbkdf2Sha256(pw, salt, { iterations: 0, dkLen: 0 })).toThrow("iterations");
  });
  it("argon2id: the reference's fixed costs, no knobs", () => {
    // Argon2::default() — the cross-platform vector in crypto.test.ts pins the bytes.
    expect(c.argon2id(pw, salt, { dkLen: 32 }).length).toBe(32);
    expect(Object.keys({ dkLen: 32 } satisfies c.Argon2idOptions)).toEqual(["dkLen"]);
  });
});
