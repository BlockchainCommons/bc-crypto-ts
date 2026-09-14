/**
 * Property tests: round-trips and tamper detection over generated inputs.
 */
import fc from "fast-check";
import { runInNewContext } from "node:vm";
import { isBytes } from "@noble/hashes/utils.js";
import { RandError } from "@blockchaincommons/rand";
import * as c from "../src";
import { ED_NONCANONICAL_DECODABLE_K } from "./corpus/corpus";

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
    // A non-canonical A the reference's decoder accepts (y = p + k reduced to
    // y = k) is a point other than the signer's, so no honest signature
    // verifies under it, on either side.
    const P = (1n << 255n) - 19n;
    const nonCanonicalA = ED_NONCANONICAL_DECODABLE_K.flatMap((k) =>
      [false, true].map((sign) => {
        const y = P + BigInt(k);
        const b = Uint8Array.from({ length: 32 }, (_, i) => Number((y >> BigInt(8 * i)) & 0xffn));
        if (sign) b[31] |= 0x80;
        return b;
      }),
    );
    fc.assert(
      fc.property(key, u8(), (priv, msg) => {
        const sig = c.ed25519.sign(priv, msg);
        return nonCanonicalA.every((a) => !c.ed25519.verify(a, sig, msg));
      }),
      { numRuns: 50 },
    );
  });
  it("x25519.sharedKey rejects every low-order encoding with NonContributoryKey, the reference's message (B2)", () => {
    // The nine RFC 7748 §6.1 encodings and the other five high-bit variants of the same
    // seven u values; anything else agrees with noble's ladder.
    const lowOrder = [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "0000000000000000000000000000000000000000000000000000000000000080",
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0100000000000000000000000000000000000000000000000000000000000080",
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ].map((h) => Uint8Array.from(Buffer.from(h, "hex")));
    fc.assert(
      fc.property(key, (priv) =>
        lowOrder.every((pub) => {
          try {
            c.x25519.sharedKey(priv, pub);
            return false;
          } catch (e) {
            return (
              c.CryptoError.isCryptoError(e) &&
              e.code === "NonContributoryKey" &&
              e.details.code === "NonContributoryKey" &&
              e.details.what === "X25519 public key" &&
              e.message === "X25519 peer key produces an all-zero shared secret" &&
              e.cause instanceof Error
            );
          }
        }),
      ),
      { numRuns: 50 },
    );
    // A non-canonical encoding of a valid point (u = p + 2) is a value, as in the reference.
    const pPlus2 = Uint8Array.from(
      Buffer.from("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "hex"),
    );
    expect(c.x25519.sharedKey(new Uint8Array(32).fill(1), pPlus2)).toHaveLength(32);
  });
});

describe("argument types: every byte, options and boolean argument is checked first", () => {
  // Rust's types make a non-byte argument impossible; here it is `InvalidParameter`
  // naming the argument, before lengths, domains, predicates and backends see it.
  const K32 = new Uint8Array(32).fill(7);
  const N12 = new Uint8Array(12);
  const M = new Uint8Array([1, 2, 3]);
  const SALT16 = new Uint8Array(16).fill(0x50);
  const P33 = c.ecdsa.publicKey(K32);
  const SIG64 = c.ecdsa.sign(K32, M);
  const EDPUB = c.ed25519.publicKey(K32);
  const EDSIG = c.ed25519.sign(K32, M);
  const SEALED = c.chacha20Poly1305.encrypt(K32, N12, M);
  const pb = { iterations: 1, dkLen: 32 };
  const B = (x: unknown): Uint8Array => x as Uint8Array;
  const O = <T>(x: unknown): T => x as T;
  /**
   * `[what, call with the bad value in that position, optional?]` for every byte
   * position; an optional one (`aad`, `auxRand`) treats `undefined` as absent.
   */
  const bytePositions: [string, (bad: unknown) => unknown, boolean?][] = [
    ["crc32 data", (b) => c.crc32(B(b))],
    ["crc32 data", (b) => c.crc32Bytes(B(b))],
    ["sha256 data", (b) => c.sha256(B(b))],
    ["doubleSha256 data", (b) => c.doubleSha256(B(b))],
    ["sha512 data", (b) => c.sha512(B(b))],
    ["hmacSha256 key", (b) => c.hmacSha256(B(b), M)],
    ["hmacSha256 message", (b) => c.hmacSha256(K32, B(b))],
    ["hmacSha512 key", (b) => c.hmacSha512(B(b), M)],
    ["hmacSha512 message", (b) => c.hmacSha512(K32, B(b))],
    ["pbkdf2 password", (b) => c.pbkdf2Sha256(B(b), SALT16, pb)],
    ["pbkdf2 salt", (b) => c.pbkdf2Sha256(M, B(b), pb)],
    ["pbkdf2 password", (b) => c.pbkdf2Sha512(B(b), SALT16, pb)],
    ["pbkdf2 salt", (b) => c.pbkdf2Sha512(M, B(b), pb)],
    ["hkdf key material", (b) => c.hkdfSha256(B(b), SALT16, { dkLen: 32 })],
    ["hkdf salt", (b) => c.hkdfSha256(K32, B(b), { dkLen: 32 })],
    ["hkdf key material", (b) => c.hkdfSha512(B(b), SALT16, { dkLen: 32 })],
    ["hkdf salt", (b) => c.hkdfSha512(K32, B(b), { dkLen: 32 })],
    ["scrypt password", (b) => c.scrypt(B(b), SALT16, { dkLen: 32, logN: 4 })],
    ["scrypt salt", (b) => c.scrypt(M, B(b), { dkLen: 32, logN: 4 })],
    ["argon2id password", (b) => c.argon2id(B(b), SALT16, { dkLen: 32 })],
    ["argon2id salt", (b) => c.argon2id(M, B(b), { dkLen: 32 })],
    ["ChaCha20-Poly1305 key", (b) => c.chacha20Poly1305.encrypt(B(b), N12, M)],
    ["ChaCha20-Poly1305 nonce", (b) => c.chacha20Poly1305.encrypt(K32, B(b), M)],
    ["ChaCha20-Poly1305 plaintext", (b) => c.chacha20Poly1305.encrypt(K32, N12, B(b))],
    ["ChaCha20-Poly1305 aad", (b) => c.chacha20Poly1305.encrypt(K32, N12, M, { aad: B(b) }), true],
    ["ChaCha20-Poly1305 key", (b) => c.chacha20Poly1305.decrypt(B(b), N12, SEALED)],
    ["ChaCha20-Poly1305 nonce", (b) => c.chacha20Poly1305.decrypt(K32, B(b), SEALED)],
    ["ChaCha20-Poly1305 sealed data", (b) => c.chacha20Poly1305.decrypt(K32, N12, B(b))],
    [
      "ChaCha20-Poly1305 aad",
      (b) => c.chacha20Poly1305.decrypt(K32, N12, SEALED, { aad: B(b) }),
      true,
    ],
    ["ChaCha20 key", (b) => c.chacha20(B(b), N12, M)],
    ["ChaCha20 nonce", (b) => c.chacha20(K32, B(b), M)],
    ["ChaCha20 data", (b) => c.chacha20(K32, N12, B(b))],
    ["X25519 private key", (b) => c.x25519.publicKey(B(b))],
    ["X25519 private key", (b) => c.x25519.sharedKey(B(b), K32)],
    ["X25519 public key", (b) => c.x25519.sharedKey(K32, B(b))],
    ["signing key material", (b) => c.deriveSigningPrivateKey(B(b))],
    ["agreement key material", (b) => c.deriveAgreementPrivateKey(B(b))],
    ["ECDSA private key", (b) => c.ecdsa.publicKey(B(b))],
    ["ECDSA compressed public key", (b) => c.ecdsa.decompressPublicKey(B(b))],
    ["ECDSA uncompressed public key", (b) => c.ecdsa.compressPublicKey(B(b))],
    ["ECDSA private key", (b) => c.ecdsa.sign(B(b), M)],
    ["ECDSA message", (b) => c.ecdsa.sign(K32, B(b))],
    ["ECDSA public key", (b) => c.ecdsa.verify(B(b), SIG64, M)],
    ["ECDSA signature", (b) => c.ecdsa.verify(P33, B(b), M)],
    ["ECDSA message", (b) => c.ecdsa.verify(P33, SIG64, B(b))],
    ["Schnorr private key", (b) => c.schnorr.publicKey(B(b))],
    ["Schnorr private key", (b) => c.schnorr.sign(B(b), M, { auxRand: K32 })],
    ["Schnorr message", (b) => c.schnorr.sign(K32, B(b), { auxRand: K32 })],
    ["Schnorr auxiliary randomness", (b) => c.schnorr.sign(K32, M, { auxRand: B(b) }), true],
    ["Schnorr public key", (b) => c.schnorr.verify(B(b), SIG64, M)],
    ["Schnorr signature", (b) => c.schnorr.verify(K32, B(b), M)],
    ["Schnorr message", (b) => c.schnorr.verify(K32, SIG64, B(b))],
    ["Ed25519 private key", (b) => c.ed25519.publicKey(B(b))],
    ["Ed25519 private key", (b) => c.ed25519.sign(B(b), M)],
    ["Ed25519 message", (b) => c.ed25519.sign(K32, B(b))],
    ["Ed25519 public key", (b) => c.ed25519.verify(B(b), EDSIG, M)],
    ["Ed25519 signature", (b) => c.ed25519.verify(EDPUB, B(b), M)],
    ["Ed25519 message", (b) => c.ed25519.verify(EDPUB, EDSIG, B(b))],
  ];
  /** Options positions: a required options object may not be missing; an optional one may. */
  const optionsPositions: [string, (bad: unknown) => unknown][] = [
    ["crc32 options", (o) => c.crc32Bytes(M, O(o))],
    ["pbkdf2 options", (o) => c.pbkdf2Sha256(M, SALT16, O(o))],
    ["pbkdf2 options", (o) => c.pbkdf2Sha512(M, SALT16, O(o))],
    ["hkdf options", (o) => c.hkdfSha256(K32, SALT16, O(o))],
    ["hkdf options", (o) => c.hkdfSha512(K32, SALT16, O(o))],
    ["scrypt options", (o) => c.scrypt(M, SALT16, O(o))],
    ["argon2id options", (o) => c.argon2id(M, SALT16, O(o))],
    ["ChaCha20-Poly1305 options", (o) => c.chacha20Poly1305.encrypt(K32, N12, M, O(o))],
    ["ChaCha20-Poly1305 options", (o) => c.chacha20Poly1305.decrypt(K32, N12, SEALED, O(o))],
    ["ChaCha20 options", (o) => c.chacha20(K32, N12, M, O(o))],
    ["X25519 options", (o) => c.x25519.generatePrivateKey(O(o))],
    ["ECDSA options", (o) => c.ecdsa.generatePrivateKey(O(o))],
    ["Schnorr options", (o) => c.schnorr.sign(K32, M, O(o))],
    ["Ed25519 options", (o) => c.ed25519.generatePrivateKey(O(o))],
  ];
  const rejects = (what: string, f: () => unknown): boolean => {
    try {
      f();
      return false;
    } catch (e) {
      return (
        c.CryptoError.isCryptoError(e) &&
        e.code === "InvalidParameter" &&
        e.details.code === "InvalidParameter" &&
        e.details.what === what
      );
    }
  };
  const notBytes = fc.anything().filter((v) => !isBytes(v));
  const notObject = fc
    .anything()
    .filter((v) => v !== undefined && (typeof v !== "object" || v === null));

  it("a byte position given anything but a Uint8Array is InvalidParameter naming it", () => {
    for (const [what, call, optional] of bytePositions) {
      const bad = optional === true ? notBytes.filter((v) => v !== undefined) : notBytes;
      fc.assert(
        fc.property(bad, (v) => rejects(what, () => call(v))),
        { numRuns: 100 },
      );
    }
  });
  it("an options position given a non-object is InvalidParameter naming it", () => {
    for (const [what, call] of optionsPositions) {
      fc.assert(
        fc.property(notObject, (bad) => rejects(what, () => call(bad))),
        { numRuns: 100 },
      );
    }
  });
  it("memzero and memzeroAll require numeric typed arrays", () => {
    const notTyped = fc.anything().filter((v) => !ArrayBuffer.isView(v));
    fc.assert(
      fc.property(notTyped, (bad) => rejects("memzero data", () => c.memzero(O(bad)))),
      { numRuns: 100 },
    );
    fc.assert(
      fc.property(
        notTyped.filter((v) => !Array.isArray(v)),
        (bad) => rejects("memzeroAll arrays", () => c.memzeroAll(O(bad))),
      ),
      { numRuns: 100 },
    );
    expect(rejects("memzero data", () => c.memzero(O(new DataView(new ArrayBuffer(4)))))).toBe(
      true,
    );
    expect(rejects("memzero data", () => c.memzero(O(new BigUint64Array(1))))).toBe(true);
    expect(rejects("memzero data", () => c.memzeroAll([O("x")]))).toBe(true);
  });
  it("littleEndian must be a boolean", () => {
    expect(rejects("crc32 littleEndian", () => c.crc32Bytes(M, { littleEndian: O(1) }))).toBe(true);
    expect(c.crc32Bytes(M, { littleEndian: undefined })).toEqual(c.crc32Bytes(M));
  });
  it("the executed regressions: engine TypeErrors, silent acceptance, misattribution", () => {
    const what = (f: () => unknown): string => {
      try {
        f();
        return "value";
      } catch (e) {
        return c.CryptoError.isCryptoError(e)
          ? `${e.code}:${e.details.code === "AuthenticationFailed" ? "" : e.details.what}`
          : `${(e as Error).name}`;
      }
    };
    expect(what(() => c.sha256(O("abc")))).toBe("InvalidParameter:sha256 data");
    expect(what(() => c.chacha20Poly1305.encrypt(O(Array(32)), N12, M))).toBe(
      "InvalidParameter:ChaCha20-Poly1305 key",
    );
    expect(what(() => c.crc32(O(undefined)))).toBe("InvalidParameter:crc32 data");
    expect(what(() => c.scrypt(M, SALT16, O(undefined)))).toBe("InvalidParameter:scrypt options");
    expect(what(() => c.pbkdf2Sha256(M, SALT16, O(undefined)))).toBe(
      "InvalidParameter:pbkdf2 options",
    );
    expect(what(() => c.crc32(O([1, 2, 3])))).toBe("InvalidParameter:crc32 data");
    expect(what(() => c.crc32Bytes(O("abc")))).toBe("InvalidParameter:crc32 data");
    expect(what(() => c.ed25519.verify(EDPUB, EDSIG, O("msg")))).toBe(
      "InvalidParameter:Ed25519 message",
    );
    expect(what(() => c.ed25519.verify(O(Array(32)), EDSIG, M))).toBe(
      "InvalidParameter:Ed25519 public key",
    );
    expect(what(() => c.ecdsa.verify(O(Array(33)), SIG64, M))).toBe(
      "InvalidParameter:ECDSA public key",
    );
    expect(what(() => c.ecdsa.sign(K32, O("msg")))).toBe("InvalidParameter:ECDSA message");
    expect(what(() => c.schnorr.sign(K32, O("msg"), { auxRand: K32 }))).toBe(
      "InvalidParameter:Schnorr message",
    );
    expect(what(() => c.x25519.sharedKey(O(Array(32)), O(Array(32))))).toBe(
      "InvalidParameter:X25519 private key",
    );
    expect(what(() => c.ecdsa.publicKey(O("x".repeat(32))))).toBe(
      "InvalidParameter:ECDSA private key",
    );
    expect(what(() => c.deriveAgreementPrivateKey(O("x")))).toBe(
      "InvalidParameter:agreement key material",
    );
    // The message names the argument and the received type.
    expect(() => c.ecdsa.sign(K32, O("msg"))).toThrow(
      "ECDSA message must be a Uint8Array, got string",
    );
    expect(() => c.crc32(O([1, 2, 3]))).toThrow("crc32 data must be a Uint8Array, got Array(3)");
    expect(() => c.crc32(O(new ArrayBuffer(3)))).toThrow(
      "crc32 data must be a Uint8Array, got ArrayBuffer",
    );
    expect(() => c.scrypt(M, SALT16, O(null))).toThrow(
      "scrypt options must be an object, got null",
    );
  });
  it("a Buffer and a Uint8Array from another realm are accepted", () => {
    const buffer = Buffer.from("abc");
    const foreign = runInNewContext("new Uint8Array([97, 98, 99])") as Uint8Array;
    expect(c.sha256(buffer)).toEqual(c.sha256(new TextEncoder().encode("abc")));
    expect(c.sha256(foreign)).toEqual(c.sha256(buffer));
    expect(c.crc32(foreign)).toBe(c.crc32(buffer));
    expect(c.chacha20Poly1305.encrypt(K32, N12, foreign)).toEqual(
      c.chacha20Poly1305.encrypt(K32, N12, buffer),
    );
  });
  it("a fillBytesPacked that is present but not a function is rand's InvalidGenerator", () => {
    let err: unknown;
    try {
      c.ed25519.generatePrivateKey({
        rng: O({ fillBytesPacked: 1, fillBytes() {} }),
      });
    } catch (e) {
      err = e;
    }
    expect(RandError.isRandError(err)).toBe(true);
    expect(RandError.isRandError(err) && err.code).toBe("InvalidGenerator");
    expect(
      RandError.isRandError(err) && err.details.code === "InvalidGenerator" && err.details.method,
    ).toBe("fillBytesPacked");
    expect(err).not.toBeInstanceOf(TypeError);
    expect(c.CryptoError.isCryptoError(err)).toBe(false);
  });
});

describe("verify never throws for inputs of the right length", () => {
  // The reference returns `false` for an unparseable key or signature
  // (`let Ok(..) = … else { return false; }`), so does the port.
  const isBool = (f: () => unknown): boolean => typeof f() === "boolean";
  it("ecdsa, schnorr and ed25519 return a boolean for random keys and signatures", () => {
    const k33 = fc.uint8Array({ minLength: 33, maxLength: 33 });
    const k32 = fc.uint8Array({ minLength: 32, maxLength: 32 });
    const sig = fc.uint8Array({ minLength: 64, maxLength: 64 });
    fc.assert(
      fc.property(k33, k32, sig, u8(16), (ecPub, pub32, s, m) =>
        [
          () => c.ecdsa.verify(ecPub, s, m),
          () => c.schnorr.verify(pub32, s, m),
          () => c.ed25519.verify(pub32, s, m),
        ].every(isBool),
      ),
      { numRuns: 200 },
    );
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
