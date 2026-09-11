/**
 * Golden snapshots: every function over a fixed input corpus, with the
 * seeded RNG wherever randomness is drawn.
 */
import * as c from "../src";
import { SeededRng, randomBytes } from "@blockchaincommons/rand";

const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const bytes = (n: number, start = 0): Uint8Array =>
  Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
const text = (s: string): Uint8Array => new TextEncoder().encode(s);

const INPUTS: [string, Uint8Array][] = [
  ["empty", new Uint8Array(0)],
  ["1", bytes(1)],
  ["31", bytes(31)],
  ["32", bytes(32)],
  ["33", bytes(33)],
  ["63", bytes(63)],
  ["64", bytes(64)],
  ["65", bytes(65)],
  ["1024", bytes(1024, 7)],
  ["hello", text("hello world")],
];
const KEY = bytes(32, 0x10);
const NONCE = bytes(12, 0xa0);
const SALT = bytes(16, 0x50);
const AAD = text("aad");
const PRIV = bytes(32, 0x01);

describe("golden: hashes", () => {
  for (const [n, d] of INPUTS) {
    it(`sha256/sha512/double/crc32 (${n})`, () => {
      expect([
        hex(c.sha256(d)),
        hex(c.doubleSha256(d)),
        hex(c.sha512(d)),
        c.crc32(d),
        hex(c.crc32Bytes(d)),
        hex(c.crc32Bytes(d, { littleEndian: true })),
      ]).toMatchSnapshot();
    });
    it(`hmac (${n})`, () => {
      expect([hex(c.hmacSha256(KEY, d)), hex(c.hmacSha512(KEY, d))]).toMatchSnapshot();
    });
  }
  it("pbkdf2 / hkdf", () => {
    expect([
      hex(c.pbkdf2Sha256(text("password"), SALT, { iterations: 1000, dkLen: 32 })),
      hex(c.pbkdf2Sha512(text("password"), SALT, { iterations: 100, dkLen: 64 })),
      hex(c.hkdfSha256(KEY, SALT, { dkLen: 32 })),
      hex(c.hkdfSha256(KEY, SALT, { dkLen: 16 })),
      hex(c.hkdfSha256(KEY, SALT, { dkLen: 64 })),
      hex(c.hkdfSha512(KEY, SALT, { dkLen: 64 })),
    ]).toMatchSnapshot();
  });
  it("scrypt / argon2id (defaults and custom)", () => {
    expect([
      hex(c.scrypt(text("pw"), SALT, { dkLen: 32 })),
      hex(c.scrypt(text("pw"), SALT, { dkLen: 32, logN: 2, r: 8, p: 1 })),
      hex(c.argon2id(text("pw"), SALT, { dkLen: 32 })),
    ]).toMatchSnapshot();
  });
});

describe("golden: symmetric", () => {
  for (const [n, d] of INPUTS) {
    it(`chacha20poly1305 (${n})`, () => {
      // Snapshot layout is [ct, tag, ctA, tagA] from the pre-redesign tuple API.
      const sealed = c.chacha20Poly1305.encrypt(KEY, NONCE, d);
      const sealedA = c.chacha20Poly1305.encrypt(KEY, NONCE, d, { aad: AAD });
      const split = (s: Uint8Array) => [
        hex(s.subarray(0, s.length - 16)),
        hex(s.subarray(s.length - 16)),
      ];
      expect([...split(sealed), ...split(sealedA)]).toMatchSnapshot();
      expect(hex(c.chacha20Poly1305.decrypt(KEY, NONCE, sealed))).toBe(hex(d));
      expect(hex(c.chacha20Poly1305.decrypt(KEY, NONCE, sealedA, { aad: AAD }))).toBe(hex(d));
    });
  }
  it("rejects a tampered tag", () => {
    const sealed = c.chacha20Poly1305.encrypt(KEY, NONCE, bytes(20));
    sealed[20] ^= 1;
    let name = "";
    try {
      c.chacha20Poly1305.decrypt(KEY, NONCE, sealed);
    } catch (e) {
      name = (e as Error).name;
    }
    expect(name).toMatchSnapshot();
  });
});

describe("golden: keys and signatures", () => {
  it("x25519", () => {
    const pub = c.x25519.publicKey(PRIV);
    const other = c.x25519.publicKey(bytes(32, 0x40));
    expect([
      hex(pub),
      hex(c.x25519.sharedKey(PRIV, other)),
      hex(c.deriveAgreementPrivateKey(KEY)),
      hex(c.deriveSigningPrivateKey(KEY)),
      hex(c.x25519.generatePrivateKey({ rng: SeededRng.forTesting() })),
    ]).toMatchSnapshot();
  });
  it("ecdsa / schnorr", () => {
    const pub = c.ecdsa.publicKey(PRIV);
    const un = c.ecdsa.decompressPublicKey(pub);
    const msg = text("message");
    expect([
      hex(pub),
      hex(un),
      hex(c.ecdsa.compressPublicKey(un)),
      hex(c.deriveSigningPrivateKey(KEY)),
      hex(c.schnorr.publicKey(PRIV)),
      hex(c.ecdsa.sign(PRIV, msg)),
      c.ecdsa.verify(pub, c.ecdsa.sign(PRIV, msg), msg),
      hex(c.schnorr.sign(PRIV, msg, { auxRand: bytes(32, 0x77) })),
      hex(c.schnorr.sign(PRIV, msg, { rng: SeededRng.forTesting() })),
      hex(c.ecdsa.generatePrivateKey({ rng: SeededRng.forTesting() })),
    ]).toMatchSnapshot();
  });
  it("ed25519", () => {
    const pub = c.ed25519.publicKey(PRIV);
    const msg = text("message");
    const sig = c.ed25519.sign(PRIV, msg);
    expect([
      hex(pub),
      hex(sig),
      c.ed25519.verify(pub, sig, msg),
      hex(c.ed25519.generatePrivateKey({ rng: SeededRng.forTesting() })),
    ]).toMatchSnapshot();
  });
  it("size errors", () => {
    const short = bytes(31);
    const names: string[] = [];
    for (const f of [
      () => c.ecdsa.publicKey(short),
      () => c.ed25519.publicKey(short),
      () => c.x25519.publicKey(short),
      () => c.ecdsa.sign(short, short),
    ]) {
      try {
        f();
        names.push("ok");
      } catch (e) {
        names.push(`${(e as Error).name}: ${(e as Error).message}`);
      }
    }
    expect(names).toMatchSnapshot();
  });
  it("memzero", () => {
    const a = bytes(8);
    c.memzero(a);
    const arrs = [bytes(4), bytes(4, 9)];
    c.memzeroAll(arrs);
    expect([
      hex(a),
      arrs.map(hex),
      hex(randomBytes(4, { rng: SeededRng.forTesting() })),
    ]).toMatchSnapshot();
  });
});

/**
 * Freeze additions: today's behaviour on inputs known to have edge-case
 * outcomes, recorded verbatim so future changes show up as snapshot diffs
 * rather than silent drift.
 */
describe("golden: freeze additions (B1–B5)", () => {
  const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v);
  const one = (n: number): Uint8Array => {
    const u = new Uint8Array(n);
    u[0] = 1;
    return u;
  };
  const outcome = (f: () => unknown): string => {
    try {
      const v = f();
      return v instanceof Uint8Array ? hex(v) : String(v);
    } catch (e) {
      return `throw:${(e as Error).name}:${(e as Error).message}`;
    }
  };
  const msg = text("hi");
  // The identity point encodes as 01‖00…; y = p + 1 is its non-canonical encoding.
  const identity = one(32);
  const nonCanonicalIdentity = fill(32, 0xff);
  nonCanonicalIdentity[0] = 0xee;
  nonCanonicalIdentity[31] = 0x7f;
  const identitySignature = new Uint8Array(64);
  identitySignature[0] = 1;
  const nonCanonicalRSignature = new Uint8Array(64);
  nonCanonicalRSignature.set(nonCanonicalIdentity, 0);

  it("B1: ed25519.verify on a small-order key / non-canonical encodings (today: true)", () => {
    expect([
      outcome(() => c.ed25519.verify(identity, identitySignature, msg)),
      outcome(() => c.ed25519.verify(nonCanonicalIdentity, identitySignature, msg)),
      outcome(() => c.ed25519.verify(identity, nonCanonicalRSignature, msg)),
    ]).toMatchSnapshot();
  });
  it("B2: x25519.sharedKey with a low-order public key (today: noble's Error)", () => {
    expect([
      outcome(() => c.x25519.sharedKey(PRIV, new Uint8Array(32))),
      outcome(() => c.x25519.sharedKey(PRIV, one(32))),
    ]).toMatchSnapshot();
  });
  it("B3: verify on malformed keys and signatures of the right length (today: false)", () => {
    const ecdsaPub = c.ecdsa.publicKey(PRIV);
    expect([
      outcome(() => c.ecdsa.verify(ecdsaPub, fill(64, 0xff), msg)),
      outcome(() =>
        c.ecdsa.verify(Uint8Array.from([2, ...fill(32, 0xff)]), c.ecdsa.sign(PRIV, msg), msg),
      ),
      outcome(() =>
        c.schnorr.verify(fill(32, 0xff), c.schnorr.sign(PRIV, msg, { auxRand: bytes(32) }), msg),
      ),
      outcome(() => c.schnorr.verify(c.schnorr.publicKey(PRIV), fill(64, 0xff), msg)),
      outcome(() => c.ed25519.verify(fill(32, 0xff), c.ed25519.sign(PRIV, msg), msg)),
      outcome(() => c.ed25519.verify(c.ed25519.publicKey(PRIV), fill(64, 0xff), msg)),
    ]).toMatchSnapshot();
  });
  it("B4: faults that escape CryptoError (today: noble's own errors)", () => {
    const n = Uint8Array.from(
      Buffer.from("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "hex"),
    );
    const pw = text("pw");
    expect(
      Object.fromEntries(
        (
          [
            ["ecdsa.publicKey(0)", () => c.ecdsa.publicKey(new Uint8Array(32))],
            ["schnorr.publicKey(0)", () => c.schnorr.publicKey(new Uint8Array(32))],
            ["ecdsa.publicKey(n)", () => c.ecdsa.publicKey(n)],
            ["ecdsa.sign(0)", () => c.ecdsa.sign(new Uint8Array(32), msg)],
            [
              "ecdsa.decompressPublicKey(02‖ff*32)",
              () => c.ecdsa.decompressPublicKey(Uint8Array.from([2, ...fill(32, 0xff)])),
            ],
            [
              "ecdsa.compressPublicKey(04‖01*64)",
              () => c.ecdsa.compressPublicKey(Uint8Array.from([4, ...fill(64, 1)])),
            ],
            ["scrypt dkLen 0", () => c.scrypt(pw, SALT, { dkLen: 0 })],
            ["scrypt logN 0", () => c.scrypt(pw, SALT, { dkLen: 32, logN: 0 })],
            ["scrypt r 1.5", () => c.scrypt(pw, SALT, { dkLen: 32, r: 1.5 })],
            ["argon2id dkLen 3", () => c.argon2id(pw, SALT, { dkLen: 3 })],
            ["argon2id salt 4", () => c.argon2id(pw, bytes(4), { dkLen: 32 })],
            ["argon2id t 0", () => c.argon2id(pw, SALT, { dkLen: 32, t: 0 })],
            ["hkdfSha256 length 8161", () => c.hkdfSha256(KEY, SALT, { dkLen: 8161 })],
            ["hkdfSha256 length 1.5", () => c.hkdfSha256(KEY, SALT, { dkLen: 1.5 })],
            [
              "pbkdf2Sha256 iterations 0",
              () => c.pbkdf2Sha256(pw, SALT, { iterations: 0, dkLen: 32 }),
            ],
            ["pbkdf2Sha256 dkLen 0", () => c.pbkdf2Sha256(pw, SALT, { iterations: 1, dkLen: 0 })],
            ["chacha20 counter -1", () => c.chacha20(KEY, NONCE, bytes(8), { counter: -1 })],
          ] as [string, () => unknown][]
        ).map(([k, f]) => [k, outcome(f)]),
      ),
    ).toMatchSnapshot();
  });
  it("B5: scrypt output length below the reference's opt bound (today: accepted)", () => {
    expect([
      outcome(() => c.scrypt(text("pw"), SALT, { dkLen: 8, logN: 4 })),
      outcome(() => c.scrypt(text("pw"), SALT, { dkLen: 8 })),
    ]).toMatchSnapshot();
  });
});
