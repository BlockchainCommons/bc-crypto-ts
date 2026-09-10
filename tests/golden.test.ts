/**
 * Golden snapshots (Phase 0.2): every function over a fixed input corpus,
 * with the seeded RNG wherever randomness is drawn.
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
      hex(c.hkdfSha256(KEY, SALT, 32)),
      hex(c.hkdfSha256(KEY, SALT, 16)),
      hex(c.hkdfSha256(KEY, SALT, 64)),
      hex(c.hkdfSha512(KEY, SALT, 64)),
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
      hex(c.x25519.deriveAgreementPrivateKey(KEY)),
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
      hex(c.ecdsa.derivePrivateKey(KEY)),
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
