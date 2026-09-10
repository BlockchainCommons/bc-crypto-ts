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
        c.hash.crc32(d),
        hex(c.hash.crc32Data(d)),
        hex(c.hash.crc32DataOpt(d, true)),
      ]).toMatchSnapshot();
    });
    it(`hmac (${n})`, () => {
      expect([hex(c.hmacSha256(KEY, d)), hex(c.hmacSha512(KEY, d))]).toMatchSnapshot();
    });
  }
  it("pbkdf2 / hkdf", () => {
    expect([
      hex(c.pbkdf2HmacSha256(text("password"), SALT, 1000, 32)),
      hex(c.hash.pbkdf2HmacSha512(text("password"), SALT, 100, 64)),
      hex(c.hkdfHmacSha256(KEY, SALT, 32)),
      hex(c.hkdfHmacSha256(KEY, SALT, 16)),
      hex(c.hkdfHmacSha256(KEY, SALT, 64)),
      hex(c.hash.hkdfHmacSha512(KEY, SALT, 64)),
    ]).toMatchSnapshot();
  });
  it("scrypt / argon2id (defaults and custom)", () => {
    expect([
      hex(c.scrypt(text("pw"), SALT, 32)),
      hex(c.scryptOpt(text("pw"), SALT, 32, 2, 8, 1)),
      hex(c.argon2id(text("pw"), SALT, 32)),
    ]).toMatchSnapshot();
  });
});

describe("golden: symmetric", () => {
  for (const [n, d] of INPUTS) {
    it(`chacha20poly1305 (${n})`, () => {
      const [ct, tag] = c.aeadChaCha20Poly1305Encrypt(d, KEY, NONCE);
      const [ctA, tagA] = c.aeadChaCha20Poly1305EncryptWithAad(d, KEY, NONCE, AAD);
      expect([hex(ct), hex(tag), hex(ctA), hex(tagA)]).toMatchSnapshot();
      expect(hex(c.aeadChaCha20Poly1305Decrypt(ct, KEY, NONCE, tag))).toBe(hex(d));
      expect(hex(c.aeadChaCha20Poly1305DecryptWithAad(ctA, KEY, NONCE, AAD, tagA))).toBe(hex(d));
    });
  }
  it("rejects a tampered tag", () => {
    const [ct, tag] = c.aeadChaCha20Poly1305Encrypt(bytes(20), KEY, NONCE);
    tag[0] ^= 1;
    let name = "";
    try {
      c.aeadChaCha20Poly1305Decrypt(ct, KEY, NONCE, tag);
    } catch (e) {
      name = (e as Error).name;
    }
    expect(name).toMatchSnapshot();
  });
});

describe("golden: keys and signatures", () => {
  it("x25519", () => {
    const pub = c.x25519PublicKeyFromPrivateKey(PRIV);
    const other = c.x25519PublicKeyFromPrivateKey(bytes(32, 0x40));
    expect([
      hex(pub),
      hex(c.x25519SharedKey(PRIV, other)),
      hex(c.deriveAgreementPrivateKey(KEY)),
      hex(c.deriveSigningPrivateKey(KEY)),
      hex(c.x25519NewPrivateKeyUsing(SeededRng.forTesting())),
    ]).toMatchSnapshot();
  });
  it("ecdsa / schnorr", () => {
    const pub = c.ecdsaPublicKeyFromPrivateKey(PRIV);
    const un = c.ecdsaDecompressPublicKey(pub);
    const msg = text("message");
    expect([
      hex(pub),
      hex(un),
      hex(c.ecdsaCompressPublicKey(un)),
      hex(c.ecdsaDerivePrivateKey(KEY)),
      hex(c.schnorrPublicKeyFromPrivateKey(PRIV)),
      hex(c.ecdsaSign(PRIV, msg)),
      c.ecdsaVerify(pub, c.ecdsaSign(PRIV, msg), msg),
      hex(c.schnorrSignWithAuxRand(PRIV, msg, bytes(32, 0x77))),
      hex(c.schnorrSignUsing(PRIV, msg, SeededRng.forTesting())),
      hex(c.ecdsaNewPrivateKeyUsing(SeededRng.forTesting())),
    ]).toMatchSnapshot();
  });
  it("ed25519", () => {
    const pub = c.ed25519PublicKeyFromPrivateKey(PRIV);
    const msg = text("message");
    const sig = c.ed25519Sign(PRIV, msg);
    expect([
      hex(pub),
      hex(sig),
      c.ed25519Verify(pub, msg, sig),
      hex(c.ed25519NewPrivateKeyUsing(SeededRng.forTesting())),
    ]).toMatchSnapshot();
  });
  it("size errors", () => {
    const short = bytes(31);
    const names: string[] = [];
    for (const f of [
      () => c.ecdsaPublicKeyFromPrivateKey(short),
      () => c.ed25519PublicKeyFromPrivateKey(short),
      () => c.x25519PublicKeyFromPrivateKey(short),
      () => c.ecdsaSign(short, short),
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
    c.memzeroVecVecU8(arrs);
    expect([
      hex(a),
      arrs.map(hex),
      hex(randomBytes(4, { rng: SeededRng.forTesting() })),
    ]).toMatchSnapshot();
  });
});
