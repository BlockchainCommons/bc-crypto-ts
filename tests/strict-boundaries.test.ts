import { ed25519 as noble } from "@noble/curves/ed25519.js";
import { ED25519_STRICT_FIXTURES } from "./corpus/ed25519-strict-fixtures";
import { ED_NONCANONICAL_DECODABLE_K, ED_NONCANONICAL_UNDECODABLE_K } from "./corpus/corpus";
import { SIGNED } from "./corpus/verify-fixtures";
import { ed25519, chacha20, scrypt, CryptoError } from "../src";
const bytes = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("Ed25519 uncofactored equation", () => {
  it.each(ED25519_STRICT_FIXTURES)("handles torsion: $valid ($signature)", (f) => {
    expect(ed25519.verify(bytes(f.publicKey), bytes(f.signature), bytes(f.message))).toBe(f.valid);
  });
});

/**
 * The decoder boundary: dalek's `CompressedEdwardsY::decompress` reduces a
 * non-canonical y (`y = p + k` reads as `y = k`) and decodes it when the
 * reduced point has a square root; the tree decodes canonically and rejects
 * every such encoding. noble's `zip215 = true` applies dalek's rule, so the
 * two lists in the corpus pin exactly which encodings each decoder takes.
 * The difference is unobservable through `verify`: both sides return
 * `false` for every one of these keys and for the same encodings as R.
 */
describe("Ed25519 decoder boundary (non-canonical y = p + k)", () => {
  const P = (1n << 255n) - 19n;
  const enc = (y: bigint, sign: boolean): Uint8Array => {
    const b = Uint8Array.from({ length: 32 }, (_, i) => Number((y >> BigInt(8 * i)) & 0xffn));
    if (sign) b[31] |= 0x80;
    return b;
  };
  const decodes = (b: Uint8Array, zip215: boolean): boolean => {
    try {
      noble.Point.fromBytes(b, zip215);
      return true;
    } catch {
      return false;
    }
  };
  /** The 40 encodings: y = p + k for k = 0..18 with both sign bits, y = 1 and y = p − 1 with the sign bit. */
  const forty: Uint8Array[] = [];
  for (let k = 0; k <= 18; k++)
    for (const sign of [false, true]) forty.push(enc(P + BigInt(k), sign));
  forty.push(enc(1n, true), enc(P - 1n, true));
  const fixture = SIGNED.find((t) => t.scheme === "ed25519");
  if (fixture === undefined) throw new Error("no ed25519 fixture");
  const pub = bytes(fixture.pub);
  const sig = bytes(fixture.sig);
  const msg = bytes(fixture.msg);

  it("dalek's rule decodes exactly the k with a square root; canonical decoding takes none of the 40", () => {
    expect(
      [...ED_NONCANONICAL_DECODABLE_K, ...ED_NONCANONICAL_UNDECODABLE_K].sort((a, b) => a - b),
    ).toEqual(Array.from({ length: 19 }, (_, k) => k));
    let dalekRejects = 0;
    for (let k = 0; k <= 18; k++) {
      for (const sign of [false, true]) {
        const e = enc(P + BigInt(k), sign);
        expect(decodes(e, true)).toBe(ED_NONCANONICAL_DECODABLE_K.includes(k));
        if (!decodes(e, true)) dalekRejects++;
      }
    }
    expect(dalekRejects).toBe(14);
    expect(forty.filter((e) => !decodes(e, false))).toHaveLength(40);
    expect(forty.filter((e) => decodes(e, true))).toHaveLength(26);
  });
  it("the four small-order re-encodings under dalek's rule", () => {
    const re = (h: string): string => hex(noble.Point.fromBytes(bytes(h), true).toBytes());
    expect(re("ee" + "ff".repeat(31))).toBe("01" + "00".repeat(31));
    expect(re("01" + "00".repeat(30) + "80")).toBe("01" + "00".repeat(31));
    expect(re("ec" + "ff".repeat(31))).toBe("ec" + "ff".repeat(30) + "7f");
    expect(re("ed" + "ff".repeat(31))).toBe("00".repeat(31) + "80");
  });
  it("verify is false for every one of the 40 as A and as R, with the fixture's honest signature", () => {
    expect(ed25519.verify(pub, sig, msg)).toBe(true);
    for (const e of forty) {
      expect(ed25519.verify(e, sig, msg)).toBe(false);
      const r = new Uint8Array(64);
      r.set(e, 0);
      r.set(sig.subarray(32), 32);
      expect(ed25519.verify(pub, r, msg)).toBe(false);
    }
  });
});
describe("backend boundaries", () => {
  const key = new Uint8Array(32),
    nonce = new Uint8Array(12);
  it("uses the last available ChaCha20 block without reaching the reserved counter", () => {
    const data = new Uint8Array(64);
    const result = chacha20(key, nonce, data, { counter: 0xfffffffe });
    expect(chacha20(key, nonce, result, { counter: 0xfffffffe })).toEqual(data);
    expect(chacha20(key, nonce, new Uint8Array(0), { counter: 0xfffffffe })).toHaveLength(0);
  });
  it.each([0, 1, 64])("rejects the reserved initial counter for %i bytes", (n) => {
    expect(() => chacha20(key, nonce, new Uint8Array(n), { counter: 0xffffffff })).toThrow(
      CryptoError,
    );
  });
  it("rejects a message that would exhaust the counter space", () => {
    expect(() => chacha20(key, nonce, new Uint8Array(65), { counter: 0xfffffffe })).toThrow(
      CryptoError,
    );
  });
  it("rejects unsupported scrypt logN before allocating memory", () => {
    expect(() =>
      scrypt(key, nonce, { dkLen: 32, logN: 33, maxmem: Number.MAX_SAFE_INTEGER }),
    ).toThrow(CryptoError);
  });
});
