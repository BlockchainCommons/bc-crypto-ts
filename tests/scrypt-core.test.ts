/**
 * The paged scrypt core equals noble (and so the reference) byte for byte,
 * under forced tiny pages as well as the default page size, and reproduces
 * the RFC 7914 §12 vectors.
 */
import fc from "fast-check";
import { scrypt as nobleScrypt } from "@noble/hashes/scrypt.js";
import { scryptCore } from "../src/scrypt-core";

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("scrypt core", () => {
  it("equals noble for small parameter sets under one-block, three-block and default pages", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 10 }),
        fc.integer({ min: 1, max: 8 }),
        fc.integer({ min: 1, max: 3 }),
        fc.integer({ min: 10, max: 64 }),
        fc.uint8Array({ maxLength: 40 }),
        fc.uint8Array({ maxLength: 40 }),
        fc.constantFrom("one", "three", "default"),
        (logN, r, p, dkLen, pw, salt, pages) => {
          const N = 2 ** logN;
          const pageBytes = pages === "one" ? 128 * r : pages === "three" ? 3 * 128 * r : undefined;
          const want = hex(nobleScrypt(pw, salt, { N, r, p, dkLen, maxmem: 2 ** 40 }));
          return hex(scryptCore(pw, salt, { N, r, p, dkLen, pageBytes })) === want;
        },
      ),
      { numRuns: 40 },
    );
  });
  it("RFC 7914 §12 vectors", () => {
    expect(hex(scryptCore(utf8(""), utf8(""), { N: 16, r: 1, p: 1, dkLen: 64 }))).toBe(
      "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
    );
    expect(
      hex(scryptCore(utf8("password"), utf8("NaCl"), { N: 1024, r: 8, p: 16, dkLen: 64 })),
    ).toBe(
      "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    );
    expect(
      hex(
        scryptCore(utf8("pleaseletmein"), utf8("SodiumChloride"), {
          N: 16384,
          r: 8,
          p: 1,
          dkLen: 64,
          pageBytes: 3 * 128 * 8,
        }),
      ),
    ).toBe(
      "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
    );
  });
  it("pages hold whole blocks and the last page may be short", () => {
    // N = 5 blocks of 128·r bytes in pages of 2 blocks: the core must still
    // address every block; a wrong page size would corrupt the mix.
    const pw = utf8("pw");
    const salt = utf8("salt");
    const want = hex(nobleScrypt(pw, salt, { N: 8, r: 2, p: 3, dkLen: 32 }));
    for (const pageBytes of [256, 512, 700, 1024, 4096]) {
      expect(hex(scryptCore(pw, salt, { N: 8, r: 2, p: 3, dkLen: 32, pageBytes }))).toBe(want);
    }
  });
});
