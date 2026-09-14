/**
 * What reaches the KDF backends: PBKDF2's `dkLen` domain is RFC 8018's
 * (2^32 − 1)·hLen, and scrypt passes no memory ceiling unless asked. Spies
 * on the noble entry points show the forwarded options without deriving.
 */
import { vi } from "vitest";
import * as c from "../src";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { scrypt as nobleScrypt } from "@noble/hashes/scrypt.js";
import type * as Pbkdf2Module from "@noble/hashes/pbkdf2.js";
import type * as ScryptModule from "@noble/hashes/scrypt.js";

vi.mock("@noble/hashes/pbkdf2.js", async (importOriginal) => {
  const actual = await importOriginal<typeof Pbkdf2Module>();
  return { ...actual, pbkdf2: vi.fn(actual.pbkdf2) };
});
vi.mock("@noble/hashes/scrypt.js", async (importOriginal) => {
  const actual = await importOriginal<typeof ScryptModule>();
  return { ...actual, scrypt: vi.fn(actual.scrypt) };
});

const pw = new TextEncoder().encode("pw");
const salt = new Uint8Array(16).fill(0x50);
const U32_MAX = 2 ** 32 - 1;

describe("PBKDF2 dkLen up to (2^32 − 1)·hLen; iterations 0 stays InvalidParameter", () => {
  afterEach(() => {
    vi.mocked(pbkdf2).mockReset();
  });
  it("a dkLen above 2^32 − 1 reaches noble (2^32, no derivation)", () => {
    vi.mocked(pbkdf2).mockImplementationOnce(() => new Uint8Array(0));
    c.pbkdf2Sha256(pw, salt, { iterations: 1, dkLen: 2 ** 32 });
    expect(vi.mocked(pbkdf2)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(pbkdf2).mock.calls[0]?.[3]).toEqual({ c: 1, dkLen: 2 ** 32 });
  });
  it("the bound is the RFC 8018 one for each hash", () => {
    vi.mocked(pbkdf2).mockImplementation(() => new Uint8Array(0));
    expect(() => c.pbkdf2Sha256(pw, salt, { iterations: 1, dkLen: U32_MAX * 32 })).not.toThrow();
    expect(() => c.pbkdf2Sha512(pw, salt, { iterations: 1, dkLen: U32_MAX * 64 })).not.toThrow();
    expect(() => c.pbkdf2Sha256(pw, salt, { iterations: 1, dkLen: U32_MAX * 32 + 1 })).toThrow(
      `pbkdf2 dkLen must be an integer in [0, ${U32_MAX * 32}], got ${U32_MAX * 32 + 1}`,
    );
    expect(() => c.pbkdf2Sha512(pw, salt, { iterations: 1, dkLen: U32_MAX * 64 + 1 })).toThrow(
      `pbkdf2 dkLen must be an integer in [0, ${U32_MAX * 64}], got ${U32_MAX * 64 + 1}`,
    );
  });
  it("iterations 0 is InvalidParameter at every length, including empty output (the reference asserts)", () => {
    for (const dkLen of [0, 32, 65]) {
      for (const f of [c.pbkdf2Sha256, c.pbkdf2Sha512]) {
        let err: unknown;
        try {
          f(pw, salt, { iterations: 0, dkLen });
        } catch (e) {
          err = e;
        }
        expect(c.CryptoError.isCryptoError(err) && err.code).toBe("InvalidParameter");
        expect((err as Error).message).toBe(
          `pbkdf2 iterations must be an integer in [1, ${U32_MAX}], got 0`,
        );
      }
    }
    expect(vi.mocked(pbkdf2)).not.toHaveBeenCalled();
  });
});

describe("scrypt has no default memory ceiling", () => {
  afterEach(() => {
    vi.mocked(nobleScrypt).mockReset();
  });
  it("forwards MAX_SAFE_INTEGER unless maxmem is given", () => {
    vi.mocked(nobleScrypt).mockImplementation(() => new Uint8Array(32));
    c.scrypt(pw, salt, { dkLen: 32, logN: 4 });
    c.scrypt(pw, salt, { dkLen: 32, logN: 4, maxmem: 1 << 30 });
    const calls = vi.mocked(nobleScrypt).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls[0]?.[2]).toEqual({
      N: 16,
      r: 8,
      p: 1,
      dkLen: 32,
      maxmem: Number.MAX_SAFE_INTEGER,
    });
    expect(calls[1]?.[2]).toEqual({ N: 16, r: 8, p: 1, dkLen: 32, maxmem: 1 << 30 });
  });
  it("an explicit ceiling is still enforced by the backend, with the cause attached", () => {
    let err: unknown;
    try {
      c.scrypt(pw, salt, { dkLen: 32, logN: 4, maxmem: 1 });
    } catch (e) {
      err = e;
    }
    expect(c.CryptoError.isCryptoError(err) && err.is("InvalidParameter")).toBe(true);
    expect((err as Error).cause).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/maxmem/);
  });
});
