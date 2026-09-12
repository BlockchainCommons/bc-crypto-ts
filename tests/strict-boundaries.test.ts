import { ED25519_STRICT_FIXTURES } from "./corpus/ed25519-strict-fixtures";
import { ed25519, chacha20, scrypt, CryptoError } from "../src";
const bytes = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));

describe("Ed25519 uncofactored equation", () => {
  it.each(ED25519_STRICT_FIXTURES)("handles torsion: $valid ($signature)", (f) => {
    expect(ed25519.verify(bytes(f.publicKey), bytes(f.signature), bytes(f.message))).toBe(f.valid);
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
