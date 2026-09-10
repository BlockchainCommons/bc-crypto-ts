/**
 * Deterministic differential corpus (Phase 1.3): input lengths at block
 * boundaries, key/nonce/salt boundaries, AAD present/absent, every exposed
 * KDF parameter, and seeded key generation. Pure and deterministic.
 */
import type { Recipe, Bytes } from "../vectors/recipes";

const cyc = (n: number, start = 0): Bytes => ({ cycle: n, start });
const txt = (t: string): Bytes => ({ text: t });
export const LENGTHS: number[] = [
  0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 4096,
];
const SEEDS = [
  ["17295166580085024720", "422929670265678780", "5577237070365765850", "7953171132032326923"],
  ["1", "1", "1", "1"],
  ["81985529216486895", "18364758544493064720", "3735928559", "14627333968358932480"],
  ["0", "0", "0", "1"],
];
const KEYS = [cyc(32, 0x10), cyc(32, 0x00), cyc(32, 0xff), { hex: "00".repeat(32) }];
const PRIVS = [
  cyc(32, 1),
  cyc(32, 0x42),
  { hex: "0000000000000000000000000000000000000000000000000000000000000001" },
  { hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
  cyc(32, 0x99),
];

function* hashes(): Generator<Recipe> {
  for (const n of LENGTHS) {
    for (const start of [0, 0x80]) {
      const d = cyc(n, start);
      yield { k: "sha256", d };
      yield { k: "doubleSha256", d };
      yield { k: "sha512", d };
      yield { k: "crc32", d };
      yield { k: "crc32Bytes", d, le: false };
      yield { k: "crc32Bytes", d, le: true };
      for (const key of KEYS.slice(0, 2)) {
        yield { k: "hmacSha256", key, d };
        yield { k: "hmacSha512", key, d };
      }
    }
  }
}
function* kdfs(): Generator<Recipe> {
  for (const pw of [txt("password"), txt(""), cyc(64, 3)]) {
    for (const salt of [cyc(16, 0x50), cyc(32, 0xaa)]) {
      for (const len of [16, 32, 64]) {
        yield { k: "hkdfSha256", key: pw, salt, len };
        yield { k: "hkdfSha512", key: pw, salt, len };
        yield { k: "pbkdf2Sha256", pw, salt, iter: 10, len };
        yield { k: "pbkdf2Sha512", pw, salt, iter: 10, len };
      }
      yield { k: "scrypt", pw, salt, len: 32 };
      yield { k: "scrypt", pw, salt, len: 32, n: 4, r: 8, p: 1 };
      yield { k: "scrypt", pw, salt, len: 64, n: 16, r: 4, p: 2 };
      yield { k: "argon2id", pw, salt, len: 32 };
    }
  }
}
function* aead(): Generator<Recipe> {
  for (const n of LENGTHS) {
    for (const key of KEYS) {
      const pt = cyc(n, 5),
        nonce = cyc(12, 0xa0);
      yield { k: "aeadEncrypt", pt, key, nonce };
      yield { k: "aeadEncrypt", pt, key, nonce, aad: txt("aad") };
      yield { k: "aeadEncrypt", pt, key, nonce, aad: cyc(0) };
    }
  }
  // rejection: wrong key / wrong tag / wrong aad
  yield { k: "aeadDecrypt", ct: cyc(36), key: KEYS[0], nonce: cyc(12, 0xa0) };
  yield { k: "aeadDecrypt", ct: cyc(16), key: KEYS[0], nonce: cyc(12, 0xa0), aad: txt("x") };
  yield { k: "aeadDecrypt", ct: cyc(15), key: KEYS[0], nonce: cyc(12, 0xa0) };
  yield { k: "aeadEncrypt", pt: cyc(3), key: cyc(31), nonce: cyc(12) };
  yield { k: "aeadEncrypt", pt: cyc(3), key: cyc(32), nonce: cyc(11) };
}
function* keys(): Generator<Recipe> {
  for (const priv of PRIVS) {
    yield { k: "x25519Pub", priv };
    yield { k: "ecdsaPub", priv };
    yield { k: "schnorrPub", priv };
    yield { k: "ed25519Pub", priv };
    for (const other of PRIVS.slice(0, 2)) yield { k: "x25519Shared", priv, pub: other };
    for (const n of [0, 1, 32, 100]) {
      const msg = cyc(n, 7);
      yield { k: "ecdsaSign", priv, msg };
      yield { k: "ed25519Sign", priv, msg };
      yield { k: "schnorrSignAux", priv, msg, aux: cyc(32, 0x77) };
      for (const seed of SEEDS.slice(0, 2)) yield { k: "schnorrSignRng", priv, msg, seed };
    }
  }
  for (const km of [cyc(32, 0x10), cyc(16), cyc(64, 0xf0), txt("key material")]) {
    yield { k: "deriveAgreement", km };
    yield { k: "deriveSigning", km };
    yield { k: "ecdsaDerive", km };
  }
  for (const seed of SEEDS)
    for (const alg of ["ecdsa", "ed25519", "x25519"] as const) yield { k: "newPriv", alg, seed };
  yield { k: "ecdsaPub", priv: cyc(31) };
  yield { k: "ed25519Pub", priv: cyc(33) };
  yield { k: "x25519Pub", priv: cyc(0) };
  yield { k: "ecdsaSign", priv: cyc(31), msg: cyc(4) };
}

export const categories: Record<string, () => Generator<Recipe>> = { hashes, kdfs, aead, keys };
export function* allRecipes(): Generator<Recipe> {
  for (const g of Object.values(categories)) yield* g();
}
/** The hand-pinned golden subset: everything except a stride over the hash grid. */
export function* goldenRecipes(): Generator<Recipe> {
  let i = 0;
  for (const r of hashes()) if (i++ % 3 === 0) yield r;
  yield* kdfs();
  i = 0;
  for (const r of aead()) if (i++ % 2 === 0) yield r;
  yield* keys();
}
