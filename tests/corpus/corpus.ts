import { ED25519_STRICT_FIXTURES } from "./ed25519-strict-fixtures";
/**
 * Deterministic differential corpus: input lengths at block boundaries,
 * key/nonce/salt boundaries, AAD present/absent, every exposed KDF
 * parameter, and seeded key generation. Pure and deterministic.
 */
import type { Recipe, Bytes } from "../vectors/recipes";
import { SIGNED } from "./verify-fixtures";

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

// ---------------------------------------------------------------------------
// Signature verification and argument-domain faults. Every input is a literal.
// ---------------------------------------------------------------------------
const hx = (hex: string): Bytes => ({ hex });
/** Flip the low bit of the first byte. */
const flip = (hex: string): string =>
  (parseInt(hex.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0") + hex.slice(2);
const SECP_N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
/** The same ECDSA signature with s replaced by n - s (high-S). */
const highS = (sig: string): string =>
  sig.slice(0, 64) + (SECP_N - BigInt("0x" + sig.slice(64))).toString(16).padStart(64, "0");
const verifyOf = (
  scheme: "ecdsa" | "schnorr" | "ed25519",
  pub: string,
  sig: string,
  msg: string,
): Recipe => ({
  k: scheme === "ecdsa" ? "ecdsaVerify" : scheme === "schnorr" ? "schnorrVerify" : "ed25519Verify",
  pub: hx(pub),
  sig: hx(sig),
  msg: hx(msg),
});
/** BIP-340 vectors 0–4 (valid) and 5–14 (invalid), as in the reference's own tests. */
const BIP340_MSG = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89";
const BIP340_PUB = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
const BIP340: [string, string, string][] = [
  [
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
    "0000000000000000000000000000000000000000000000000000000000000000",
  ],
  [
    BIP340_PUB,
    "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
    BIP340_MSG,
  ],
  [
    "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
    "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7",
    "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
  ],
  [
    "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
    "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  ],
  [
    "d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9",
    "00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4",
    "4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703",
  ],
  // 5: public key not on the curve
  [
    "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
    "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
    BIP340_MSG,
  ],
  // 6: has_even_y(R) is false
  [
    BIP340_PUB,
    "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2",
    BIP340_MSG,
  ],
  // 7: negated message
  [
    BIP340_PUB,
    "1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd",
    BIP340_MSG,
  ],
  // 8: negated s
  [
    BIP340_PUB,
    "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6",
    BIP340_MSG,
  ],
  // 9, 10: sG - eP is infinite
  [
    BIP340_PUB,
    "0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051",
    BIP340_MSG,
  ],
  [
    BIP340_PUB,
    "00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197",
    BIP340_MSG,
  ],
  // 11: sig[0:32] not an X coordinate
  [
    BIP340_PUB,
    "4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
    BIP340_MSG,
  ],
  // 12: sig[0:32] equals the field size
  [
    BIP340_PUB,
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
    BIP340_MSG,
  ],
  // 13: sig[32:64] equals the curve order
  [
    BIP340_PUB,
    "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    BIP340_MSG,
  ],
  // 14: public key is not a valid X coordinate
  [
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
    "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
    BIP340_MSG,
  ],
];
/** RFC 8032 §7.1 test vectors 1–3 (public key, signature, message). */
const RFC8032: [string, string, string][] = [
  [
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "",
  ],
  [
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    "72",
  ],
  [
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    "af82",
  ],
];
/** Report B1: the identity point (small order), canonical and non-canonical (y = p + 1). */
const ED_IDENTITY = "01" + "00".repeat(31);
const ED_IDENTITY_NONCANONICAL = "ee" + "ff".repeat(30) + "7f";
const ED_ZERO_S = "00".repeat(32);
/** Report B3: malformed keys and signatures of the right length. */
const FF32 = "ff".repeat(32);
const FF64 = "ff".repeat(64);
/** Report B2: low-order X25519 public keys. */
/**
 * Every encoding of a low-order point (RFC 7748 §6.1, little-endian): 0, 1,
 * the two order-8 points, p − 1, p, p + 1, and (bit 255 is masked on both
 * sides) two of them with the high bit set. The reference derives the same
 * zero-secret key for all of them; the port rejects them (D2).
 */
export const X25519_LOW_ORDER: string[] = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];
/** Ed25519's group order L, for a non-canonical `s` (`s + L`). */
const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const leHexToBigInt = (h: string): bigint =>
  BigInt("0x" + (h.match(/../g) ?? []).reverse().join(""));
const bigIntToLeHex = (v: bigint, bytes: number): string => {
  let out = "";
  for (let i = 0; i < bytes; i++)
    out += ((v >> BigInt(8 * i)) & 0xffn).toString(16).padStart(2, "0");
  return out;
};

const firstSigned = (scheme: "ecdsa" | "schnorr" | "ed25519") => {
  const t = SIGNED.find((x) => x.scheme === scheme);
  if (t === undefined) throw new Error(`no ${scheme} fixture`);
  return t;
};

function* verify(): Generator<Recipe> {
  for (const f of ED25519_STRICT_FIXTURES)
    yield verifyOf("ed25519", f.publicKey, f.signature, f.message);
  for (const t of SIGNED) {
    yield verifyOf(t.scheme, t.pub, t.sig, t.msg);
    yield verifyOf(t.scheme, t.pub, flip(t.sig), t.msg);
    yield verifyOf(t.scheme, t.pub, t.sig, flip(t.msg));
    yield verifyOf(t.scheme, flip(t.pub), t.sig, t.msg);
    if (t.scheme === "ecdsa") yield verifyOf("ecdsa", t.pub, highS(t.sig), t.msg);
  }
  for (const [pub, sig, msg] of BIP340) yield verifyOf("schnorr", pub, sig, msg);
  for (const [pub, sig, msg] of RFC8032) {
    yield verifyOf("ed25519", pub, sig, msg);
    yield verifyOf("ed25519", pub, flip(sig), msg);
  }
  const ed = firstSigned("ed25519");
  // A non-canonical s (s + L): rejected on both sides (`check_scalar` / noble's range check).
  yield verifyOf(
    "ed25519",
    ed.pub,
    ed.sig.slice(0, 64) + bigIntToLeHex(leHexToBigInt(ed.sig.slice(64)) + ED_L, 32),
    ed.msg,
  );
  // Small-order and non-canonical Ed25519 encodings.
  yield verifyOf("ed25519", ED_IDENTITY, ED_IDENTITY + ED_ZERO_S, "6869");
  yield verifyOf("ed25519", ED_IDENTITY_NONCANONICAL, ED_IDENTITY + ED_ZERO_S, "6869");
  yield verifyOf("ed25519", ED_IDENTITY, ED_IDENTITY_NONCANONICAL + ED_ZERO_S, "6869");
  // Malformed verification inputs.
  const ec = firstSigned("ecdsa");
  const sc = firstSigned("schnorr");
  yield verifyOf("ecdsa", ec.pub, FF64, ec.msg);
  yield verifyOf("ecdsa", "02" + FF32, ec.sig, ec.msg);
  yield verifyOf("schnorr", FF32, sc.sig, sc.msg);
  yield verifyOf("schnorr", sc.pub, FF64, sc.msg);
  yield verifyOf("ed25519", FF32, ed.sig, ed.msg);
  yield verifyOf("ed25519", ed.pub, FF64, ed.msg);
}
function* faults(): Generator<Recipe> {
  const zero = hx("00".repeat(32));
  const n = hx("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  const pw = txt("pw");
  const salt = cyc(16, 0x50);
  // Low-order X25519 peers.
  for (const pub of X25519_LOW_ORDER) yield { k: "x25519Shared", priv: cyc(32, 1), pub: hx(pub) };
  // Scalar, point, and KDF domain checks.
  yield { k: "ecdsaPub", priv: zero };
  yield { k: "schnorrPub", priv: zero };
  yield { k: "ecdsaPub", priv: n };
  yield { k: "ecdsaSign", priv: zero, msg: cyc(4) };
  yield { k: "ecdsaDecompress", pub: hx("02" + FF32) };
  yield { k: "ecdsaCompress", pub: hx("04" + "01".repeat(64)) };
  yield { k: "scrypt", pw, salt, len: 0 };
  yield { k: "scrypt", pw, salt, len: 32, n: 0, r: 8, p: 1 };
  yield { k: "scrypt", pw, salt, len: 32, n: 4, r: 1.5, p: 1 };
  yield { k: "argon2id", pw, salt, len: 3 };
  yield { k: "argon2id", pw, salt: cyc(4), len: 32 };
  // scrypt shape rules of `scrypt::Params::new` (RFC 7914 §2): logN < 16·r, r·p < 2^30.
  yield { k: "scrypt", pw, salt, len: 32, n: 17, r: 1, p: 1 };
  yield { k: "scrypt", pw, salt, len: 32, n: 16, r: 1, p: 1 };
  yield { k: "scrypt", pw, salt, len: 32, n: 15, r: 1, p: 1 };
  yield { k: "scrypt", pw, salt, len: 32, n: 4, r: 32768, p: 32768 };
  // The parameterised path's output-length bound (10..=64) and the default path's absence of one.
  yield { k: "scrypt", pw, salt, len: 9, n: 4, r: 8, p: 1 };
  yield { k: "scrypt", pw, salt, len: 65, n: 4, r: 8, p: 1 };
  yield { k: "scrypt", pw, salt, len: 10, n: 4, r: 8, p: 1 };
  yield { k: "scrypt", pw, salt, len: 65 };
  // Parity the corpus never pinned: an X25519 public key with bit 255 set, an empty HKDF salt.
  yield { k: "x25519Shared", priv: cyc(32, 1), pub: hx("ff".repeat(32)) };
  yield { k: "hkdfSha256", key: cyc(32, 0x10), salt: cyc(0), len: 32 };
  yield { k: "hkdfSha512", key: cyc(32, 0x10), salt: cyc(0), len: 32 };
  yield { k: "hkdfSha256", key: cyc(32, 0x10), salt, len: 8161 };
  yield { k: "hkdfSha256", key: cyc(32, 0x10), salt, len: 1.5 };
  for (const k of ["pbkdf2Sha256", "pbkdf2Sha512"] as const) {
    for (const len of [0, 32]) yield { k, pw, salt, iter: 0, len };
  }
  yield { k: "pbkdf2Sha256", pw, salt, iter: 1, len: 0 };
  yield { k: "chacha20", key: cyc(32, 0x10), nonce: cyc(12, 0xa0), d: cyc(8), counter: -1 };
  // The parameterised path rejects len 8 (10..=64); the default path accepts it — on both sides.
  yield { k: "scrypt", pw, salt, len: 8, n: 4, r: 8, p: 1 };
  yield { k: "scrypt", pw, salt, len: 8 };
  // A6: the JS-only keystream on an honest input (js-only in the reference harness)
  yield { k: "chacha20", key: cyc(32, 0x10), nonce: cyc(12, 0xa0), d: cyc(64) };
  yield { k: "chacha20", key: cyc(32, 0x10), nonce: cyc(12, 0xa0), d: cyc(64), counter: 1 };
}
/** Recipes the frozen baseline bundle cannot run (no `chacha20`). */
export const noBaseline = (r: Recipe): boolean => r.k === "chacha20";

export const categories: Record<string, () => Generator<Recipe>> = {
  hashes,
  kdfs,
  aead,
  keys,
  verify,
  faults,
};
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
  yield* verify();
  yield* faults();
}
