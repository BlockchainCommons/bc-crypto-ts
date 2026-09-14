/**
 * Build-agnostic recipes for the crypto vector suites.
 *
 * Every argument is named, so an API refactor changes only the adapters.
 * Byte inputs are hex or cycling-byte descriptions; the
 * seeded RNG is a four-word seed. Outcomes are hex strings, booleans as
 * "1"/"0", or `throw:<ErrorName>` (message-independent), except that an
 * `x25519Shared` `CryptoError` renders as `throw:<code>|<message>`.
 *
 * Recipe semantics are fixed: the committed vectors depend on them.
 */

export type Bytes = { hex: string } | { cycle: number; start?: number } | { text: string };

export type Recipe =
  | { k: "sha256"; d: Bytes }
  | { k: "doubleSha256"; d: Bytes }
  | { k: "sha512"; d: Bytes }
  | { k: "crc32"; d: Bytes }
  | { k: "crc32Bytes"; d: Bytes; le: boolean }
  | { k: "hmacSha256"; key: Bytes; d: Bytes }
  | { k: "hmacSha512"; key: Bytes; d: Bytes }
  | { k: "pbkdf2Sha256"; pw: Bytes; salt: Bytes; iter: number; len: number }
  | { k: "pbkdf2Sha512"; pw: Bytes; salt: Bytes; iter: number; len: number }
  | { k: "hkdfSha256"; key: Bytes; salt: Bytes; len: number }
  | { k: "hkdfSha512"; key: Bytes; salt: Bytes; len: number }
  /** `n` is log2(N), the exponent, as the underlying API takes it. */
  | { k: "scrypt"; pw: Bytes; salt: Bytes; len: number; n?: number; r?: number; p?: number }
  | { k: "argon2id"; pw: Bytes; salt: Bytes; len: number }
  /** Raw ChaCha20 keystream — no `bc-crypto` function (js-only J1); `counter` is the initial block counter. */
  | { k: "chacha20"; key: Bytes; nonce: Bytes; d: Bytes; counter?: number }
  | { k: "aeadEncrypt"; pt: Bytes; key: Bytes; nonce: Bytes; aad?: Bytes }
  | { k: "aeadDecrypt"; ct: Bytes; key: Bytes; nonce: Bytes; aad?: Bytes }
  | { k: "x25519Pub"; priv: Bytes }
  | { k: "x25519Shared"; priv: Bytes; pub: Bytes }
  | { k: "deriveAgreement"; km: Bytes }
  | { k: "deriveSigning"; km: Bytes }
  | { k: "ecdsaDerive"; km: Bytes }
  | { k: "ecdsaPub"; priv: Bytes }
  | { k: "ecdsaDecompress"; pub: Bytes }
  | { k: "ecdsaCompress"; pub: Bytes }
  | { k: "ecdsaSign"; priv: Bytes; msg: Bytes }
  | { k: "ecdsaVerify"; pub: Bytes; sig: Bytes; msg: Bytes }
  | { k: "schnorrPub"; priv: Bytes }
  | { k: "schnorrSignAux"; priv: Bytes; msg: Bytes; aux: Bytes }
  | { k: "schnorrSignRng"; priv: Bytes; msg: Bytes; seed: string[] }
  | { k: "schnorrVerify"; pub: Bytes; sig: Bytes; msg: Bytes }
  | { k: "ed25519Pub"; priv: Bytes }
  | { k: "ed25519Sign"; priv: Bytes; msg: Bytes }
  | { k: "ed25519Verify"; pub: Bytes; sig: Bytes; msg: Bytes }
  | { k: "newPriv"; alg: "ecdsa" | "ed25519" | "x25519"; seed: string[] };

export interface Rng {
  nextU32(): number;
  nextU64(): bigint;
  fillBytes(dest: Uint8Array): void;
}

/** What a build must provide; names are the adapter's business. */
export interface VectorApi {
  sha256(d: Uint8Array): Uint8Array;
  doubleSha256(d: Uint8Array): Uint8Array;
  sha512(d: Uint8Array): Uint8Array;
  crc32(d: Uint8Array): number;
  crc32Bytes(d: Uint8Array, le: boolean): Uint8Array;
  hmacSha256(k: Uint8Array, d: Uint8Array): Uint8Array;
  hmacSha512(k: Uint8Array, d: Uint8Array): Uint8Array;
  pbkdf2Sha256(pw: Uint8Array, salt: Uint8Array, iter: number, len: number): Uint8Array;
  pbkdf2Sha512(pw: Uint8Array, salt: Uint8Array, iter: number, len: number): Uint8Array;
  hkdfSha256(k: Uint8Array, salt: Uint8Array, len: number): Uint8Array;
  hkdfSha512(k: Uint8Array, salt: Uint8Array, len: number): Uint8Array;
  scrypt(
    pw: Uint8Array,
    salt: Uint8Array,
    len: number,
    n?: number,
    r?: number,
    p?: number,
  ): Uint8Array;
  argon2id(pw: Uint8Array, salt: Uint8Array, len: number): Uint8Array;
  chacha20(key: Uint8Array, nonce: Uint8Array, d: Uint8Array, counter?: number): Uint8Array;
  aeadEncrypt(pt: Uint8Array, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Uint8Array;
  aeadDecrypt(ct: Uint8Array, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Uint8Array;
  x25519Pub(priv: Uint8Array): Uint8Array;
  x25519Shared(priv: Uint8Array, pub: Uint8Array): Uint8Array;
  deriveAgreement(km: Uint8Array): Uint8Array;
  deriveSigning(km: Uint8Array): Uint8Array;
  ecdsaDerive(km: Uint8Array): Uint8Array;
  ecdsaPub(priv: Uint8Array): Uint8Array;
  ecdsaDecompress(pub: Uint8Array): Uint8Array;
  ecdsaCompress(pub: Uint8Array): Uint8Array;
  ecdsaSign(priv: Uint8Array, msg: Uint8Array): Uint8Array;
  ecdsaVerify(pub: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean;
  schnorrPub(priv: Uint8Array): Uint8Array;
  schnorrSignAux(priv: Uint8Array, msg: Uint8Array, aux: Uint8Array): Uint8Array;
  schnorrSignRng(priv: Uint8Array, msg: Uint8Array, rng: Rng): Uint8Array;
  schnorrVerify(pub: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean;
  ed25519Pub(priv: Uint8Array): Uint8Array;
  ed25519Sign(priv: Uint8Array, msg: Uint8Array): Uint8Array;
  ed25519Verify(pub: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean;
  newPriv(alg: "ecdsa" | "ed25519" | "x25519", rng: Rng): Uint8Array;
  makeRng(seed: [bigint, bigint, bigint, bigint]): Rng;
}

export const bytesToHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const hexToBytes = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
export const materializeBytes = (b: Bytes): Uint8Array =>
  "hex" in b
    ? hexToBytes(b.hex)
    : "text" in b
      ? new TextEncoder().encode(b.text)
      : Uint8Array.from({ length: b.cycle }, (_, i) => ((b.start ?? 0) + i) & 0xff);

const seedOf = (s: string[]): [bigint, bigint, bigint, bigint] =>
  s.map(BigInt) as [bigint, bigint, bigint, bigint];

export function materialize(api: VectorApi, r: Recipe): string {
  const B = materializeBytes;
  try {
    switch (r.k) {
      case "sha256":
        return bytesToHex(api.sha256(B(r.d)));
      case "doubleSha256":
        return bytesToHex(api.doubleSha256(B(r.d)));
      case "sha512":
        return bytesToHex(api.sha512(B(r.d)));
      case "crc32":
        return String(api.crc32(B(r.d)));
      case "crc32Bytes":
        return bytesToHex(api.crc32Bytes(B(r.d), r.le));
      case "hmacSha256":
        return bytesToHex(api.hmacSha256(B(r.key), B(r.d)));
      case "hmacSha512":
        return bytesToHex(api.hmacSha512(B(r.key), B(r.d)));
      case "pbkdf2Sha256":
        return bytesToHex(api.pbkdf2Sha256(B(r.pw), B(r.salt), r.iter, r.len));
      case "pbkdf2Sha512":
        return bytesToHex(api.pbkdf2Sha512(B(r.pw), B(r.salt), r.iter, r.len));
      case "hkdfSha256":
        return bytesToHex(api.hkdfSha256(B(r.key), B(r.salt), r.len));
      case "hkdfSha512":
        return bytesToHex(api.hkdfSha512(B(r.key), B(r.salt), r.len));
      case "scrypt":
        return bytesToHex(api.scrypt(B(r.pw), B(r.salt), r.len, r.n, r.r, r.p));
      case "argon2id":
        return bytesToHex(api.argon2id(B(r.pw), B(r.salt), r.len));
      case "chacha20":
        return bytesToHex(api.chacha20(B(r.key), B(r.nonce), B(r.d), r.counter));
      case "aeadEncrypt":
        return bytesToHex(
          api.aeadEncrypt(
            B(r.pt),
            B(r.key),
            B(r.nonce),
            r.aad === undefined ? undefined : B(r.aad),
          ),
        );
      case "aeadDecrypt":
        return bytesToHex(
          api.aeadDecrypt(
            B(r.ct),
            B(r.key),
            B(r.nonce),
            r.aad === undefined ? undefined : B(r.aad),
          ),
        );
      case "x25519Pub":
        return bytesToHex(api.x25519Pub(B(r.priv)));
      case "x25519Shared":
        return bytesToHex(api.x25519Shared(B(r.priv), B(r.pub)));
      case "deriveAgreement":
        return bytesToHex(api.deriveAgreement(B(r.km)));
      case "deriveSigning":
        return bytesToHex(api.deriveSigning(B(r.km)));
      case "ecdsaDerive":
        return bytesToHex(api.ecdsaDerive(B(r.km)));
      case "ecdsaPub":
        return bytesToHex(api.ecdsaPub(B(r.priv)));
      case "ecdsaDecompress":
        return bytesToHex(api.ecdsaDecompress(B(r.pub)));
      case "ecdsaCompress":
        return bytesToHex(api.ecdsaCompress(B(r.pub)));
      case "ecdsaSign":
        return bytesToHex(api.ecdsaSign(B(r.priv), B(r.msg)));
      case "ecdsaVerify":
        return api.ecdsaVerify(B(r.pub), B(r.sig), B(r.msg)) ? "1" : "0";
      case "schnorrPub":
        return bytesToHex(api.schnorrPub(B(r.priv)));
      case "schnorrSignAux":
        return bytesToHex(api.schnorrSignAux(B(r.priv), B(r.msg), B(r.aux)));
      case "schnorrSignRng":
        return bytesToHex(api.schnorrSignRng(B(r.priv), B(r.msg), api.makeRng(seedOf(r.seed))));
      case "schnorrVerify":
        return api.schnorrVerify(B(r.pub), B(r.sig), B(r.msg)) ? "1" : "0";
      case "ed25519Pub":
        return bytesToHex(api.ed25519Pub(B(r.priv)));
      case "ed25519Sign":
        return bytesToHex(api.ed25519Sign(B(r.priv), B(r.msg)));
      case "ed25519Verify":
        return api.ed25519Verify(B(r.pub), B(r.sig), B(r.msg)) ? "1" : "0";
      case "newPriv":
        return bytesToHex(api.newPriv(r.alg, api.makeRng(seedOf(r.seed))));
    }
  } catch (e) {
    // `x25519Shared` failures carry the error value: the reference's
    // `try_x25519_shared_key` returns `Err(NonContributoryKey)` with a Display
    // text, and the harness compares code and message for this kind.
    if (r.k === "x25519Shared" && e instanceof Error && e.name === "CryptoError" && "code" in e) {
      return `throw:${String(e.code)}|${e.message}`;
    }
    return `throw:${e instanceof Error ? e.name : "Error"}`;
  }
}

/* eslint-disable @typescript-eslint/no-explicit-any */

/** The `@bcts/crypto` surface of the frozen baseline bundle (with its own inlined rand). */
export function baselineAdapterFor(m: any, randBaseline: any): VectorApi {
  return {
    sha256: m.sha256,
    doubleSha256: m.doubleSha256,
    sha512: m.sha512,
    crc32: m.hash.crc32,
    crc32Bytes: (d, le) => m.hash.crc32DataOpt(d, le),
    hmacSha256: m.hmacSha256,
    hmacSha512: m.hmacSha512,
    pbkdf2Sha256: m.pbkdf2HmacSha256,
    pbkdf2Sha512: m.hash.pbkdf2HmacSha512,
    hkdfSha256: m.hkdfHmacSha256,
    hkdfSha512: m.hash.hkdfHmacSha512,
    scrypt: (pw, salt, len, n, r, p) =>
      n === undefined ? m.scrypt(pw, salt, len) : m.scryptOpt(pw, salt, len, n, r, p),
    // The baseline has no raw ChaCha20; those recipes are excluded from the
    // differential (`noBaseline` in the corpus).
    argon2id: (pw, salt, len) => m.argon2id(pw, salt, len),
    chacha20: () => {
      throw new Error("no baseline analog");
    },
    // The baseline AEAD returns [ciphertext, tag] and decrypt takes the tag
    // last; the vector representation is the concatenation ciphertext || tag.
    aeadEncrypt: (pt, k, n, aad) => {
      const [ct, tag] =
        aad === undefined
          ? m.aeadChaCha20Poly1305Encrypt(pt, k, n)
          : m.aeadChaCha20Poly1305EncryptWithAad(pt, k, n, aad);
      return new Uint8Array([...ct, ...tag]);
    },
    aeadDecrypt: (all, k, n, aad) => {
      const ct = all.subarray(0, all.length - 16),
        tag = all.subarray(all.length - 16);
      return aad === undefined
        ? m.aeadChaCha20Poly1305Decrypt(ct, k, n, tag)
        : m.aeadChaCha20Poly1305DecryptWithAad(ct, k, n, aad, tag);
    },
    x25519Pub: m.x25519PublicKeyFromPrivateKey,
    x25519Shared: m.x25519SharedKey,
    deriveAgreement: m.deriveAgreementPrivateKey,
    deriveSigning: m.deriveSigningPrivateKey,
    ecdsaDerive: m.ecdsaDerivePrivateKey,
    ecdsaPub: m.ecdsaPublicKeyFromPrivateKey,
    ecdsaDecompress: m.ecdsaDecompressPublicKey,
    ecdsaCompress: m.ecdsaCompressPublicKey,
    ecdsaSign: m.ecdsaSign,
    ecdsaVerify: m.ecdsaVerify,
    schnorrPub: m.schnorrPublicKeyFromPrivateKey,
    schnorrSignAux: m.schnorrSignWithAuxRand,
    schnorrSignRng: (priv, msg, rng) => m.schnorrSignUsing(priv, msg, rng),
    schnorrVerify: m.schnorrVerify,
    ed25519Pub: m.ed25519PublicKeyFromPrivateKey,
    ed25519Sign: m.ed25519Sign,
    // The baseline's ed25519Verify takes (pub, msg, sig), unlike ecdsa/schnorr (pub, sig, msg).
    ed25519Verify: (pub, sig, msg) => m.ed25519Verify(pub, msg, sig),
    newPriv: (alg, rng) =>
      ({
        ecdsa: m.ecdsaNewPrivateKeyUsing,
        ed25519: m.ed25519NewPrivateKeyUsing,
        x25519: m.x25519NewPrivateKeyUsing,
      })[alg](rng),
    // The baseline's `*Using(rng)` call rng.randomData(n), which the baseline rand provides.
    makeRng: (seed) => new randBaseline.SeededRandomNumberGenerator(seed),
  };
}

/** This package's surface (the working tree or its build). */
export function currentAdapterFor(m: any, rand: any): VectorApi {
  return {
    sha256: m.sha256,
    doubleSha256: m.doubleSha256,
    sha512: m.sha512,
    crc32: m.crc32,
    crc32Bytes: (d, le) => m.crc32Bytes(d, { littleEndian: le }),
    hmacSha256: m.hmacSha256,
    hmacSha512: m.hmacSha512,
    pbkdf2Sha256: (pw, salt, iter, len) =>
      m.pbkdf2Sha256(pw, salt, { iterations: iter, dkLen: len }),
    pbkdf2Sha512: (pw, salt, iter, len) =>
      m.pbkdf2Sha512(pw, salt, { iterations: iter, dkLen: len }),
    hkdfSha256: (k, salt, len) => m.hkdfSha256(k, salt, { dkLen: len }),
    hkdfSha512: (k, salt, len) => m.hkdfSha512(k, salt, { dkLen: len }),
    scrypt: (pw, salt, len, n, r, p) => m.scrypt(pw, salt, { dkLen: len, logN: n, r, p }),
    argon2id: (pw, salt, len) => m.argon2id(pw, salt, { dkLen: len }),
    chacha20: (key, nonce, d, counter) => m.chacha20(key, nonce, d, { counter }),
    aeadEncrypt: (pt, k, n, aad) => m.chacha20Poly1305.encrypt(k, n, pt, { aad }),
    aeadDecrypt: (ct, k, n, aad) => m.chacha20Poly1305.decrypt(k, n, ct, { aad }),
    x25519Pub: m.x25519.publicKey,
    x25519Shared: m.x25519.sharedKey,
    deriveAgreement: m.deriveAgreementPrivateKey,
    deriveSigning: m.deriveSigningPrivateKey,
    // The reference's `ecdsa_derive_private_key` ≡ `derive_signing_private_key`; the port keeps one.
    ecdsaDerive: m.deriveSigningPrivateKey,
    ecdsaPub: m.ecdsa.publicKey,
    ecdsaDecompress: m.ecdsa.decompressPublicKey,
    ecdsaCompress: m.ecdsa.compressPublicKey,
    ecdsaSign: m.ecdsa.sign,
    ecdsaVerify: m.ecdsa.verify,
    schnorrPub: m.schnorr.publicKey,
    schnorrSignAux: (priv, msg, aux) => m.schnorr.sign(priv, msg, { auxRand: aux }),
    schnorrSignRng: (priv, msg, rng) => m.schnorr.sign(priv, msg, { rng }),
    schnorrVerify: m.schnorr.verify,
    ed25519Pub: m.ed25519.publicKey,
    ed25519Sign: m.ed25519.sign,
    ed25519Verify: m.ed25519.verify,
    newPriv: (alg, rng) => m[alg].generatePrivateKey({ rng }),
    makeRng: (seed) => new rand.SeededRng(seed),
  };
}
