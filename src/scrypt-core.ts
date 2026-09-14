/**
 * RFC 7914 scrypt over paged working memory.
 *
 * noble keeps `V` (128·r·N bytes) and `B` (128·r·p bytes) each in one typed
 * array, and JavaScriptCore (Bun, Safari) holds at most 2^32 bytes in one,
 * so parameter sets the reference derives with (for example logN 22, r 9,
 * 4.8 GiB) cannot run there. This core keeps both in pages of whole
 * 128·r-byte blocks, each page at most `pageBytes` (2^30 by default), and
 * {@link scrypt} dispatches to it only when a working buffer would exceed
 * 2^31 bytes; everything smaller goes to noble, which is faster. The bytes
 * are identical to noble's and to the reference's (`scrypt` 0.11.0).
 *
 * @module scrypt-core
 * @internal
 */
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { rotl, swap32IfBE } from "@noble/hashes/utils.js";

/** Parameters for {@link scryptCore}; already validated by the caller. */
export interface ScryptCoreParams {
  /** CPU/memory cost, a power of two in [1, 2^32] (N = 1: one block of `V`, mixed once). */
  readonly N: number;
  /** Block size factor ≥ 1. */
  readonly r: number;
  /** Parallelism ≥ 1. */
  readonly p: number;
  /** Output length ≥ 1. */
  readonly dkLen: number;
  /** Largest page in bytes; a page always holds at least one 128·r-byte block. Tests use tiny pages. */
  readonly pageBytes?: number | undefined;
}

const DEFAULT_PAGE_BYTES = 2 ** 30;

/** `units` blocks of `unitWords` 32-bit words, in pages of whole blocks. */
class PagedBlocks {
  readonly pages: Uint32Array[] = [];
  readonly unitsPerPage: number;
  constructor(
    units: number,
    readonly unitWords: number,
    pageBytes: number,
  ) {
    this.unitsPerPage = Math.max(1, Math.floor(pageBytes / (unitWords * 4)));
    for (let done = 0; done < units; done += this.unitsPerPage) {
      const n = Math.min(this.unitsPerPage, units - done);
      this.pages.push(new Uint32Array(n * unitWords));
    }
  }
  /** The page holding block `i` and the block's word offset in it. */
  page(i: number): Uint32Array {
    return this.pages[Math.floor(i / this.unitsPerPage)];
  }
  offset(i: number): number {
    return (i % this.unitsPerPage) * this.unitWords;
  }
  /** The bytes of every page, in page order. */
  bytes(): Uint8Array[] {
    return this.pages.map((page) => new Uint8Array(page.buffer, page.byteOffset, page.byteLength));
  }
}

/** `out[oi..oi+16] = Salsa20/8(a[ai..ai+16] xor b[bi..bi+16])` (RFC 7914 §3). */
function salsa20_8Xor(
  out: Uint32Array,
  oi: number,
  a: Uint32Array,
  ai: number,
  b: Uint32Array,
  bi: number,
): void {
  const i0 = a[ai] ^ b[bi],
    i1 = a[ai + 1] ^ b[bi + 1],
    i2 = a[ai + 2] ^ b[bi + 2],
    i3 = a[ai + 3] ^ b[bi + 3],
    i4 = a[ai + 4] ^ b[bi + 4],
    i5 = a[ai + 5] ^ b[bi + 5],
    i6 = a[ai + 6] ^ b[bi + 6],
    i7 = a[ai + 7] ^ b[bi + 7],
    i8 = a[ai + 8] ^ b[bi + 8],
    i9 = a[ai + 9] ^ b[bi + 9],
    i10 = a[ai + 10] ^ b[bi + 10],
    i11 = a[ai + 11] ^ b[bi + 11],
    i12 = a[ai + 12] ^ b[bi + 12],
    i13 = a[ai + 13] ^ b[bi + 13],
    i14 = a[ai + 14] ^ b[bi + 14],
    i15 = a[ai + 15] ^ b[bi + 15];
  let x0 = i0,
    x1 = i1,
    x2 = i2,
    x3 = i3,
    x4 = i4,
    x5 = i5,
    x6 = i6,
    x7 = i7,
    x8 = i8,
    x9 = i9,
    x10 = i10,
    x11 = i11,
    x12 = i12,
    x13 = i13,
    x14 = i14,
    x15 = i15;
  // Eight rounds: four double-rounds of column then row quarter-rounds.
  for (let round = 0; round < 8; round += 2) {
    x4 ^= rotl((x0 + x12) | 0, 7);
    x8 ^= rotl((x4 + x0) | 0, 9);
    x12 ^= rotl((x8 + x4) | 0, 13);
    x0 ^= rotl((x12 + x8) | 0, 18);
    x9 ^= rotl((x5 + x1) | 0, 7);
    x13 ^= rotl((x9 + x5) | 0, 9);
    x1 ^= rotl((x13 + x9) | 0, 13);
    x5 ^= rotl((x1 + x13) | 0, 18);
    x14 ^= rotl((x10 + x6) | 0, 7);
    x2 ^= rotl((x14 + x10) | 0, 9);
    x6 ^= rotl((x2 + x14) | 0, 13);
    x10 ^= rotl((x6 + x2) | 0, 18);
    x3 ^= rotl((x15 + x11) | 0, 7);
    x7 ^= rotl((x3 + x15) | 0, 9);
    x11 ^= rotl((x7 + x3) | 0, 13);
    x15 ^= rotl((x11 + x7) | 0, 18);
    x1 ^= rotl((x0 + x3) | 0, 7);
    x2 ^= rotl((x1 + x0) | 0, 9);
    x3 ^= rotl((x2 + x1) | 0, 13);
    x0 ^= rotl((x3 + x2) | 0, 18);
    x6 ^= rotl((x5 + x4) | 0, 7);
    x7 ^= rotl((x6 + x5) | 0, 9);
    x4 ^= rotl((x7 + x6) | 0, 13);
    x5 ^= rotl((x4 + x7) | 0, 18);
    x11 ^= rotl((x10 + x9) | 0, 7);
    x8 ^= rotl((x11 + x10) | 0, 9);
    x9 ^= rotl((x8 + x11) | 0, 13);
    x10 ^= rotl((x9 + x8) | 0, 18);
    x12 ^= rotl((x15 + x14) | 0, 7);
    x13 ^= rotl((x12 + x15) | 0, 9);
    x14 ^= rotl((x13 + x12) | 0, 13);
    x15 ^= rotl((x14 + x13) | 0, 18);
  }
  out[oi] = (i0 + x0) | 0;
  out[oi + 1] = (i1 + x1) | 0;
  out[oi + 2] = (i2 + x2) | 0;
  out[oi + 3] = (i3 + x3) | 0;
  out[oi + 4] = (i4 + x4) | 0;
  out[oi + 5] = (i5 + x5) | 0;
  out[oi + 6] = (i6 + x6) | 0;
  out[oi + 7] = (i7 + x7) | 0;
  out[oi + 8] = (i8 + x8) | 0;
  out[oi + 9] = (i9 + x9) | 0;
  out[oi + 10] = (i10 + x10) | 0;
  out[oi + 11] = (i11 + x11) | 0;
  out[oi + 12] = (i12 + x12) | 0;
  out[oi + 13] = (i13 + x13) | 0;
  out[oi + 14] = (i14 + x14) | 0;
  out[oi + 15] = (i15 + x15) | 0;
}

/**
 * `out[oi..] = BlockMix(input[ii..])` over `2r` 64-byte sub-blocks (RFC 7914
 * §4): `X = B[2r−1]; for i: X = Salsa(X xor B[i]); Y[i] = X`, with the even
 * `Y` first and the odd `Y` after them. `out` may not overlap `input`.
 */
function blockMix(input: Uint32Array, ii: number, out: Uint32Array, oi: number, r: number): void {
  let even = oi;
  let odd = oi + 16 * r;
  // The running X starts as the last sub-block; the first odd slot holds it
  // until that slot is written (its consumer runs first).
  const last = ii + (2 * r - 1) * 16;
  for (let t = 0; t < 16; t++) out[odd + t] = input[last + t];
  let prev = odd;
  for (let i = 0; i < r; i++) {
    salsa20_8Xor(out, even, out, prev, input, ii + 32 * i); // Y[2i]
    salsa20_8Xor(out, odd, out, even, input, ii + 32 * i + 16); // Y[2i+1]
    prev = odd;
    even += 16;
    odd += 16;
  }
}

/** One big-endian 32-bit block index, as PBKDF2's `INT(i)`. */
function int32be(i: number): Uint8Array {
  return Uint8Array.from([(i >>> 24) & 0xff, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff]);
}

/**
 * The scrypt KDF of RFC 7914 with `V` and `B` in pages. `password` and
 * `salt` are used as given; the caller validates the parameters.
 */
export function scryptCore(
  password: Uint8Array,
  salt: Uint8Array,
  { N, r, p, dkLen, pageBytes = DEFAULT_PAGE_BYTES }: ScryptCoreParams,
): Uint8Array<ArrayBuffer> {
  const unitWords = 32 * r; // 128·r bytes
  const B = new PagedBlocks(p, unitWords, pageBytes);
  const V = new PagedBlocks(N, unitWords, pageBytes);

  // B = PBKDF2-HMAC-SHA-256(P, S, 1, 128·r·p), block by block into the pages:
  // T_i = HMAC(P, S ‖ INT(i)). A page holds whole 128·r-byte blocks, so a
  // 32-byte T_i never straddles two pages.
  const prf = hmac.create(sha256, password);
  let block = 1;
  for (const bytes of B.bytes()) {
    for (let off = 0; off < bytes.length; off += 32, block++) {
      bytes.set(prf.clone().update(salt).update(int32be(block)).digest(), off);
    }
  }
  for (const page of B.pages) swap32IfBE(page);

  const X = new Uint32Array(unitWords);
  const T = new Uint32Array(unitWords);
  for (let unit = 0; unit < p; unit++) {
    const bPage = B.page(unit);
    const bOff = B.offset(unit);
    // V[0] = B_unit; V[j] = BlockMix(V[j−1]); X = BlockMix(V[N−1]).
    V.page(0).set(bPage.subarray(bOff, bOff + unitWords), V.offset(0));
    for (let j = 1; j < N; j++) {
      blockMix(V.page(j - 1), V.offset(j - 1), V.page(j), V.offset(j), r);
    }
    blockMix(V.page(N - 1), V.offset(N - 1), X, 0, r);
    // X = BlockMix(X xor V[Integerify(X) mod N]), N times. Integerify reads
    // the first word of the last sub-block; N is a power of two ≤ 2^32.
    for (let j = 0; j < N; j++) {
      const k = (X[unitWords - 16] & (N - 1)) >>> 0;
      const kPage = V.page(k);
      const kOff = V.offset(k);
      for (let t = 0; t < unitWords; t++) T[t] = X[t] ^ kPage[kOff + t];
      blockMix(T, 0, X, 0, r);
    }
    bPage.set(X, bOff);
  }
  for (const page of B.pages) swap32IfBE(page);

  // DK = PBKDF2-HMAC-SHA-256(P, B, 1, dkLen): one HMAC state absorbs the
  // whole of B once; each output block clones it and appends INT(i).
  const base = hmac.create(sha256, password);
  for (const bytes of B.bytes()) base.update(bytes);
  const out = new Uint8Array(dkLen);
  for (let i = 1, off = 0; off < dkLen; i++, off += 32) {
    const t = base.clone().update(int32be(i)).digest();
    out.set(t.subarray(0, Math.min(32, dkLen - off)), off);
  }
  for (const page of V.pages) page.fill(0);
  for (const page of B.pages) page.fill(0);
  X.fill(0);
  T.fill(0);
  return out;
}
