/**
 * Baseline vs working tree micro-benchmarks (Phase 2.3).
 *
 *   bun run build && bun bench/benchmark.mjs
 */
import * as baseline from "../tests/baseline/crypto-baseline.mjs";
import * as current from "../dist/index.mjs";

const bytes = (n, start = 0) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
const MIB = bytes(1 << 20, 3);
const KEY = bytes(32, 0x10);
const NONCE = bytes(12, 0xa0);
const PRIV = bytes(32, 1);
const MSG = bytes(100, 7);

function time(fn, iters = 5) {
  fn(); // warm
  let best = Infinity;
  for (let i = 0; i < iters; i++) {
    const t0 = performance.now();
    fn();
    best = Math.min(best, performance.now() - t0);
  }
  return best;
}

// Each case is [old-API thunk, new-API thunk]; the pair must do identical work.
const cases = {
  "chacha20poly1305 encrypt 1 MiB": [
    () => baseline.aeadChaCha20Poly1305Encrypt(MIB, KEY, NONCE),
    () => current.chacha20Poly1305.encrypt(KEY, NONCE, MIB),
  ],
  "hkdfSha256 ×10k": [
    () => { for (let i = 0; i < 1e4; i++) baseline.hkdfHmacSha256(KEY, NONCE, 32); },
    () => { for (let i = 0; i < 1e4; i++) current.hkdfSha256(KEY, NONCE, 32); },
  ],
  "derivePrivateKey ×10k": [
    () => { for (let i = 0; i < 1e4; i++) baseline.ecdsaDerivePrivateKey(KEY); },
    () => { for (let i = 0; i < 1e4; i++) current.ecdsa.derivePrivateKey(KEY); },
  ],
  "ecdsa sign+verify ×200": [
    () => { const pub = baseline.ecdsaPublicKeyFromPrivateKey(PRIV); for (let i = 0; i < 200; i++) baseline.ecdsaVerify(pub, baseline.ecdsaSign(PRIV, MSG), MSG); },
    () => { const pub = current.ecdsa.publicKey(PRIV); for (let i = 0; i < 200; i++) current.ecdsa.verify(pub, current.ecdsa.sign(PRIV, MSG), MSG); },
  ],
  "schnorr sign+verify ×200": [
    () => { const pub = baseline.schnorrPublicKeyFromPrivateKey(PRIV); for (let i = 0; i < 200; i++) baseline.schnorrVerify(pub, baseline.schnorrSignWithAuxRand(PRIV, MSG, KEY), MSG); },
    () => { const pub = current.schnorr.publicKey(PRIV); for (let i = 0; i < 200; i++) current.schnorr.verify(pub, current.schnorr.sign(PRIV, MSG, { auxRand: KEY }), MSG); },
  ],
  "ed25519 sign+verify ×200": [
    () => { const pub = baseline.ed25519PublicKeyFromPrivateKey(PRIV); for (let i = 0; i < 200; i++) baseline.ed25519Verify(pub, MSG, baseline.ed25519Sign(PRIV, MSG)); },
    () => { const pub = current.ed25519.publicKey(PRIV); for (let i = 0; i < 200; i++) current.ed25519.verify(pub, current.ed25519.sign(PRIV, MSG), MSG); },
  ],
  "crc32 1 MiB": [() => baseline.hash.crc32(MIB), () => current.crc32(MIB)],
};

console.log(`${"case".padEnd(32)} ${"baseline".padStart(10)} ${"current".padStart(10)} ${"speedup".padStart(8)}`);
for (const [name, [b, c]] of Object.entries(cases)) {
  const tb = time(b);
  const tc = time(c);
  console.log(`${name.padEnd(32)} ${tb.toFixed(1).padStart(8)}ms ${tc.toFixed(1).padStart(8)}ms ${(tb / tc).toFixed(2).padStart(7)}×`);
}
