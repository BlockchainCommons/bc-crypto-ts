/**
 * Differential harness: every corpus recipe through the frozen baseline
 * bundle (with its own inlined pre-redesign rand) AND the working tree;
 * outcomes must be identical except for enumerated tombstones. Error NAMES
 * are compared, not messages.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as baselineMod from "./baseline/crypto-baseline.mjs";
import * as randBaseline from "./baseline/rand-baseline.mjs";
import * as src from "../src";
import * as rand from "@blockchaincommons/rand";
import {
  materialize,
  baselineAdapterFor,
  redesignedAdapterFor,
  type Recipe,
} from "./vectors/recipes";
import { categories, noBaseline } from "./corpus/corpus";

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE_SHA256 = "d3a5a82546fd0424232ba32ea1c1bd485e08f35f3f241edc90c8476fb1559655";

/** The only allowed differences. Error classes changed from AeadError/Error to CryptoError. */
const TOMBSTONES: { id: string; landed: boolean; matches: (r: Recipe) => boolean }[] = [
  {
    // Strict Ed25519 verification (`verify_strict`): the baseline accepts
    // non-canonical/small-order encodings, the working tree rejects them.
    id: "T1",
    landed: true,
    matches: (r) =>
      r.k === "ed25519Verify" &&
      "hex" in r.pub &&
      "hex" in r.sig &&
      (r.pub.hex === "01" + "00".repeat(31) || r.pub.hex === "ee" + "ff".repeat(30) + "7f") &&
      r.sig.hex.endsWith("00".repeat(32)),
  },
  {
    // Seeded Ed25519 key generation draws the reference's packed
    // `fill_bytes` stream (`SeededRng.fillBytesPacked`); the baseline drew
    // one step per byte (`random_data`), which is not what the reference does.
    id: "T2",
    landed: true,
    matches: (r) => r.k === "newPriv" && r.alg === "ed25519",
  },
  {
    // scrypt's parameterised path mirrors `scrypt::Params::new`: output length
    // in 10..=64, logN < 16·r, r·p < 2^30. The baseline computed these; the
    // reference panics; the tree throws.
    id: "T3",
    landed: true,
    matches: (r) =>
      r.k === "scrypt" &&
      r.n !== undefined &&
      (r.len < 10 || r.len > 64 || r.n >= 16 * (r.r ?? 8) || (r.r ?? 8) * (r.p ?? 1) >= 2 ** 30),
  },
  {
    // PBKDF2 with dkLen 0 is an empty key on the tree (as the reference returns);
    // the baseline threw.
    id: "T4",
    landed: true,
    matches: (r) =>
      (r.k === "pbkdf2Sha256" || r.k === "pbkdf2Sha512") && r.len === 0 && r.iter >= 1,
  },
];

const baseline = baselineAdapterFor(baselineMod, randBaseline);
const current = redesignedAdapterFor(src, rand);
// Error class names changed (AeadError/Error -> CryptoError); compare throw-vs-value only.
const norm = (s: string): string => (s.startsWith("throw:") ? "throw" : s);

describe("differential: baseline vs working tree", () => {
  it("baseline bundle integrity", () => {
    const sha = createHash("sha256")
      .update(readFileSync(join(here, "baseline/crypto-baseline.mjs")))
      .digest("hex");
    expect(sha).toBe(BASELINE_SHA256);
  });
  for (const [name, gen] of Object.entries(categories)) {
    // scrypt/argon2id are deliberately slow; give every category room.
    it(`category ${name}`, { timeout: 300_000 }, () => {
      let n = 0;
      const diffs: string[] = [];
      const landedHits = new Map<string, number>();
      const landedMatches = new Map<string, number>();
      for (const recipe of gen()) {
        if (noBaseline(recipe)) continue;
        n++;
        const a = norm(materialize(baseline, recipe));
        const b = norm(materialize(current, recipe));
        const equal = a === b;
        const tomb = TOMBSTONES.find((t) => t.matches(recipe));
        if (tomb?.landed === true) {
          landedMatches.set(tomb.id, (landedMatches.get(tomb.id) ?? 0) + 1);
          if (!equal) landedHits.set(tomb.id, (landedHits.get(tomb.id) ?? 0) + 1);
        } else if (!equal) {
          diffs.push(`${JSON.stringify(recipe)}: ${a} !== ${b}`);
        }
      }
      expect(n).toBeGreaterThan(0);
      expect(diffs).toEqual([]);
      for (const [id, matches] of landedMatches)
        if (matches > 0) expect(landedHits.get(id) ?? 0).toBeGreaterThan(0);
    });
  }
});
