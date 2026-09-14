import { ED25519_STRICT_FIXTURES } from "./corpus/ed25519-strict-fixtures";
/**
 * Differential test: every corpus recipe through the frozen baseline bundle
 * (the `@bcts/crypto` surface this package replaces, with its own inlined
 * rand) and through the working tree. Outcomes must be identical except for
 * the allowed differences below. Only "throws" versus a value is compared,
 * not error classes or messages.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as baselineMod from "./baseline/crypto-baseline.mjs";
import * as randBaseline from "./baseline/rand-baseline.mjs";
import * as src from "../src";
import * as rand from "@blockchaincommons/rand";
import { materialize, baselineAdapterFor, currentAdapterFor, type Recipe } from "./vectors/recipes";
import { categories, noBaseline } from "./corpus/corpus";

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE_SHA256 = "d3a5a82546fd0424232ba32ea1c1bd485e08f35f3f241edc90c8476fb1559655";

/**
 * Where the tree deliberately differs from the baseline. Within a category, an
 * entry that matches any recipe must see at least one of them differ, so a
 * stale entry fails the test.
 */
const ALLOWED_DIFFERENCES: { id: string; matches: (r: Recipe) => boolean }[] = [
  {
    // The uncofactored equation (`verify_strict`): torsion fixtures the
    // baseline's cofactored check accepted are rejected.
    id: "uncofactored-ed25519",
    matches: (r) =>
      r.k === "ed25519Verify" &&
      "hex" in r.sig &&
      ED25519_STRICT_FIXTURES.some((f) => !f.valid && "hex" in r.sig && f.signature === r.sig.hex),
  },
  {
    // Strict Ed25519 verification (`verify_strict`): the baseline accepted
    // small-order and non-canonical encodings, the tree rejects them. The
    // reference's decoder reduces a non-canonical y where the tree decodes
    // canonically; the outcome is the same `false`, because an undecodable
    // key is `false` on both sides and a decodable non-canonical key is
    // small-order or would need a discrete logarithm to verify.
    id: "strict-ed25519-encodings",
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
    id: "packed-ed25519-keygen",
    matches: (r) => r.k === "newPriv" && r.alg === "ed25519",
  },
  {
    // scrypt's parameterised path mirrors `scrypt::Params::new`: output length
    // in 10..=64, logN < 16·r, r·p < 2^30. The baseline computed these; the
    // reference panics; the tree throws.
    id: "scrypt-params-new",
    matches: (r) =>
      r.k === "scrypt" &&
      r.n !== undefined &&
      (r.len < 10 || r.len > 64 || r.n >= 16 * (r.r ?? 8) || (r.r ?? 8) * (r.p ?? 1) >= 2 ** 30),
  },
  {
    // PBKDF2 with dkLen 0 is an empty key on the tree (as the reference returns);
    // the baseline threw.
    id: "pbkdf2-empty-output",
    matches: (r) =>
      (r.k === "pbkdf2Sha256" || r.k === "pbkdf2Sha512") && r.len === 0 && r.iter >= 1,
  },
  {
    // Hybrid `06`/`07` uncompressed keys compress on the tree, as libsecp256k1
    // parses them for the reference; the baseline (noble) rejected every
    // prefix but `04`.
    id: "hybrid-uncompressed-keys",
    matches: (r) =>
      r.k === "ecdsaCompress" &&
      "hex" in r.pub &&
      (r.pub.hex.startsWith("06") || r.pub.hex.startsWith("07")),
  },
  {
    // scrypt has no default memory ceiling on the tree (the reference has
    // none); the baseline kept noble's default of 128·8·(2^20 + 2) bytes.
    id: "scrypt-no-memory-ceiling",
    matches: (r) =>
      r.k === "scrypt" &&
      r.n !== undefined &&
      128 * (r.r ?? 8) * (2 ** r.n + (r.p ?? 1) + 1) > 128 * 8 * (2 ** 20 + 2),
  },
];

const baseline = baselineAdapterFor(baselineMod, randBaseline);
const current = currentAdapterFor(src, rand);
// The two surfaces throw different error classes; only throw versus value is compared.
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
      const differing = new Map<string, number>();
      const matched = new Map<string, number>();
      for (const recipe of gen()) {
        if (noBaseline(recipe)) continue;
        n++;
        const a = norm(materialize(baseline, recipe));
        const b = norm(materialize(current, recipe));
        const equal = a === b;
        const allowed = ALLOWED_DIFFERENCES.find((d) => d.matches(recipe));
        if (allowed !== undefined) {
          matched.set(allowed.id, (matched.get(allowed.id) ?? 0) + 1);
          if (!equal) differing.set(allowed.id, (differing.get(allowed.id) ?? 0) + 1);
        } else if (!equal) {
          diffs.push(`${JSON.stringify(recipe)}: ${a} !== ${b}`);
        }
      }
      expect(n).toBeGreaterThan(0);
      expect(diffs).toEqual([]);
      for (const [id, count] of matched)
        if (count > 0) expect(differing.get(id) ?? 0, id).toBeGreaterThan(0);
    });
  }
});
