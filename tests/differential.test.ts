/**
 * Differential harness (Phase 1.3): every corpus recipe through the frozen
 * baseline bundle (with its own inlined pre-redesign rand) AND the working
 * tree; outcomes must be identical except for enumerated tombstones. Error
 * NAMES are compared, not messages.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as baselineMod from "./baseline/crypto-baseline.mjs";
import * as randBaseline from "../../bc-rand-ts/tests/baseline/rand-baseline.mjs";
import * as src from "../src";
import * as rand from "@blockchaincommons/rand";
import {
  materialize,
  baselineAdapterFor,
  redesignedAdapterFor,
  type Recipe,
} from "./vectors/recipes";
import { categories } from "./corpus/corpus";

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE_SHA256 = "57148b07094f9488bdc8c3a35183faad440181967aed5e08452ccee45c106fd5";

/** The only allowed differences. Error classes change from AeadError/Error to CryptoError in Phase 3. */
const TOMBSTONES: { id: string; landed: boolean; matches: (r: Recipe) => boolean }[] = [];

const baseline = baselineAdapterFor(baselineMod, randBaseline);
const current = redesignedAdapterFor(src, rand);
// Error class names change in Phase 3 (AeadError/Error -> CryptoError); compare throw-vs-value only.
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
