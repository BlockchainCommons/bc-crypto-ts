/**
 * The heavy vectors (tests/vectors/heavy.json) on Node. Skipped unless
 * `CRYPTO_HEAVY=1`: the logN 22, r 9 scrypt vector needs about 5 GiB and
 * several seconds. CI runs it; Bun runs the same file through
 * `scripts/check-heavy-vectors.ts`.
 */
import { readFileSync } from "node:fs";
import process from "node:process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as src from "../src";
import * as rand from "@blockchaincommons/rand";
import { materialize, redesignedAdapterFor, type Recipe } from "./vectors/recipes";

const here = dirname(fileURLToPath(import.meta.url));
const { count, vectors } = JSON.parse(readFileSync(join(here, "vectors/heavy.json"), "utf8")) as {
  count: number;
  vectors: { recipe: Recipe; expect: string }[];
};
const api = redesignedAdapterFor(src, rand);

describe.skipIf(process.env["CRYPTO_HEAVY"] !== "1")("heavy vectors (CRYPTO_HEAVY=1)", () => {
  it("fixture is self-consistent", () => {
    expect(vectors.length).toBe(count);
    expect(vectors.length).toBeGreaterThan(0);
  });
  vectors.forEach((v, i) => {
    it(`#${i} ${v.recipe.k}`, { timeout: 600_000 }, () => {
      expect(materialize(api, v.recipe)).toBe(v.expect);
    });
  });
});
