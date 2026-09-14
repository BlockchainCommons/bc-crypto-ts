/** Golden vector suite: the committed freeze; changes only via `bun run vectors:generate`. */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as src from "../src";
import * as rand from "@blockchaincommons/rand";
import { materialize, currentAdapterFor, type Recipe } from "./vectors/recipes";

const here = dirname(fileURLToPath(import.meta.url));
const { count, vectors } = JSON.parse(readFileSync(join(here, "vectors/vectors.json"), "utf8")) as {
  count: number;
  vectors: { recipe: Recipe; expect: string }[];
};
const api = currentAdapterFor(src, rand);

describe("golden vectors (frozen)", () => {
  it("fixture is self-consistent and non-trivial", () => {
    expect(vectors.length).toBe(count);
    expect(vectors.length).toBeGreaterThanOrEqual(300);
  });
  vectors.forEach((v, i) => {
    // scrypt rows derive for real: the logN 17, r 64 row (1.07 GiB) takes
    // over a second here and several on a CI runner, past vitest's 5 s default.
    const options = v.recipe.k === "scrypt" ? { timeout: 120_000 } : {};
    it(`#${i} ${v.recipe.k}`, options, () => {
      expect(materialize(api, v.recipe)).toBe(v.expect);
    });
  });
});
