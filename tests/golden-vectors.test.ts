/** Golden vector suite: the committed freeze; changes only via `bun run vectors:generate`. */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as src from "../src";
import * as rand from "@blockchaincommons/rand";
import { materialize, redesignedAdapterFor, type Recipe } from "./vectors/recipes";

const here = dirname(fileURLToPath(import.meta.url));
const { count, vectors } = JSON.parse(readFileSync(join(here, "vectors/vectors.json"), "utf8")) as {
  count: number;
  vectors: { recipe: Recipe; expect: string }[];
};
const api = redesignedAdapterFor(src, rand);

describe("golden vectors (frozen)", () => {
  it("fixture is self-consistent and non-trivial", () => {
    expect(vectors.length).toBe(count);
    expect(vectors.length).toBeGreaterThanOrEqual(300);
  });
  vectors.forEach((v, i) => {
    it(`#${i} ${v.recipe.k}`, () => {
      expect(materialize(api, v.recipe)).toBe(v.expect);
    });
  });
});
