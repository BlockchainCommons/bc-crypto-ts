/**
 * Golden vector generator. `bun scripts/generate-vectors.mjs`.
 * Materialises the golden recipe subset with the WORKING TREE and writes
 * tests/vectors/vectors.json. Regenerating is a deliberate, reviewed act.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as src from "../src/index.ts";
import * as rand from "@blockchaincommons/rand";
import { materialize, redesignedAdapterFor } from "../tests/vectors/recipes.ts";
import { goldenRecipes } from "../tests/corpus/corpus.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const api = redesignedAdapterFor(src, rand);
const vectors = [];
for (const recipe of goldenRecipes()) vectors.push({ recipe, expect: materialize(api, recipe) });
writeFileSync(join(root, "tests/vectors/vectors.json"), JSON.stringify({ count: vectors.length, vectors }, null, 1) + "\n");
console.log(`wrote ${vectors.length} vectors`);
