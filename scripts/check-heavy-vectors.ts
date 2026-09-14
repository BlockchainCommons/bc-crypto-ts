/**
 * Replays tests/vectors/heavy.json with the working tree on this runtime.
 *
 *   bun scripts/check-heavy-vectors.ts
 *
 * Run it with Bun in CI: JavaScriptCore caps one typed array at 2^32 bytes,
 * so this is the runtime where scrypt's paged core has to produce the
 * reference's bytes. Node runs the same file through
 * `CRYPTO_HEAVY=1 bunx vitest run tests/heavy-vectors.test.ts`. Needs about
 * 5 GiB of memory and takes seconds to a minute. Exit 1 on any difference.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as src from "../src/index.ts";
import * as rand from "@blockchaincommons/rand";
import { materialize, redesignedAdapterFor, type Recipe } from "../tests/vectors/recipes.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { count, vectors } = JSON.parse(
  readFileSync(join(root, "tests/vectors/heavy.json"), "utf8"),
) as { count: number; vectors: { recipe: Recipe; expect: string }[] };
if (vectors.length !== count) throw new Error("heavy.json count does not match its vectors");
const api = redesignedAdapterFor(src, rand);

let mismatch = 0;
for (const v of vectors) {
  const t0 = performance.now();
  const got = materialize(api, v.recipe);
  const seconds = ((performance.now() - t0) / 1000).toFixed(1);
  if (got === v.expect) {
    console.log(`match ${JSON.stringify(v.recipe)} (${seconds} s)`);
  } else {
    mismatch++;
    console.error(`MISMATCH ${JSON.stringify(v.recipe)}\n  expect: ${v.expect}\n  got:    ${got}`);
  }
}
console.log(`${vectors.length} heavy vectors - ${vectors.length - mismatch} match, ${mismatch} MISMATCH`);
process.exit(mismatch === 0 ? 0 : 1);
