/**
 * Dependency hygiene gate.
 *
 *   bun scripts/check-deps.ts          # no @bcts/* or workspace: dependency
 *   bun scripts/check-deps.ts --zero   # additionally: zero runtime deps
 *
 * The first check is universal: a published package must never depend on
 * `@bcts/*` or use a `workspace:` protocol range, neither of which resolves
 * from the npm registry. The `--zero` form additionally
 * enforces the zero-runtime-dependency policy for the packages that hold it.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const zero = process.argv.includes("--zero");

const groups = ["dependencies", "peerDependencies", "optionalDependencies", "devDependencies"];
let failed = false;

for (const group of groups) {
  for (const [name, range] of Object.entries(pkg[group] ?? {})) {
    if (name.startsWith("@bcts/")) {
      console.error(`${group}: "${name}" is a @bcts package and cannot be published.`);
      failed = true;
    }
    if (typeof range === "string" && range.startsWith("workspace:")) {
      console.error(`${group}: "${name}" uses the workspace: protocol ("${range}").`);
      failed = true;
    }
  }
}

if (zero) {
  const runtime = Object.keys(pkg.dependencies ?? {});
  if (runtime.length > 0) {
    console.error("zero-dependency policy violated:", runtime.join(", "));
    failed = true;
  }
}

if (failed) process.exit(1);
console.log(zero ? "zero runtime dependencies" : "no @bcts or workspace: dependencies");
