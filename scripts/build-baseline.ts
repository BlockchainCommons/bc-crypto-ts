/**
 * Build a baseline bundle from a historical checkout.
 *
 *   bun scripts/build-baseline.ts
 *
 * Run against the source revision recorded in tests/baseline/README.md.
 * Current sources may require exports absent from frozen sibling bundles.
 * This command overwrites the baseline; it is not a routine build step.
 *
 * Bundles src/index.ts as a single ESM file with every @blockchaincommons
 * sibling INLINED, resolving each sibling to ITS frozen baseline bundle
 * (../<repo>/tests/baseline/<pkg>-baseline.mjs) when one exists, so the
 * baseline keeps the behaviour its dependencies had at that commit even
 * after they change. Writes tests/baseline/<pkg>-baseline.mjs, the .d.mts API
 * snapshot, and README.md with the commit and sha256 pinned.
 */
import { build } from "tsdown";
import { createHash } from "node:crypto";
import { execSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  copyFileSync,
  readdirSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const parent = dirname(root);
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const short = pkg.name.replace("@blockchaincommons/", "");
const outDir = join(root, "tests", "baseline");
mkdirSync(outDir, { recursive: true });

// Map every sibling to its frozen baseline bundle where available.
const alias: Record<string, string> = {};
for (const dir of readdirSync(parent)) {
  const bl = join(parent, dir, "tests", "baseline");
  if (!existsSync(bl)) continue;
  const f = readdirSync(bl).find((x) => x.endsWith("-baseline.mjs"));
  if (!f) continue;
  const depPkgPath = join(parent, dir, "package.json");
  if (!existsSync(depPkgPath)) continue;
  const depName = JSON.parse(readFileSync(depPkgPath, "utf8")).name;
  // dcbor is a published, stable dependency: never alias it to its own
  // (much older) baseline bundle.
  if (depName !== pkg.name && depName !== "@blockchaincommons/dcbor") alias[depName] = join(bl, f);
}

await build({
  entry: { [`${short}-baseline`]: join(root, "src/index.ts") },
  outDir,
  format: ["esm"],
  dts: false,
  sourcemap: false,
  clean: false,
  target: "es2022",
  noExternal: [/^@blockchaincommons\//],
  alias,
  inputOptions: {
    onwarn(w, d) {
      if (w.code !== "SOURCEMAP_BROKEN") d(w);
    },
  },
});

const bundle = join(outDir, `${short}-baseline.mjs`);
let text = readFileSync(bundle, "utf8").replace(/\n\/\/# sourceMappingURL=.*\n?$/, "\n");
writeFileSync(bundle, text);
const sha = createHash("sha256").update(text).digest("hex");
const commit = execSync("git rev-parse HEAD", { cwd: root }).toString().trim();
if (existsSync(join(root, "api/index.d.mts")))
  copyFileSync(join(root, "api/index.d.mts"), join(outDir, `${short}-baseline.d.mts`));
writeFileSync(
  join(outDir, "README.md"),
  `# Frozen baseline build

\`${short}-baseline.mjs\` is the self-contained ESM bundle of \`${pkg.name}\` built from
commit \`${commit}\`, the \`@bcts/${short}\` wire-format reference. Sibling
\`@blockchaincommons/*\` packages are INLINED from their own frozen baseline
bundles (${Object.keys(alias).length ? Object.keys(alias).join(", ") : "none"}), so this bundle keeps the
behaviour its dependencies had at that commit.
\`${short}-baseline.d.mts\` is the public surface at that commit.

\`tests/differential.test.ts\` runs every corpus recipe through this bundle and
the working tree and asserts identical outcomes; it pins the sha256 below so
an accidental rebuild cannot turn the differential into a self-comparison.

Baseline commit: ${commit}
Baseline sha256: ${sha}
`,
);
console.log(
  `wrote ${bundle}\nsha256 ${sha}\ncommit ${commit}\naliases: ${JSON.stringify(alias, null, 1)}`,
);
