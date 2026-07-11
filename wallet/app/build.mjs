#!/usr/bin/env node
// npm-free UI build for the MindChain Wallet desktop shell.
// Uses only node builtins: TypeScript is stripped with node:module's
// stripTypeScriptTypes (no bundler, no package manager, no registry access).
//
//   node wallet/app/build.mjs [outDir]     (default: wallet/app/ui/dist)
//
// The dist tree is flat: main.js next to index.html, shared cores under
// core/, and wallet/identity.mjs vendored to core/identity.mjs. The two
// import-specifier rewrites below exist ONLY because of that flattening and
// are exact-string, not general resolution.
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = dirname(fileURLToPath(import.meta.url));
const uiRoot = join(appRoot, "ui");

export async function build(outDir = join(uiRoot, "dist")) {
  const out = resolve(outDir);
  await rm(out, { recursive: true, force: true });
  await mkdir(join(out, "core"), { recursive: true });

  await cp(join(uiRoot, "index.html"), join(out, "index.html"));
  await cp(join(uiRoot, "styles.css"), join(out, "styles.css"));

  // src/main.ts -> main.js: strip types, then retarget core imports for the
  // flattened layout (src/../core -> ./core).
  const ts = await readFile(join(uiRoot, "src", "main.ts"), "utf8");
  const js = stripTypeScriptTypes(ts, { mode: "strip" })
    .replaceAll('"../core/', '"./core/');
  await writeFile(join(out, "main.js"), js);

  // Shared cores: manifest.mjs imports the product identity module from
  // wallet/; vendor it beside the cores and retarget that one specifier.
  for (const name of ["derivation.mjs", "address.mjs", "manifest.mjs"]) {
    const source = await readFile(join(uiRoot, "core", name), "utf8");
    await writeFile(
      join(out, "core", name),
      source.replaceAll('"../../../identity.mjs"', '"./identity.mjs"'),
    );
  }
  await cp(join(appRoot, "..", "identity.mjs"), join(out, "core", "identity.mjs"));
  return out;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = await build(process.argv[2]);
  console.log(`built ${out}`);
}
