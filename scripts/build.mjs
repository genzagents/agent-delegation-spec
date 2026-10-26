// Strip types from src/*.ts into dist/*.js so `npx` and plain `node` work without TypeScript tooling.
import { stripTypeScriptTypes } from "node:module";
import { mkdirSync, readdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
mkdirSync("dist", { recursive: true });
for (const f of readdirSync("src").filter((f) => f.endsWith(".ts"))) {
  const src = readFileSync(`src/${f}`, "utf8");
  const js = stripTypeScriptTypes(src, { mode: "strip" }).replace(/(from\s+"\.\/[^"]+)\.ts"/g, '$1.js"');
  const out = `dist/${f.replace(/\.ts$/, ".js")}`;
  writeFileSync(out, js);
  if (f === "cli.ts") chmodSync(out, 0o755);
}
console.log("built dist/");
