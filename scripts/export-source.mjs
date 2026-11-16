/**
 * Build step: copies the application's own source code into public/source/ so
 * the Security Manual (/manual.html) can append it verbatim as an appendix.
 * Runs on every deploy, so the appendix can never drift from the deployed code.
 */
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const out = join(root, "public", "source");

const migrationsDir = join(root, "netlify/database/migrations");
const migrations = existsSync(migrationsDir)
  ? readdirSync(migrationsDir)
      .sort()
      .map((d) => `netlify/database/migrations/${d}/migration.sql`)
      .filter((f) => existsSync(join(root, f)))
  : [];

const groups = [
  { title: "Database script", files: [...migrations, "db/schema.ts", "db/index.ts", "drizzle.config.ts"] },
  {
    title: "Server application",
    files: ["netlify/server/lib/crypto.ts", "netlify/server/lib/session.ts", "netlify/server/index.ts"],
  },
  {
    title: "Dashboard (client)",
    files: [
      "public/index.html",
      "public/dashboard.html",
      "public/evidence.html",
      "public/js/api.js",
      "public/js/login.js",
      "public/js/dashboard.js",
      "public/js/evidence.js",
    ],
  },
  { title: "Configuration & build", files: ["netlify.toml", "package.json", "scripts/export-source.mjs"] },
];

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const manifest = groups.map((g) => ({
  title: g.title,
  files: g.files
    .filter((f) => existsSync(join(root, f)))
    .map((path, i) => {
      const content = readFileSync(join(root, path), "utf8");
      const name = `${g.title.replace(/\W+/g, "-").toLowerCase()}-${i}.txt`;
      writeFileSync(join(out, name), content);
      return { path, url: `/source/${name}`, lines: content.split("\n").length };
    }),
}));

writeFileSync(join(out, "manifest.json"), JSON.stringify({ generatedAt: new Date().toISOString(), groups: manifest }, null, 2));
console.log(`Exported ${manifest.reduce((n, g) => n + g.files.length, 0)} source files to public/source/`);
