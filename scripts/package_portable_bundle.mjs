import { chmod, cp, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const DIST_DIR = path.join(ROOT, "dist", "scamnomom-portable");

const COPY_TARGETS = [
  "README.md",
  "README.zh-TW.md",
  "INSTALL.md",
  "INSTALL.zh-TW.md",
  "setup-scamnomom.sh",
  "setup-scamnomom.command",
  "setup-scamnomom.bat",
  "start-scamnomom.sh",
  "start-scamnomom.command",
  "start-scamnomom.bat",
  "package.json",
  "apps/api/package.json",
  "apps/api/package-lock.json",
  "apps/api/tsconfig.json",
  "apps/api/.env.example",
  "apps/api/src",
  "apps/extension",
  "data/README.md",
  "data/README.zh-TW.md",
  "data/benchmarks",
  "data/schemas",
  "data/tw_brand_domains.json",
  "data/tw_scam_keywords.json",
  "data/processed/tw_scam_pattern_approvals.json",
  "docs",
  "scripts"
];

async function copyTarget(relativePath) {
  await cp(path.join(ROOT, relativePath), path.join(DIST_DIR, relativePath), { recursive: true });
}

async function writeLauncherFiles() {
  const unixFiles = [
    "start-scamnomom.sh",
    "start-scamnomom.command",
    "setup-ollama.sh",
    "setup-ollama.command",
    "setup-scamnomom.sh",
    "setup-scamnomom.command"
  ];

  const unixLauncher = `#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
npm run start
`;

  const windowsLauncher = `@echo off
cd /d %~dp0
npm run start
`;

  const setupOllamaUnix = `#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
npm run setup:ollama
`;

  const setupAutoUnix = `#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
npm run setup
`;

  const setupOllamaWindows = `@echo off
cd /d %~dp0
npm run setup:ollama
`;

  const setupAutoWindows = `@echo off
cd /d %~dp0
npm run setup
`;

  const releaseReadme = `ScamNoMom Portable Bundle

Quick start
1. Run setup-ollama or use npm run setup:openai.
2. Run start-scamnomom.
3. Open Chrome and load apps/extension.
4. Use the extension Settings page to confirm the API URL.

Main commands
- npm run setup
- npm run start
- npm run doctor
- npm run test:smoke
- npm run benchmark
- npm run service:install
- npm run schedule:install
`;

  await writeFile(path.join(DIST_DIR, "start-scamnomom.sh"), unixLauncher);
  await writeFile(path.join(DIST_DIR, "start-scamnomom.command"), unixLauncher);
  await writeFile(path.join(DIST_DIR, "start-scamnomom.bat"), windowsLauncher);
  await writeFile(path.join(DIST_DIR, "setup-ollama.sh"), setupOllamaUnix);
  await writeFile(path.join(DIST_DIR, "setup-ollama.command"), setupOllamaUnix);
  await writeFile(path.join(DIST_DIR, "setup-ollama.bat"), setupOllamaWindows);
  await writeFile(path.join(DIST_DIR, "setup-scamnomom.sh"), setupAutoUnix);
  await writeFile(path.join(DIST_DIR, "setup-scamnomom.command"), setupAutoUnix);
  await writeFile(path.join(DIST_DIR, "setup-scamnomom.bat"), setupAutoWindows);
  await writeFile(path.join(DIST_DIR, "PORTABLE_BUNDLE.md"), releaseReadme);

  for (const file of unixFiles) {
    await chmod(path.join(DIST_DIR, file), 0o755);
  }
}

async function main() {
  await rm(DIST_DIR, { recursive: true, force: true });
  await mkdir(DIST_DIR, { recursive: true });

  for (const target of COPY_TARGETS) {
    await copyTarget(target);
  }

  await mkdir(path.join(DIST_DIR, "logs"), { recursive: true });
  await mkdir(path.join(DIST_DIR, "data", "raw", "external"), { recursive: true });
  await writeLauncherFiles();

  console.log(
    JSON.stringify(
      {
        ok: true,
        output: DIST_DIR,
        note: "Portable bundle created. Compress this folder if you want to share it with end users."
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
