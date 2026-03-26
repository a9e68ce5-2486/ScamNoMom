import { cp, mkdir, rm } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const SOURCE_DIR = path.join(ROOT, "apps", "extension");
const DIST_DIR = path.join(ROOT, "dist", "scamnomom-extension");

async function main() {
  await rm(DIST_DIR, { recursive: true, force: true });
  await mkdir(path.dirname(DIST_DIR), { recursive: true });
  await cp(SOURCE_DIR, DIST_DIR, { recursive: true });

  console.log(
    JSON.stringify(
      {
        ok: true,
        output: DIST_DIR,
        note: "Load this folder with chrome://extensions or zip it for release."
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
