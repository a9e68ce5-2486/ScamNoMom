import { spawn } from "node:child_process";
import path from "node:path";

const ROOT = process.cwd();

function runNodeScript(scriptPath, args = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, ...args], {
      cwd: ROOT,
      stdio: "inherit"
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(new Error(`${path.basename(scriptPath)} failed with exit code ${code}`));
    });
  });
}

async function main() {
  const args = new Set(process.argv.slice(2));
  const skipFetch = args.has("--skip-fetch");

  const steps = [];

  if (!skipFetch) {
    await runNodeScript(path.join(ROOT, "scripts/fetch_feeds.mjs"));
    steps.push("fetch_feeds");
  }

  await runNodeScript(path.join(ROOT, "scripts/prepare_dataset.mjs"));
  steps.push("prepare_dataset");

  await runNodeScript(path.join(ROOT, "scripts/build_lightweight_model_profile.mjs"));
  steps.push("build_lightweight_model_profile");

  await runNodeScript(path.join(ROOT, "scripts/mine_tw_scam_patterns.mjs"));
  steps.push("mine_tw_scam_patterns");

  await runNodeScript(path.join(ROOT, "scripts/generate_tw_dashboard.mjs"));
  steps.push("generate_tw_dashboard");

  await runNodeScript(path.join(ROOT, "scripts/build_threat_intel_profile.mjs"));
  steps.push("build_threat_intel_profile");

  console.log(
    JSON.stringify(
      {
        ok: true,
        steps,
        dashboard: path.join(ROOT, "data/processed/tw_dashboard.html")
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
