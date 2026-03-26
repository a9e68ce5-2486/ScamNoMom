import { access, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const ROOT = process.cwd();
const API_DIR = path.join(ROOT, "apps/api");
const ENV_EXAMPLE = path.join(API_DIR, ".env.example");
const ENV_FILE = path.join(API_DIR, ".env");
const LOGS_DIR = path.join(ROOT, "logs");
const EXTERNAL_DIR = path.join(ROOT, "data/raw/external");
const FEEDBACK_DIR = path.join(ROOT, "data/raw/feedback");
const PROCESSED_DIR = path.join(ROOT, "data/processed");

function parseArgs() {
  const args = process.argv.slice(2);
  const parsed = {
    provider: "auto",
    skipInstall: false
  };

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--provider") {
      parsed.provider = String(args[i + 1] || "auto").toLowerCase();
      i += 1;
      continue;
    }
    if (arg === "--skip-install") {
      parsed.skipInstall = true;
    }
  }

  return parsed;
}

function runCommand(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: "inherit",
      shell: false
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} ${args.join(" ")} failed with exit code ${code}`));
    });
  });
}

async function exists(filePath) {
  try {
    await access(filePath, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function ensureEnv(provider) {
  if (!(await exists(ENV_FILE))) {
    await copyFile(ENV_EXAMPLE, ENV_FILE);
  }

  const replacements = {
    auto: "LLM_PROVIDER=auto",
    ollama: "LLM_PROVIDER=ollama",
    openai: "LLM_PROVIDER=openai"
  };

  const current = await readFile(ENV_FILE, "utf8");
  const updated = current.replace(/LLM_PROVIDER=.*/g, replacements[provider] ?? replacements.auto);
  await writeFile(ENV_FILE, updated);
}

async function main() {
  const config = parseArgs();

  await mkdir(LOGS_DIR, { recursive: true });
  await mkdir(EXTERNAL_DIR, { recursive: true });
  await mkdir(FEEDBACK_DIR, { recursive: true });
  await mkdir(PROCESSED_DIR, { recursive: true });

  if (!config.skipInstall) {
    await runCommand("npm", ["install"], API_DIR);
  }

  await ensureEnv(config.provider);

  console.log(
    JSON.stringify(
      {
        ok: true,
        apiDir: API_DIR,
        envFile: ENV_FILE,
        provider: config.provider,
        nextSteps: [
          "cd apps/api && npm run dev",
          "Load apps/extension in chrome://extensions",
          "Optionally run node scripts/run_pipeline.mjs --skip-fetch"
        ]
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
