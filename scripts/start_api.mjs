import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const ROOT = process.cwd();
const API_DIR = path.join(ROOT, "apps/api");
const ENV_EXAMPLE = path.join(API_DIR, ".env.example");
const ENV_FILE = path.join(API_DIR, ".env");

function parseArgs() {
  return {
    dev: process.argv.includes("--dev")
  };
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

async function ensureEnv() {
  if (await exists(ENV_FILE)) {
    return;
  }

  const content = await readFile(ENV_EXAMPLE, "utf8");
  await mkdir(API_DIR, { recursive: true });
  await writeFile(ENV_FILE, content);
}

async function ensureNodeModules() {
  const nodeModules = path.join(API_DIR, "node_modules");
  if (await exists(nodeModules)) {
    return;
  }

  await runCommand("npm", ["install"], API_DIR);
}

async function main() {
  const config = parseArgs();
  await ensureEnv();
  await ensureNodeModules();

  if (config.dev) {
    await runCommand("npm", ["run", "dev"], API_DIR);
    return;
  }

  await runCommand("npm", ["run", "build"], API_DIR);
  await runCommand("npm", ["run", "start"], API_DIR);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
