import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const ROOT = process.cwd();
const API_DIR = path.join(ROOT, "apps/api");
const ENV_FILE = path.join(API_DIR, ".env");

function run(command, args = []) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd: ROOT, shell: false });
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", (error) => {
      resolve({ ok: false, stdout, stderr: error.message });
    });
    child.on("close", (code) => {
      resolve({ ok: code === 0, stdout, stderr });
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

async function main() {
  const checks = [];

  checks.push({
    name: "node",
    ...(await run("node", ["--version"]))
  });

  checks.push({
    name: "npm",
    ...(await run("npm", ["--version"]))
  });

  checks.push({
    name: "api_env",
    ok: await exists(ENV_FILE),
    stdout: await exists(ENV_FILE) ? "apps/api/.env present" : "",
    stderr: await exists(ENV_FILE) ? "" : "apps/api/.env missing"
  });

  checks.push({
    name: "api_node_modules",
    ok: await exists(path.join(API_DIR, "node_modules")),
    stdout: "",
    stderr: (await exists(path.join(API_DIR, "node_modules"))) ? "" : "apps/api/node_modules missing"
  });

  const envExists = await exists(ENV_FILE);
  let envContent = "";
  if (envExists) {
    envContent = await readFile(ENV_FILE, "utf8");
  }

  const providerMatch = envContent.match(/^LLM_PROVIDER=(.*)$/m);
  const provider = providerMatch?.[1]?.trim() || "unknown";

  if (provider === "ollama" || provider === "auto") {
    checks.push({
      name: "ollama",
      ...(await run("ollama", ["--version"]))
    });
  }

  const failed = checks.filter((check) => !check.ok).length;

  console.log(
    JSON.stringify(
      {
        ok: failed === 0,
        provider,
        checks: checks.map((check) => ({
          name: check.name,
          ok: check.ok,
          detail: (check.stdout || check.stderr || "").trim()
        }))
      },
      null,
      2
    )
  );

  if (failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
