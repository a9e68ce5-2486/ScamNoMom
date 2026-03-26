import { spawn } from "node:child_process";
import path from "node:path";

const ROOT = process.cwd();

function parseArgs() {
  return {
    dev: process.argv.includes("--dev")
  };
}

function run() {
  const config = parseArgs();
  const target = path.join(ROOT, "scripts", "start_api.mjs");
  const args = [target];

  if (config.dev) {
    args.push("--dev");
  }

  console.log("ScamNoMom local system startup");
  console.log("API will be available at http://localhost:8787");
  console.log("After the API is running, open Chrome and load apps/extension if you have not done that yet.");

  const child = spawn(process.execPath, args, {
    cwd: ROOT,
    stdio: "inherit",
    shell: false
  });

  child.on("close", (code) => {
    process.exitCode = code ?? 0;
  });

  child.on("error", (error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}

run();
