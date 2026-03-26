import { mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const ROOT = process.cwd();
const LABEL = "com.scamnomom.api.autostart";
const LOGS_DIR = path.join(ROOT, "logs");
const STDOUT_LOG = path.join(LOGS_DIR, "api.stdout.log");
const STDERR_LOG = path.join(LOGS_DIR, "api.stderr.log");

function parseArgs() {
  return {
    uninstall: process.argv.includes("--uninstall"),
    dev: process.argv.includes("--dev")
  };
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: "inherit",
      shell: false,
      ...options
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

function apiArgs(dev) {
  const args = [path.join(ROOT, "scripts/start_api.mjs")];
  if (dev) {
    args.push("--dev");
  }
  return args;
}

function buildLaunchdPlist(config) {
  const plistPath = path.join(os.homedir(), "Library", "LaunchAgents", `${LABEL}.plist`);

  return {
    plistPath,
    content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
      <string>${process.execPath}</string>
      ${apiArgs(config.dev).map((arg) => `<string>${arg}</string>`).join("\n      ")}
    </array>
    <key>WorkingDirectory</key>
    <string>${ROOT}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${STDOUT_LOG}</string>
    <key>StandardErrorPath</key>
    <string>${STDERR_LOG}</string>
  </dict>
</plist>`
  };
}

async function installDarwin(config) {
  const { plistPath, content } = buildLaunchdPlist(config);
  await mkdir(path.dirname(plistPath), { recursive: true });
  await writeFile(plistPath, content);

  try {
    await runCommand("launchctl", ["bootout", `gui/${process.getuid()}`, plistPath]);
  } catch {}

  await runCommand("launchctl", ["bootstrap", `gui/${process.getuid()}`, plistPath]);
  return { platform: "darwin", installed: plistPath };
}

async function uninstallDarwin() {
  const plistPath = path.join(os.homedir(), "Library", "LaunchAgents", `${LABEL}.plist`);
  try {
    await runCommand("launchctl", ["bootout", `gui/${process.getuid()}`, plistPath]);
  } catch {}
  await rm(plistPath, { force: true });
  return { platform: "darwin", removed: plistPath };
}

function buildCronLine(config) {
  const args = apiArgs(config.dev).map((arg) => `"${arg}"`).join(" ");
  return `@reboot cd "${ROOT}" && "${process.execPath}" ${args} >> "${STDOUT_LOG}" 2>> "${STDERR_LOG}" # ${LABEL}`;
}

async function readCrontab() {
  try {
    return await new Promise((resolve, reject) => {
      const child = spawn("crontab", ["-l"], { stdio: ["ignore", "pipe", "ignore"] });
      let output = "";
      child.stdout.on("data", (chunk) => {
        output += chunk.toString();
      });
      child.on("error", reject);
      child.on("close", () => resolve(output));
    });
  } catch {
    return "";
  }
}

async function installLinux(config) {
  const current = await readCrontab();
  const filtered = current
    .split(/\r?\n/)
    .filter((line) => line && !line.includes(`# ${LABEL}`))
    .join("\n");
  const next = `${filtered}${filtered ? "\n" : ""}${buildCronLine(config)}\n`;
  const tmpPath = path.join(LOGS_DIR, "scamnomom-api.cron.tmp");
  await writeFile(tmpPath, next);
  await runCommand("crontab", [tmpPath]);
  await rm(tmpPath, { force: true });
  return { platform: "linux", installed: "crontab" };
}

async function uninstallLinux() {
  const current = await readCrontab();
  const filtered = current
    .split(/\r?\n/)
    .filter((line) => line && !line.includes(`# ${LABEL}`))
    .join("\n");
  const tmpPath = path.join(LOGS_DIR, "scamnomom-api.cron.tmp");
  await writeFile(tmpPath, filtered ? `${filtered}\n` : "");
  await runCommand("crontab", [tmpPath]);
  await rm(tmpPath, { force: true });
  return { platform: "linux", removed: "crontab" };
}

async function installWindows(config) {
  const command = [process.execPath, ...apiArgs(config.dev)].join(" ");
  await runCommand("schtasks", [
    "/Create",
    "/F",
    "/SC",
    "ONLOGON",
    "/TN",
    LABEL,
    "/TR",
    command
  ]);
  return { platform: "win32", installed: LABEL };
}

async function uninstallWindows() {
  try {
    await runCommand("schtasks", ["/Delete", "/F", "/TN", LABEL]);
  } catch {}
  return { platform: "win32", removed: LABEL };
}

async function main() {
  const config = parseArgs();
  await mkdir(LOGS_DIR, { recursive: true });

  let result;
  if (config.uninstall) {
    if (process.platform === "darwin") {
      result = await uninstallDarwin();
    } else if (process.platform === "linux") {
      result = await uninstallLinux();
    } else if (process.platform === "win32") {
      result = await uninstallWindows();
    } else {
      throw new Error(`Unsupported platform: ${process.platform}`);
    }
  } else if (process.platform === "darwin") {
    result = await installDarwin(config);
  } else if (process.platform === "linux") {
    result = await installLinux(config);
  } else if (process.platform === "win32") {
    result = await installWindows(config);
  } else {
    throw new Error(`Unsupported platform: ${process.platform}`);
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        ...result,
        mode: config.dev ? "dev" : "prod",
        logs: {
          stdout: STDOUT_LOG,
          stderr: STDERR_LOG
        }
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
