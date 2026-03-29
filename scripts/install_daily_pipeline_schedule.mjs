import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const ROOT = process.cwd();
const LABEL = "com.scamnomom.pipeline.daily";
const LOGS_DIR = path.join(ROOT, "logs");
const STDOUT_LOG = path.join(LOGS_DIR, "pipeline.stdout.log");
const STDERR_LOG = path.join(LOGS_DIR, "pipeline.stderr.log");

function parseArgs() {
  const args = process.argv.slice(2);
  const parsed = {
    hour: 3,
    minute: 15,
    uninstall: false,
    skipFetch: false,
    monitor: false
  };

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--hour") {
      parsed.hour = Number(args[i + 1]);
      i += 1;
      continue;
    }
    if (arg === "--minute") {
      parsed.minute = Number(args[i + 1]);
      i += 1;
      continue;
    }
    if (arg === "--uninstall") {
      parsed.uninstall = true;
      continue;
    }
    if (arg === "--skip-fetch") {
      parsed.skipFetch = true;
      continue;
    }
    if (arg === "--monitor") {
      parsed.monitor = true;
    }
  }

  return parsed;
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

function pipelineArgs(skipFetch) {
  const args = [path.join(ROOT, "scripts/run_pipeline.mjs")];
  if (skipFetch) {
    args.push("--skip-fetch");
  }
  return args;
}

function monitorArgs(skipFetch) {
  const args = [path.join(ROOT, "scripts/daily_monitor.mjs")];
  if (skipFetch) {
    args.push("--skip-fetch");
  }
  return args;
}

function scheduledArgs(config) {
  return config.monitor ? monitorArgs(config.skipFetch) : pipelineArgs(config.skipFetch);
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
      ${scheduledArgs(config).map((arg) => `<string>${arg}</string>`).join("\n      ")}
    </array>
    <key>WorkingDirectory</key>
    <string>${ROOT}</string>
    <key>StartCalendarInterval</key>
    <dict>
      <key>Hour</key>
      <integer>${config.hour}</integer>
      <key>Minute</key>
      <integer>${config.minute}</integer>
    </dict>
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
  const args = scheduledArgs(config).map((arg) => `"${arg}"`).join(" ");
  return `${config.minute} ${config.hour} * * * cd "${ROOT}" && "${process.execPath}" ${args} >> "${STDOUT_LOG}" 2>> "${STDERR_LOG}" # ${LABEL}`;
}

async function installLinux(config) {
  let current = "";
  try {
    current = await new Promise((resolve, reject) => {
      const child = spawn("crontab", ["-l"], { stdio: ["ignore", "pipe", "ignore"] });
      let output = "";
      child.stdout.on("data", (chunk) => {
        output += chunk.toString();
      });
      child.on("error", reject);
      child.on("close", () => resolve(output));
    });
  } catch {}

  const filtered = current
    .split(/\r?\n/)
    .filter((line) => line && !line.includes(`# ${LABEL}`))
    .join("\n");
  const next = `${filtered}${filtered ? "\n" : ""}${buildCronLine(config)}\n`;
  const tmpPath = path.join(LOGS_DIR, "scamnomom.cron.tmp");
  await writeFile(tmpPath, next);
  await runCommand("crontab", [tmpPath]);
  await rm(tmpPath, { force: true });
  return { platform: "linux", installed: "crontab" };
}

async function uninstallLinux() {
  let current = "";
  try {
    current = await new Promise((resolve, reject) => {
      const child = spawn("crontab", ["-l"], { stdio: ["ignore", "pipe", "ignore"] });
      let output = "";
      child.stdout.on("data", (chunk) => {
        output += chunk.toString();
      });
      child.on("error", reject);
      child.on("close", () => resolve(output));
    });
  } catch {
    return { platform: "linux", removed: "crontab" };
  }

  const filtered = current
    .split(/\r?\n/)
    .filter((line) => line && !line.includes(`# ${LABEL}`))
    .join("\n");
  const tmpPath = path.join(LOGS_DIR, "scamnomom.cron.tmp");
  await writeFile(tmpPath, filtered ? `${filtered}\n` : "");
  await runCommand("crontab", [tmpPath]);
  await rm(tmpPath, { force: true });
  return { platform: "linux", removed: "crontab" };
}

async function installWindows(config) {
  const pipeline = [process.execPath, ...scheduledArgs(config)].join(" ");
  await runCommand("schtasks", [
    "/Create",
    "/F",
    "/SC",
    "DAILY",
    "/TN",
    LABEL,
    "/TR",
    pipeline,
    "/ST",
    `${String(config.hour).padStart(2, "0")}:${String(config.minute).padStart(2, "0")}`
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

  const platform = process.platform;
  let result;

  if (config.uninstall) {
    if (platform === "darwin") {
      result = await uninstallDarwin();
    } else if (platform === "linux") {
      result = await uninstallLinux();
    } else if (platform === "win32") {
      result = await uninstallWindows();
    } else {
      throw new Error(`Unsupported platform: ${platform}`);
    }
  } else {
    if (!Number.isInteger(config.hour) || config.hour < 0 || config.hour > 23) {
      throw new Error("--hour must be an integer between 0 and 23");
    }
    if (!Number.isInteger(config.minute) || config.minute < 0 || config.minute > 59) {
      throw new Error("--minute must be an integer between 0 and 59");
    }

    if (platform === "darwin") {
      result = await installDarwin(config);
    } else if (platform === "linux") {
      result = await installLinux(config);
    } else if (platform === "win32") {
      result = await installWindows(config);
    } else {
      throw new Error(`Unsupported platform: ${platform}`);
    }
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        ...result,
        schedule: config.uninstall
          ? undefined
          : { hour: config.hour, minute: config.minute, skipFetch: config.skipFetch, monitor: config.monitor },
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
