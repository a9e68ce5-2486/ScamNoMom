import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const OUTPUT_DIR = path.join(ROOT, "data/raw/external");
const STATUS_PATH = path.join(OUTPUT_DIR, "feed-status.json");

const DEFAULT_OPENPHISH_URL = "https://openphish.com/feed.txt";
const DEFAULT_PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json";
const DEFAULT_URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_online/";
const DEFAULT_PHISHING_ARMY_URL = "https://phishing.army/download/phishing_army_blocklist_extended.txt";
const DEFAULT_RETRY_MAX = 3;
const DEFAULT_TIMEOUT_MS = 12_000;

function parsePositiveInt(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function getConfig() {
  const phishTankAppKey = process.env.PHISHTANK_APP_KEY?.trim() || "";
  const phishTankUrl = phishTankAppKey
    ? `https://data.phishtank.com/data/${phishTankAppKey}/online-valid.json`
    : DEFAULT_PHISHTANK_URL;

  return {
    phishTankUrl,
    openPhishUrl: process.env.OPENPHISH_FEED_URL?.trim() || DEFAULT_OPENPHISH_URL,
    urlHausUrl: process.env.URLHAUS_FEED_URL?.trim() || DEFAULT_URLHAUS_URL,
    phishingArmyUrl: process.env.PHISHING_ARMY_FEED_URL?.trim() || DEFAULT_PHISHING_ARMY_URL,
    userAgent: process.env.PHISHTANK_USER_AGENT?.trim() || "scamnomom/dev-local",
    retryMax: parsePositiveInt(process.env.FEED_FETCH_RETRY_MAX, DEFAULT_RETRY_MAX, 1, 8),
    timeoutMs: parsePositiveInt(process.env.FEED_FETCH_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, 1000, 60_000),
    requireAll: String(process.env.FEED_FETCH_REQUIRE_ALL || "").trim().toLowerCase() === "true"
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function downloadTextWithRetry(url, options = {}, retryMax = DEFAULT_RETRY_MAX, timeoutMs = DEFAULT_TIMEOUT_MS) {
  let lastError;
  for (let attempt = 1; attempt <= retryMax; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return await response.text();
    } catch (error) {
      const message =
        error instanceof Error && error.name === "AbortError"
          ? `request timed out after ${timeoutMs}ms`
          : error instanceof Error
            ? error.message
            : String(error);
      lastError = new Error(`Request failed for ${url}: ${message}`);
      if (attempt < retryMax) {
        await sleep(2 ** attempt * 500);
      }
    } finally {
      clearTimeout(timeout);
    }
  }
  throw lastError ?? new Error(`Request failed for ${url}`);
}

async function fetchPhishTank(config) {
  const raw = await downloadTextWithRetry(
    config.phishTankUrl,
    {
      headers: {
        "User-Agent": config.userAgent
      }
    },
    config.retryMax,
    config.timeoutMs
  );
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new Error("PhishTank response is not a JSON array.");
  }
  const outputPath = path.join(OUTPUT_DIR, "phishtank.json");
  await writeFile(outputPath, raw);
  return {
    outputPath,
    records: parsed.length
  };
}

async function fetchOpenPhish(config) {
  const raw = await downloadTextWithRetry(config.openPhishUrl, {}, config.retryMax, config.timeoutMs);
  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length === 0) {
    throw new Error("OpenPhish feed is empty.");
  }
  const outputPath = path.join(OUTPUT_DIR, "openphish.txt");
  await writeFile(outputPath, raw);
  return {
    outputPath,
    records: lines.length
  };
}

async function fetchUrlHaus(config) {
  const raw = await downloadTextWithRetry(config.urlHausUrl, {}, config.retryMax, config.timeoutMs);
  const rows = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
  if (rows.length === 0) {
    throw new Error("URLhaus feed has no rows.");
  }
  const outputPath = path.join(OUTPUT_DIR, "urlhaus.csv");
  await writeFile(outputPath, raw);
  return {
    outputPath,
    records: rows.length
  };
}

async function fetchPhishingArmy(config) {
  const raw = await downloadTextWithRetry(
    config.phishingArmyUrl,
    {
      headers: {
        "User-Agent": config.userAgent
      }
    },
    config.retryMax,
    config.timeoutMs
  );
  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
  if (lines.length === 0) {
    throw new Error("Phishing Army feed is empty.");
  }
  const outputPath = path.join(OUTPUT_DIR, "phishing_army.txt");
  await writeFile(outputPath, raw);
  return {
    outputPath,
    records: lines.length
  };
}

async function main() {
  await mkdir(OUTPUT_DIR, { recursive: true });
  const config = getConfig();
  const tasks = [
    { name: "phishtank", run: () => fetchPhishTank(config) },
    { name: "openphish", run: () => fetchOpenPhish(config) },
    { name: "urlhaus", run: () => fetchUrlHaus(config) },
    { name: "phishing_army", run: () => fetchPhishingArmy(config) }
  ];
  const successes = [];
  const errors = [];

  for (const task of tasks) {
    try {
      const result = await task.run();
      successes.push({
        source: task.name,
        ...result
      });
    } catch (error) {
      errors.push({
        source: task.name,
        message: error instanceof Error ? error.message : String(error)
      });
    }
  }

  const status = {
    generatedAt: new Date().toISOString(),
    config: {
      retryMax: config.retryMax,
      timeoutMs: config.timeoutMs,
      requireAll: config.requireAll
    },
    successes,
    errors
  };
  await writeFile(STATUS_PATH, JSON.stringify(status, null, 2));
  const ok = config.requireAll ? errors.length === 0 : successes.length > 0;

  console.log(
    JSON.stringify(
      {
        ok,
        fetchedSources: successes.map((entry) => entry.source),
        failedSources: errors.map((entry) => entry.source),
        statusFile: STATUS_PATH,
        successes,
        errors
      },
      null,
      2
    )
  );

  if (!ok) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
