import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const OUTPUT_DIR = path.join(ROOT, "data/raw/external");

const DEFAULT_OPENPHISH_URL = "https://openphish.com/feed.txt";
const DEFAULT_PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.json";

function getConfig() {
  const phishTankAppKey = process.env.PHISHTANK_APP_KEY?.trim() || "";
  const phishTankUrl = phishTankAppKey
    ? `http://data.phishtank.com/data/${phishTankAppKey}/online-valid.json`
    : DEFAULT_PHISHTANK_URL;

  return {
    phishTankUrl,
    openPhishUrl: process.env.OPENPHISH_FEED_URL?.trim() || DEFAULT_OPENPHISH_URL,
    userAgent: process.env.PHISHTANK_USER_AGENT?.trim() || "scamnomom/dev-local"
  };
}

async function downloadText(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`Request failed for ${url}: HTTP ${response.status}`);
  }

  return response.text();
}

async function fetchPhishTank(config) {
  const raw = await downloadText(config.phishTankUrl, {
    headers: {
      "User-Agent": config.userAgent
    }
  });

  JSON.parse(raw);

  const outputPath = path.join(OUTPUT_DIR, "phishtank.json");
  await writeFile(outputPath, raw);
  return outputPath;
}

async function fetchOpenPhish(config) {
  const raw = await downloadText(config.openPhishUrl);
  const outputPath = path.join(OUTPUT_DIR, "openphish.txt");
  await writeFile(outputPath, raw);
  return outputPath;
}

async function main() {
  await mkdir(OUTPUT_DIR, { recursive: true });
  const config = getConfig();
  const results = {
    phishTank: null,
    openPhish: null,
    errors: []
  };

  try {
    results.phishTank = await fetchPhishTank(config);
  } catch (error) {
    results.errors.push({
      source: "phishtank",
      message: error instanceof Error ? error.message : String(error)
    });
  }

  try {
    results.openPhish = await fetchOpenPhish(config);
  } catch (error) {
    results.errors.push({
      source: "openphish",
      message: error instanceof Error ? error.message : String(error)
    });
  }

  console.log(
    JSON.stringify(
      {
        ok: results.errors.length === 0,
        phishTankOutput: results.phishTank,
        openPhishOutput: results.openPhish,
        errors: results.errors
      },
      null,
      2
    )
  );

  if (results.errors.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
