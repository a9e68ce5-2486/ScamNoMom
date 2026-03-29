import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const TRAINING_SAMPLES_PATH = path.join(ROOT, "data/processed/training-samples.json");
const OUTPUT_DIR = path.join(ROOT, "data/processed");
const OUTPUT_PATH = path.join(OUTPUT_DIR, "threat-intel-profile.json");

function tokenize(text) {
  const normalized = String(text || "").toLowerCase();
  const chinese = normalized.match(/[\u4e00-\u9fff]{2,8}/g) || [];
  const latin = normalized.match(/[a-z0-9]{3,24}/g) || [];
  return [...new Set([...chinese, ...latin])];
}

function hostnameFromUrl(value) {
  try {
    return new URL(String(value || "")).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function collectSampleText(sample) {
  return [
    sample.content?.title ?? "",
    sample.content?.visibleText ?? "",
    sample.content?.subject ?? "",
    sample.content?.sender ?? "",
    sample.content?.bodyText ?? ""
  ].join(" ");
}

function updateCounter(counter, key, label) {
  if (!key) {
    return;
  }
  const current = counter.get(key) || { phishing: 0, safe: 0 };
  current[label] += 1;
  counter.set(key, current);
}

function toWeightedEntries(counter, minTotal, minWeight) {
  const entries = [];
  for (const [value, stat] of counter.entries()) {
    const phishing = stat.phishing || 0;
    const safe = stat.safe || 0;
    const total = phishing + safe;
    if (total < minTotal) {
      continue;
    }
    const weight = (phishing + 1) / (safe + 1);
    if (weight < minWeight) {
      continue;
    }
    entries.push({
      value,
      weight: Number(weight.toFixed(3)),
      phishingCount: phishing,
      safeCount: safe
    });
  }

  return entries.sort((a, b) => b.weight - a.weight);
}

async function readSamples() {
  try {
    const raw = await readFile(TRAINING_SAMPLES_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function main() {
  const samples = await readSamples();
  const tokenCounter = new Map();
  const hostCounter = new Map();
  let phishingCount = 0;
  let safeCount = 0;

  for (const sample of samples) {
    const label = sample?.label === "phishing" ? "phishing" : sample?.label === "safe" ? "safe" : null;
    if (!label) {
      continue;
    }

    if (label === "phishing") {
      phishingCount += 1;
    } else {
      safeCount += 1;
    }

    const sampleText = collectSampleText(sample);
    const tokens = tokenize(sampleText);
    for (const token of tokens) {
      updateCounter(tokenCounter, token, label);
    }

    const hostname = String(sample.content?.hostname || "").toLowerCase() || hostnameFromUrl(sample.content?.url || "");
    updateCounter(hostCounter, hostname, label);
  }

  const tokenWeights = toWeightedEntries(tokenCounter, 3, 1.25)
    .slice(0, 300)
    .map((entry) => ({
      token: entry.value,
      weight: entry.weight,
      phishingCount: entry.phishingCount,
      safeCount: entry.safeCount
    }));

  const riskyHosts = toWeightedEntries(hostCounter, 2, 1.4)
    .slice(0, 200)
    .map((entry) => ({
      hostname: entry.value,
      weight: entry.weight,
      phishingCount: entry.phishingCount,
      safeCount: entry.safeCount
    }));

  const profile = {
    generatedAt: new Date().toISOString(),
    version: "v1",
    sampleStats: {
      phishing: phishingCount,
      safe: safeCount
    },
    tokenWeights,
    riskyHosts
  };

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(OUTPUT_PATH, JSON.stringify(profile, null, 2));

  console.log(
    JSON.stringify(
      {
        ok: true,
        outputPath: OUTPUT_PATH,
        tokenWeights: tokenWeights.length,
        riskyHosts: riskyHosts.length,
        sampleStats: profile.sampleStats
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
