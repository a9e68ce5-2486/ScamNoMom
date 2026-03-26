import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const FEEDBACK_PATH = path.join(ROOT, "apps/api/data/feedback.json");
const EXTERNAL_DIR = path.join(ROOT, "data/raw/external");
const OUTPUT_DIR = path.join(ROOT, "data/processed");
const OUTPUT_PATH = path.join(OUTPUT_DIR, "training-samples.json");

function truncate(value, limit = 4000) {
  const text = String(value || "").trim();
  return text.slice(0, limit);
}

function toTrainingSample(record) {
  const features = record.features ?? {};
  const analysis = record.analysis ?? {};

  return {
    id: record.id,
    sourceType: features.source ?? "web",
    label: record.label,
    content: {
      url: features.url ?? "",
      hostname: features.hostname ?? "",
      title: features.title ?? "",
      visibleText: truncate(features.visibleText ?? "", 4000),
      subject: features.email?.subject ?? "",
      sender: features.email?.sender ?? features.email?.replyTo ?? "",
      bodyText: truncate(features.email?.bodyText ?? "", 4000)
    },
    signals: {
      ruleScore: analysis.evidence?.ruleScore ?? 0,
      llmScore: analysis.evidence?.llmScore ?? 0,
      riskScore: analysis.score ?? 0,
      attackType: analysis.attackType ?? "unknown",
      brandSignals: Array.isArray(features.brandSignals) ? features.brandSignals : [],
      emailProvider: features.email?.provider ?? ""
    },
    provenance: {
      sourceName: "extension_feedback",
      collectedAt: record.createdAt ?? new Date().toISOString(),
      feedbackId: record.id
    }
  };
}

function normalizeUrl(value) {
  const url = String(value || "").trim();
  if (!url) {
    return "";
  }

  try {
    return new URL(url).toString();
  } catch {
    return "";
  }
}

function hostnameFromUrl(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return "";
  }
}

function phishTankRowToSample(row, index) {
  const url = normalizeUrl(row.url || row.phish_url || row.phishURL);
  if (!url) {
    return null;
  }

  return {
    id: `phishtank_${row.phish_id || row.id || index}`,
    sourceType: "url_feed",
    label: "phishing",
    content: {
      url,
      hostname: hostnameFromUrl(url),
      title: "",
      visibleText: "",
      subject: "",
      sender: "",
      bodyText: ""
    },
    signals: {
      ruleScore: 0,
      llmScore: 0,
      riskScore: 100,
      attackType: "unknown",
      brandSignals: [],
      emailProvider: ""
    },
    provenance: {
      sourceName: "phishtank",
      collectedAt: row.verification_time || row.submission_time || new Date().toISOString(),
      feedbackId: String(row.phish_id || row.id || "")
    }
  };
}

function openPhishUrlToSample(url, index) {
  const normalized = normalizeUrl(url);
  if (!normalized) {
    return null;
  }

  return {
    id: `openphish_${index}`,
    sourceType: "url_feed",
    label: "phishing",
    content: {
      url: normalized,
      hostname: hostnameFromUrl(normalized),
      title: "",
      visibleText: "",
      subject: "",
      sender: "",
      bodyText: ""
    },
    signals: {
      ruleScore: 0,
      llmScore: 0,
      riskScore: 100,
      attackType: "unknown",
      brandSignals: [],
      emailProvider: ""
    },
    provenance: {
      sourceName: "openphish",
      collectedAt: new Date().toISOString(),
      feedbackId: ""
    }
  };
}

async function readJsonArray(filePath) {
  try {
    const raw = await readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    if (error.code === "ENOENT") {
      return [];
    }

    throw error;
  }
}

async function listExternalFiles() {
  try {
    const names = await readdir(EXTERNAL_DIR);
    return names.map((name) => path.join(EXTERNAL_DIR, name));
  } catch (error) {
    if (error.code === "ENOENT") {
      return [];
    }

    throw error;
  }
}

function parseCsvLine(line) {
  const result = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    const next = line[i + 1];

    if (char === '"' && inQuotes && next === '"') {
      current += '"';
      i += 1;
      continue;
    }

    if (char === '"') {
      inQuotes = !inQuotes;
      continue;
    }

    if (char === "," && !inQuotes) {
      result.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  result.push(current);
  return result.map((value) => value.trim());
}

function csvToObjects(raw) {
  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length < 2) {
    return [];
  }

  const headers = parseCsvLine(lines[0]);
  return lines.slice(1).map((line) => {
    const values = parseCsvLine(line);
    return Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""]));
  });
}

async function loadPhishTankSamples(files) {
  const targetFiles = files.filter((file) => /phishtank/i.test(path.basename(file)));
  const samples = [];

  for (const file of targetFiles) {
    const raw = await readFile(file, "utf8");
    const rows = file.endsWith(".json") ? JSON.parse(raw) : csvToObjects(raw);

    for (const [index, row] of rows.entries()) {
      const sample = phishTankRowToSample(row, index);
      if (sample) {
        samples.push(sample);
      }
    }
  }

  return samples;
}

async function loadOpenPhishSamples(files) {
  const targetFiles = files.filter((file) => /openphish/i.test(path.basename(file)));
  const samples = [];

  for (const file of targetFiles) {
    const raw = await readFile(file, "utf8");

    if (file.endsWith(".json")) {
      const rows = JSON.parse(raw);
      for (const [index, row] of rows.entries()) {
        const sample = openPhishUrlToSample(row.url || row.phish_url || "", index);
        if (sample) {
          samples.push(sample);
        }
      }
      continue;
    }

    const lines = raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    for (const [index, line] of lines.entries()) {
      const sample = openPhishUrlToSample(line, index);
      if (sample) {
        samples.push(sample);
      }
    }
  }

  return samples;
}

async function main() {
  const feedbackRecords = await readJsonArray(FEEDBACK_PATH);
  const externalFiles = await listExternalFiles();
  const feedbackSamples = feedbackRecords.map(toTrainingSample);
  const phishTankSamples = await loadPhishTankSamples(externalFiles);
  const openPhishSamples = await loadOpenPhishSamples(externalFiles);
  const samples = [...feedbackSamples, ...phishTankSamples, ...openPhishSamples];

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(OUTPUT_PATH, JSON.stringify(samples, null, 2));

  console.log(
    JSON.stringify(
      {
        ok: true,
        inputFeedbackRecords: feedbackRecords.length,
        inputPhishTankSamples: phishTankSamples.length,
        inputOpenPhishSamples: openPhishSamples.length,
        outputSamples: samples.length,
        outputPath: OUTPUT_PATH
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
