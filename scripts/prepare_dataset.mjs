import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const FEEDBACK_PATH = path.join(ROOT, "apps/api/data/feedback.json");
const FEEDBACK_EVENTS_PATH = path.join(ROOT, "apps/api/data/feedback-events.json");
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
      mlScore: analysis.evidence?.mlScore ?? 0,
      urlRiskScore: analysis.evidence?.urlRiskScore ?? 0,
      riskScore: analysis.score ?? 0,
      hasPasswordField: Number(features?.forms?.passwordFields || 0) > 0 ? 1 : 0,
      externalSubmitCount: Number(features?.forms?.externalSubmitCount || 0),
      mismatchedTextCount: Number(features?.links?.mismatchedTextCount || 0),
      suspiciousTldCount: Number(features?.links?.suspiciousTldCount || 0),
      hiddenElementCount: Number(features?.dom?.hiddenElementCount || 0),
      iframeCount: Number(features?.dom?.iframeCount || 0),
      urlLength: Number(features?.urlSignals?.length || features?.url?.length || 0),
      hasIpHost: Boolean(features?.urlSignals?.hasIpHost) ? 1 : 0,
      hasAtSymbol: Boolean(features?.urlSignals?.hasAtSymbol) ? 1 : 0,
      hasPunycode: Boolean(features?.urlSignals?.hasPunycode) ? 1 : 0,
      hasHexEncoding: Boolean(features?.urlSignals?.hasHexEncoding) ? 1 : 0,
      hasSuspiciousPathKeyword: Boolean(features?.urlSignals?.hasSuspiciousPathKeyword) ? 1 : 0,
      hasSuspiciousQueryKeyword: Boolean(features?.urlSignals?.hasSuspiciousQueryKeyword) ? 1 : 0,
      hasLongHostname: Boolean(features?.urlSignals?.hasLongHostname) ? 1 : 0,
      hasManySubdomains: Boolean(features?.urlSignals?.hasManySubdomains) ? 1 : 0,
      attackType: analysis.attackType ?? "unknown",
      brandSignals: Array.isArray(features.brandSignals) ? features.brandSignals : [],
      emailProvider: features.email?.provider ?? "",
      liveDomUsed: Boolean(features.liveDom?.enriched),
      liveDomEnriched: Boolean(features.liveDom?.enriched) ? 1 : 0,
      liveDomFetchError: features.liveDom?.fetchError ? 1 : 0
    },
    provenance: {
      sourceName: "extension_feedback",
      collectedAt: record.createdAt ?? new Date().toISOString(),
      feedbackId: record.id
    }
  };
}

function toHardNegativeSample(event) {
  const normalizedUrl = normalizeUrl(event?.url || "");
  const hostname = normalizeHostname(event?.hostname || hostnameFromUrl(normalizedUrl));
  if (!hostname) {
    return null;
  }

  const sourceName = event?.eventType === "ignore_once" ? "extension_ignore_once" : "extension_trust_host";
  const idSuffix = String(event?.id || `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);

  return {
    id: `hard_negative_${idSuffix}`,
    sourceType: "web",
    label: "safe",
    content: {
      url: normalizedUrl || `https://${hostname}`,
      hostname,
      title: "",
      visibleText: "",
      subject: "",
      sender: "",
      bodyText: ""
    },
    signals: {
      ruleScore: 0,
      llmScore: 0,
      mlScore: 0,
      urlRiskScore: 0,
      riskScore: 0,
      hasPasswordField: 0,
      externalSubmitCount: 0,
      mismatchedTextCount: 0,
      suspiciousTldCount: 0,
      hiddenElementCount: 0,
      iframeCount: 0,
      urlLength: normalizedUrl.length || hostname.length,
      hasIpHost: 0,
      hasAtSymbol: normalizedUrl.includes("@") ? 1 : 0,
      hasPunycode: hostname.includes("xn--") ? 1 : 0,
      hasHexEncoding: /%[0-9a-f]{2}/i.test(normalizedUrl) ? 1 : 0,
      hasSuspiciousPathKeyword: /login|verify|signin|account|secure|auth|password|billing|invoice|refund|otp/i.test(normalizedUrl) ? 1 : 0,
      hasSuspiciousQueryKeyword: /token|session|redirect|verify|login|password|auth/i.test(normalizedUrl) ? 1 : 0,
      hasLongHostname: hostname.length >= 35 ? 1 : 0,
      hasManySubdomains: hostname.split(".").filter(Boolean).length >= 4 ? 1 : 0,
      attackType: "unknown",
      brandSignals: [],
      emailProvider: "",
      liveDomUsed: false,
      liveDomEnriched: 0,
      liveDomFetchError: 0
    },
    provenance: {
      sourceName,
      collectedAt: event?.createdAt || new Date().toISOString(),
      feedbackId: String(event?.id || "")
    }
  };
}

function normalizeUrl(value) {
  const url = String(value || "").trim();
  if (!url) {
    return "";
  }

  if (!/^https?:\/\//i.test(url) && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(url)) {
    return `https://${url}`;
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
      mlScore: 0,
      urlRiskScore: 0,
      riskScore: 100,
      hasPasswordField: 0,
      externalSubmitCount: 0,
      mismatchedTextCount: 0,
      suspiciousTldCount: 0,
      hiddenElementCount: 0,
      iframeCount: 0,
      urlLength: url.length,
      hasIpHost: /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostnameFromUrl(url)) ? 1 : 0,
      hasAtSymbol: url.includes("@") ? 1 : 0,
      hasPunycode: hostnameFromUrl(url).includes("xn--") ? 1 : 0,
      hasHexEncoding: /%[0-9a-f]{2}/i.test(url) ? 1 : 0,
      hasSuspiciousPathKeyword: /login|verify|signin|account|secure|auth|password|billing|invoice|refund|otp/i.test(url) ? 1 : 0,
      hasSuspiciousQueryKeyword: /token|session|redirect|verify|login|password|auth/i.test(url) ? 1 : 0,
      hasLongHostname: hostnameFromUrl(url).length >= 35 ? 1 : 0,
      hasManySubdomains: hostnameFromUrl(url).split(".").filter(Boolean).length >= 4 ? 1 : 0,
      attackType: "unknown",
      brandSignals: [],
      emailProvider: "",
      liveDomUsed: false,
      liveDomEnriched: 0,
      liveDomFetchError: 0
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
      mlScore: 0,
      urlRiskScore: 0,
      riskScore: 100,
      hasPasswordField: 0,
      externalSubmitCount: 0,
      mismatchedTextCount: 0,
      suspiciousTldCount: 0,
      hiddenElementCount: 0,
      iframeCount: 0,
      urlLength: normalized.length,
      hasIpHost: /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostnameFromUrl(normalized)) ? 1 : 0,
      hasAtSymbol: normalized.includes("@") ? 1 : 0,
      hasPunycode: hostnameFromUrl(normalized).includes("xn--") ? 1 : 0,
      hasHexEncoding: /%[0-9a-f]{2}/i.test(normalized) ? 1 : 0,
      hasSuspiciousPathKeyword: /login|verify|signin|account|secure|auth|password|billing|invoice|refund|otp/i.test(normalized) ? 1 : 0,
      hasSuspiciousQueryKeyword: /token|session|redirect|verify|login|password|auth/i.test(normalized) ? 1 : 0,
      hasLongHostname: hostnameFromUrl(normalized).length >= 35 ? 1 : 0,
      hasManySubdomains: hostnameFromUrl(normalized).split(".").filter(Boolean).length >= 4 ? 1 : 0,
      attackType: "unknown",
      brandSignals: [],
      emailProvider: "",
      liveDomUsed: false,
      liveDomEnriched: 0,
      liveDomFetchError: 0
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

function normalizeHostname(value) {
  return String(value || "").trim().toLowerCase();
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

async function loadUrlHausSamples(files) {
  const targetFiles = files.filter((file) => /urlhaus/i.test(path.basename(file)));
  const samples = [];

  for (const file of targetFiles) {
    const raw = await readFile(file, "utf8");
    const lines = raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));

    for (const [index, line] of lines.entries()) {
      const columns = parseCsvLine(line);
      const urlCandidate = columns[2] || columns[1] || columns[0] || "";
      const sample = openPhishUrlToSample(urlCandidate, index);
      if (sample) {
        samples.push({
          ...sample,
          id: `urlhaus_${index}`,
          provenance: {
            ...sample.provenance,
            sourceName: "urlhaus"
          }
        });
      }
    }
  }

  return samples;
}

async function loadPhishingArmySamples(files) {
  const targetFiles = files.filter((file) => /phishing[_-]?army/i.test(path.basename(file)));
  const samples = [];

  for (const file of targetFiles) {
    const raw = await readFile(file, "utf8");
    const lines = raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));

    for (const [index, line] of lines.entries()) {
      const sample = openPhishUrlToSample(line, index);
      if (sample) {
        samples.push({
          ...sample,
          id: `phishing_army_${index}`,
          provenance: {
            ...sample.provenance,
            sourceName: "phishing_army"
          }
        });
      }
    }
  }

  return samples;
}

async function main() {
  const feedbackRecords = await readJsonArray(FEEDBACK_PATH);
  const feedbackEvents = await readJsonArray(FEEDBACK_EVENTS_PATH);
  const externalFiles = await listExternalFiles();
  const feedbackSamples = feedbackRecords.map(toTrainingSample);
  const hardNegativeSamples = feedbackEvents
    .filter((event) => event?.eventType === "ignore_once" || event?.eventType === "trust_host")
    .map(toHardNegativeSample)
    .filter(Boolean);
  const phishTankSamples = await loadPhishTankSamples(externalFiles);
  const openPhishSamples = await loadOpenPhishSamples(externalFiles);
  const urlHausSamples = await loadUrlHausSamples(externalFiles);
  const phishingArmySamples = await loadPhishingArmySamples(externalFiles);
  const samples = [
    ...feedbackSamples,
    ...hardNegativeSamples,
    ...phishTankSamples,
    ...openPhishSamples,
    ...urlHausSamples,
    ...phishingArmySamples
  ];

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(OUTPUT_PATH, JSON.stringify(samples, null, 2));

  console.log(
    JSON.stringify(
      {
        ok: true,
        inputFeedbackRecords: feedbackRecords.length,
        inputFeedbackEvents: feedbackEvents.length,
        hardNegativeSamples: hardNegativeSamples.length,
        inputPhishTankSamples: phishTankSamples.length,
        inputOpenPhishSamples: openPhishSamples.length,
        inputUrlHausSamples: urlHausSamples.length,
        inputPhishingArmySamples: phishingArmySamples.length,
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
