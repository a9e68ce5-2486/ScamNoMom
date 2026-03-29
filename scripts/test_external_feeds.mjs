import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const EXTERNAL_DIR = path.join(ROOT, "data/raw/external");
const OUTPUT_DIR = path.join(ROOT, "data/processed");
const JSON_REPORT_PATH = path.join(OUTPUT_DIR, "external-feeds-test-report.json");
const MD_REPORT_PATH = path.join(OUTPUT_DIR, "external-feeds-test-report.md");

const SAMPLE_LIMIT = Number(process.env.EXTERNAL_FEED_TEST_SAMPLE_LIMIT || 120);
const TIMEOUT_MS = Number(process.env.EXTERNAL_FEED_TEST_TIMEOUT_MS || 12000);

const SUSPICIOUS_TLDS = new Set(["zip", "click", "top", "gq", "work", "country", "xyz", "icu", "shop", "live"]);
const SHORTENER_HOSTS = new Set(["bit.ly", "tinyurl.com", "t.co", "rb.gy", "reurl.cc", "ppt.cc", "lihi.cc"]);

function safeDivide(numerator, denominator) {
  return denominator ? numerator / denominator : 0;
}

function round(value) {
  return Number(value.toFixed(4));
}

function normalizeUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return "";
  }

  if (!/^https?:\/\//i.test(raw) && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(raw)) {
    return `https://${raw}`;
  }

  try {
    return new URL(raw).toString();
  } catch {
    return "";
  }
}

function getHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
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

async function listFeedFiles() {
  try {
    const names = await readdir(EXTERNAL_DIR);
    return names.filter((name) => !name.startsWith(".")).map((name) => path.join(EXTERNAL_DIR, name));
  } catch (error) {
    if ((error && typeof error === "object" && "code" in error && error.code === "ENOENT")) {
      return [];
    }
    throw error;
  }
}

function extractUrlsFromJsonArray(records) {
  const urls = [];
  for (const record of records) {
    if (typeof record === "string") {
      urls.push(record);
      continue;
    }
    urls.push(record?.url || record?.phish_url || record?.phishURL || "");
  }
  return urls.filter(Boolean);
}

async function loadFeedUrls() {
  const files = await listFeedFiles();
  const entries = [];

  for (const filePath of files) {
    const baseName = path.basename(filePath).toLowerCase();
    const source = baseName.includes("phishtank")
      ? "phishtank"
      : baseName.includes("openphish")
        ? "openphish"
        : baseName.includes("urlhaus")
          ? "urlhaus"
          : baseName.includes("phishing_army") || baseName.includes("phishing-army")
            ? "phishing_army"
            : "other";
    const raw = await readFile(filePath, "utf8");
    let urls = [];

    if (baseName.endsWith(".txt")) {
      urls = raw
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"));
    } else if (baseName.endsWith(".json")) {
      const parsed = JSON.parse(raw);
      urls = Array.isArray(parsed) ? extractUrlsFromJsonArray(parsed) : [];
    } else if (baseName.endsWith(".csv")) {
      const rows = csvToObjects(raw);
      urls = extractUrlsFromJsonArray(rows);
    } else {
      continue;
    }

    for (const url of urls) {
      const normalized = normalizeUrl(url);
      if (!normalized) {
        continue;
      }
      entries.push({
        source,
        file: path.basename(filePath),
        url: normalized
      });
    }
  }

  const dedup = new Map();
  for (const entry of entries) {
    if (!dedup.has(entry.url)) {
      dedup.set(entry.url, entry);
    }
  }
  return [...dedup.values()];
}

function buildFeaturesFromUrl(url) {
  const parsed = new URL(url);
  const hostname = parsed.hostname.toLowerCase();
  const tld = hostname.split(".").pop() || "";
  const pathname = parsed.pathname.toLowerCase();
  const isShortener = SHORTENER_HOSTS.has(hostname);
  const suspiciousTldCount = SUSPICIOUS_TLDS.has(tld) ? 1 : 0;
  const keywordHints = ["login", "verify", "account", "secure", "payment", "invoice", "refund", "otp"]
    .filter((token) => pathname.includes(token))
    .join(" ");
  const visibleText = keywordHints
    ? `External feed URL test sample with suspicious path hints: ${keywordHints}`
    : "External feed URL test sample";

  return {
    url,
    hostname,
    source: "web",
    title: parsed.pathname.slice(0, 120) || hostname,
    visibleText,
    forms: {
      total: 0,
      passwordFields: pathname.includes("login") || pathname.includes("verify") ? 1 : 0,
      externalSubmitCount: 0
    },
    links: {
      total: 1,
      mismatchedTextCount: 0,
      suspiciousTldCount,
      hostnames: [hostname, ...(isShortener ? [hostname] : [])],
      urls: [url]
    },
    dom: {
      hiddenElementCount: 0,
      iframeCount: 0
    },
    brandSignals: []
  };
}

async function analyzeWithTimeout(analyzeFeatures, features) {
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`analysis timeout after ${TIMEOUT_MS}ms`)), TIMEOUT_MS);
  });
  return Promise.race([analyzeFeatures(features), timeoutPromise]);
}

function computeSummary(records, totalInput, skipped) {
  const analyzed = records.length;
  const highOrBlocked = records.filter(
    (record) => record.result && (record.result.riskLevel === "high" || record.result.recommendedAction === "block")
  ).length;
  const warnOrAbove = records.filter(
    (record) =>
      record.result &&
      (record.result.recommendedAction === "warn" ||
        record.result.recommendedAction === "block" ||
        record.result.recommendedAction === "escalate")
  ).length;
  const failed = records.filter((record) => record.error).length;
  return {
    totalInput,
    skippedByLimit: skipped,
    analyzed,
    failed,
    highOrBlockedRate: round(safeDivide(highOrBlocked, analyzed)),
    warnOrAboveRate: round(safeDivide(warnOrAbove, analyzed))
  };
}

function aggregateBy(records, selector) {
  const groups = new Map();
  for (const record of records) {
    if (!record.result) {
      continue;
    }
    const key = selector(record);
    groups.set(key, (groups.get(key) || 0) + 1);
  }
  return Object.fromEntries([...groups.entries()].sort((a, b) => b[1] - a[1]));
}

function buildMarkdownReport(report) {
  return `# External Feeds Model Test Report

Generated at: ${report.generatedAt}

## Summary

\`\`\`json
${JSON.stringify(report.summary, null, 2)}
\`\`\`

## Distribution

### By Action
\`\`\`json
${JSON.stringify(report.distribution.byAction, null, 2)}
\`\`\`

### By Risk Level
\`\`\`json
${JSON.stringify(report.distribution.byRiskLevel, null, 2)}
\`\`\`

### By Provider
\`\`\`json
${JSON.stringify(report.distribution.byProvider, null, 2)}
\`\`\`

### By Source Feed
\`\`\`json
${JSON.stringify(report.distribution.byFeedSource, null, 2)}
\`\`\`

## Sample Results (first 30)

\`\`\`json
${JSON.stringify(report.samples, null, 2)}
\`\`\`
`;
}

async function main() {
  const [{ analyzeFeatures }, feedEntries] = await Promise.all([
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/pipeline/analyze.js")).href),
    loadFeedUrls()
  ]);

  if (feedEntries.length === 0) {
    throw new Error("No external feed files found. Run `node scripts/fetch_feeds.mjs` first.");
  }

  const sampled = feedEntries.slice(0, SAMPLE_LIMIT);
  const skippedByLimit = Math.max(0, feedEntries.length - sampled.length);
  const records = [];

  for (const entry of sampled) {
    const features = buildFeaturesFromUrl(entry.url);
    try {
      const result = await analyzeWithTimeout(analyzeFeatures, features);
      records.push({
        ...entry,
        result: {
          score: result.score,
          riskLevel: result.riskLevel,
          recommendedAction: result.recommendedAction,
          provider: result.provider,
          needsAgent: result.needsAgent,
          attackType: result.attackType
        }
      });
    } catch (error) {
      records.push({
        ...entry,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  const summary = computeSummary(records, feedEntries.length, skippedByLimit);
  const distribution = {
    byAction: aggregateBy(records, (record) => record.result.recommendedAction),
    byRiskLevel: aggregateBy(records, (record) => record.result.riskLevel),
    byProvider: aggregateBy(records, (record) => record.result.provider),
    byFeedSource: aggregateBy(records, (record) => record.source)
  };

  const report = {
    generatedAt: new Date().toISOString(),
    config: {
      sampleLimit: SAMPLE_LIMIT,
      timeoutMs: TIMEOUT_MS
    },
    summary,
    distribution,
    samples: records.slice(0, 30)
  };

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(JSON_REPORT_PATH, JSON.stringify(report, null, 2));
  await writeFile(MD_REPORT_PATH, buildMarkdownReport(report));

  console.log(
    JSON.stringify(
      {
        ok: true,
        totalFeedUrls: feedEntries.length,
        analyzed: summary.analyzed,
        failed: summary.failed,
        jsonReport: JSON_REPORT_PATH,
        markdownReport: MD_REPORT_PATH
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
