import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const TRAINING_SAMPLES_PATH = path.join(ROOT, "data/processed/training-samples.json");
const OUTPUT_DIR = path.join(ROOT, "data/processed");
const OUTPUT_PATH = path.join(OUTPUT_DIR, "lightweight-model-profile.json");

const FEATURE_KEYS = [
  "hasPasswordField",
  "externalSubmitCount",
  "mismatchedTextCount",
  "suspiciousTldCount",
  "hiddenElementCount",
  "iframeCount",
  "brandSignalCount",
  "urlLengthNorm",
  "dotCountNorm",
  "hyphenCountNorm",
  "digitCountNorm",
  "hasIpHost",
  "hasAtSymbol",
  "hasPunycode",
  "hasHexEncoding",
  "hasSuspiciousPathKeyword",
  "hasSuspiciousQueryKeyword",
  "hasLongHostname",
  "hasManySubdomains",
  "isShortenerHost",
  "liveDomEnriched",
  "liveDomFetchError",
  "highRiskPathHint",
  "lowTextDensity",
  "emailContext"
];
const HIGH_RISK_PATH_PATTERN = /(login|verify|signin|account|secure|auth|password|billing|invoice|refund|otp)/i;
const SHORTENER_HOST_PATTERN = /(^|\.)(bit\.ly|tinyurl\.com|t\.co|rb\.gy|reurl\.cc|ppt\.cc|lihi\.cc|cutt\.ly)$/i;

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function round(value, digits = 6) {
  return Number(value.toFixed(digits));
}

function safeString(value) {
  return String(value || "");
}

function isIpHost(hostname) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(safeString(hostname));
}

function extractPathAndQuery(url) {
  try {
    const parsed = new URL(safeString(url));
    return {
      pathname: safeString(parsed.pathname).toLowerCase(),
      search: safeString(parsed.search).toLowerCase(),
      hostname: safeString(parsed.hostname).toLowerCase()
    };
  } catch {
    return {
      pathname: "",
      search: "",
      hostname: ""
    };
  }
}

function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function deriveFeatureVector(sample) {
  const content = sample?.content || {};
  const signals = sample?.signals || {};
  const url = safeString(content.url);
  const extracted = extractPathAndQuery(url);
  const hostname = safeString(content.hostname || extracted.hostname).toLowerCase();
  const visibleText = safeString(content.visibleText);
  const title = safeString(content.title);
  const sourceName = safeString(sample?.sourceType || sample?.provenance?.sourceName || "");

  const dotCount = (hostname.match(/\./g) || []).length;
  const hyphenCount = (hostname.match(/-/g) || []).length;
  const digitCount = (hostname.match(/\d/g) || []).length;
  const hasPathKeyword = /(login|verify|signin|account|secure|auth|password|billing|invoice|refund)/i.test(extracted.pathname);
  const hasQueryKeyword = /(token|session|redirect|verify|login|password|auth)/i.test(extracted.search);
  const hasShortener = SHORTENER_HOST_PATTERN.test(hostname);

  const urlLength = toNumber(signals?.urlLength, url.length || 0);
  const suspiciousTldCount = toNumber(signals?.suspiciousTldCount, 0);
  const brandSignals = Array.isArray(signals?.brandSignals) ? signals.brandSignals : [];
  const isEmail = sourceName === "email" || sourceName.includes("email");

  const vector = {
    hasPasswordField: toNumber(signals.hasPasswordField, 0) > 0 ? 1 : /password|login|signin/i.test(`${title} ${visibleText}`) ? 1 : 0,
    externalSubmitCount: clamp(toNumber(signals.externalSubmitCount, 0), 0, 8),
    mismatchedTextCount: clamp(toNumber(signals.mismatchedTextCount, 0), 0, 12),
    suspiciousTldCount: clamp(Number(suspiciousTldCount), 0, 12),
    hiddenElementCount: clamp(toNumber(signals.hiddenElementCount, 0), 0, 30),
    iframeCount: clamp(toNumber(signals.iframeCount, 0), 0, 12),
    brandSignalCount: clamp(brandSignals.length, 0, 12),
    urlLengthNorm: clamp(urlLength / 180, 0, 4),
    dotCountNorm: clamp(dotCount / 5, 0, 4),
    hyphenCountNorm: clamp(hyphenCount / 4, 0, 4),
    digitCountNorm: clamp(digitCount / 6, 0, 4),
    hasIpHost: toNumber(signals.hasIpHost, 0) > 0 || isIpHost(hostname) ? 1 : 0,
    hasAtSymbol: toNumber(signals.hasAtSymbol, 0) > 0 || url.includes("@") ? 1 : 0,
    hasPunycode: toNumber(signals.hasPunycode, 0) > 0 || hostname.includes("xn--") ? 1 : 0,
    hasHexEncoding: toNumber(signals.hasHexEncoding, 0) > 0 || /%[0-9a-f]{2}/i.test(url) ? 1 : 0,
    hasSuspiciousPathKeyword: toNumber(signals.hasSuspiciousPathKeyword, 0) > 0 || hasPathKeyword ? 1 : 0,
    hasSuspiciousQueryKeyword: toNumber(signals.hasSuspiciousQueryKeyword, 0) > 0 || hasQueryKeyword ? 1 : 0,
    hasLongHostname: toNumber(signals.hasLongHostname, 0) > 0 || hostname.length >= 35 ? 1 : 0,
    hasManySubdomains: toNumber(signals.hasManySubdomains, 0) > 0 || hostname.split(".").filter(Boolean).length >= 4 ? 1 : 0,
    isShortenerHost: hasShortener ? 1 : 0,
    liveDomEnriched: toNumber(signals.liveDomEnriched, 0) > 0 ? 1 : 0,
    liveDomFetchError: toNumber(signals.liveDomFetchError, 0) > 0 ? 1 : 0,
    highRiskPathHint: HIGH_RISK_PATH_PATTERN.test(extracted.pathname) ? 1 : 0,
    lowTextDensity: visibleText.trim().length > 0 && visibleText.trim().length < 140 ? 1 : 0,
    emailContext: isEmail ? 1 : 0
  };

  return vector;
}

async function readTrainingSamples() {
  try {
    const raw = await readFile(TRAINING_SAMPLES_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function trainModel(samples) {
  const trainRows = samples
    .map((sample) => {
      const label = sample?.label === "phishing" ? 1 : sample?.label === "safe" ? 0 : null;
      if (label === null) {
        return null;
      }
      return {
        label,
        features: deriveFeatureVector(sample)
      };
    })
    .filter(Boolean);

  const total = trainRows.length;
  const phishing = trainRows.filter((row) => row.label === 1).length;
  const safe = total - phishing;
  const priors = {
    phishing: total > 0 ? phishing / total : 0.5
  };

  const featureWeights = {};
  for (const key of FEATURE_KEYS) {
    const phishingMean = phishing
      ? trainRows.filter((row) => row.label === 1).reduce((sum, row) => sum + Number(row.features[key] || 0), 0) / phishing
      : 0;
    const safeMean = safe
      ? trainRows.filter((row) => row.label === 0).reduce((sum, row) => sum + Number(row.features[key] || 0), 0) / safe
      : 0;
    const delta = phishingMean - safeMean;
    featureWeights[key] = round(clamp(delta * 1.9, -2.5, 2.5));
  }

  const intercept = round(
    clamp(
      Math.log(clamp(priors.phishing, 0.01, 0.99) / clamp(1 - priors.phishing, 0.01, 0.99)),
      -3,
      3
    )
  );

  featureWeights.bias = intercept;

  return {
    version: "lw-v1",
    generatedAt: new Date().toISOString(),
    samples: {
      total,
      phishing,
      safe
    },
    priors: {
      phishing: round(priors.phishing, 4)
    },
    featureWeights,
    intercept,
    metadata: {
      featureKeys: FEATURE_KEYS
    }
  };
}

async function main() {
  const samples = await readTrainingSamples();
  const profile = trainModel(samples);

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(OUTPUT_PATH, JSON.stringify(profile, null, 2));

  console.log(
    JSON.stringify(
      {
        ok: true,
        outputPath: OUTPUT_PATH,
        samples: profile.samples,
        version: profile.version
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
