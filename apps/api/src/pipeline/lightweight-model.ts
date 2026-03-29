import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { LightweightModelFeatureWeights, LightweightModelProfile, LightweightModelVector } from "../types/lightweight-model.js";
import type { PageFeatures } from "../types/analysis.js";

export interface LightweightModelResult {
  score: number;
  confidence: number;
  probability: number;
  reasons: string[];
  features: Array<{ key: string; value: number; weight: number; contribution: number }>;
  version: string;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "../../../..");
const PROFILE_PATH = path.join(REPO_ROOT, "data", "processed", "lightweight-model-profile.json");

const DEFAULT_FEATURE_WEIGHTS: LightweightModelFeatureWeights = {
  bias: -2.1,
  hasPasswordField: 1.05,
  externalSubmitCount: 0.58,
  mismatchedTextCount: 0.43,
  suspiciousTldCount: 0.41,
  hiddenElementCount: 0.08,
  iframeCount: 0.13,
  brandSignalCount: 0.22,
  urlLengthNorm: 0.7,
  dotCountNorm: 0.55,
  hyphenCountNorm: 0.5,
  digitCountNorm: 0.42,
  hasIpHost: 1.2,
  hasAtSymbol: 0.4,
  hasPunycode: 0.58,
  hasHexEncoding: 0.5,
  hasSuspiciousPathKeyword: 0.66,
  hasSuspiciousQueryKeyword: 0.64,
  hasLongHostname: 0.36,
  hasManySubdomains: 0.46,
  isShortenerHost: 0.37,
  liveDomEnriched: 0.18,
  liveDomFetchError: -0.12,
  highRiskPathHint: 0.58,
  lowTextDensity: 0.46,
  emailContext: 0.12
};

const PROFILE_CACHE = {
  loadedAt: 0,
  profile: null as LightweightModelProfile | null
};

function sigmoid(value: number): number {
  return 1 / (1 + Math.exp(-value));
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function loadProfile(): LightweightModelProfile {
  const now = Date.now();
  if (PROFILE_CACHE.profile && now - PROFILE_CACHE.loadedAt < 5 * 60_000) {
    return PROFILE_CACHE.profile;
  }

  if (!existsSync(PROFILE_PATH)) {
    const fallback: LightweightModelProfile = {
      version: "fallback-v1",
      generatedAt: new Date(0).toISOString(),
      samples: { total: 0, phishing: 0, safe: 0 },
      priors: { phishing: 0.5 },
      featureWeights: DEFAULT_FEATURE_WEIGHTS,
      intercept: DEFAULT_FEATURE_WEIGHTS.bias
    };
    PROFILE_CACHE.loadedAt = now;
    PROFILE_CACHE.profile = fallback;
    return fallback;
  }

  try {
    const raw = JSON.parse(readFileSync(PROFILE_PATH, "utf8")) as Partial<LightweightModelProfile>;
    const profile: LightweightModelProfile = {
      version: String(raw.version || "v1"),
      generatedAt: String(raw.generatedAt || new Date(0).toISOString()),
      samples: {
        total: Number(raw.samples?.total || 0),
        phishing: Number(raw.samples?.phishing || 0),
        safe: Number(raw.samples?.safe || 0)
      },
      priors: {
        phishing: clamp(Number(raw.priors?.phishing || 0.5), 0.01, 0.99)
      },
      featureWeights: {
        ...DEFAULT_FEATURE_WEIGHTS,
        ...(raw.featureWeights || {})
      } as LightweightModelFeatureWeights,
      intercept: Number(raw.intercept ?? raw.featureWeights?.bias ?? DEFAULT_FEATURE_WEIGHTS.bias)
    };
    PROFILE_CACHE.loadedAt = now;
    PROFILE_CACHE.profile = profile;
    return profile;
  } catch {
    const fallback: LightweightModelProfile = {
      version: "fallback-v1",
      generatedAt: new Date(0).toISOString(),
      samples: { total: 0, phishing: 0, safe: 0 },
      priors: { phishing: 0.5 },
      featureWeights: DEFAULT_FEATURE_WEIGHTS,
      intercept: DEFAULT_FEATURE_WEIGHTS.bias
    };
    PROFILE_CACHE.loadedAt = now;
    PROFILE_CACHE.profile = fallback;
    return fallback;
  }
}

function featureVector(features: PageFeatures): LightweightModelVector {
  const urlSignals = features.urlSignals || {};
  const visibleTextLength = String(features.visibleText || "").trim().length;
  const pathname = (() => {
    try {
      return new URL(features.url).pathname.toLowerCase();
    } catch {
      return "";
    }
  })();

  const vector: LightweightModelVector = {
    hasPasswordField: features.forms.passwordFields > 0 ? 1 : 0,
    externalSubmitCount: clamp(features.forms.externalSubmitCount, 0, 8),
    mismatchedTextCount: clamp(features.links.mismatchedTextCount, 0, 12),
    suspiciousTldCount: clamp(features.links.suspiciousTldCount, 0, 12),
    hiddenElementCount: clamp(features.dom.hiddenElementCount, 0, 30),
    iframeCount: clamp(features.dom.iframeCount, 0, 12),
    brandSignalCount: clamp(features.brandSignals.length, 0, 12),
    urlLengthNorm: clamp((urlSignals.length || features.url.length) / 180, 0, 4),
    dotCountNorm: clamp((urlSignals.dotCount ?? features.hostname.split(".").length - 1) / 5, 0, 4),
    hyphenCountNorm: clamp((urlSignals.hyphenCount ?? 0) / 4, 0, 4),
    digitCountNorm: clamp((urlSignals.digitCount ?? 0) / 6, 0, 4),
    hasIpHost: urlSignals.hasIpHost ? 1 : 0,
    hasAtSymbol: urlSignals.hasAtSymbol ? 1 : 0,
    hasPunycode: urlSignals.hasPunycode ? 1 : 0,
    hasHexEncoding: urlSignals.hasHexEncoding ? 1 : 0,
    hasSuspiciousPathKeyword: urlSignals.hasSuspiciousPathKeyword ? 1 : 0,
    hasSuspiciousQueryKeyword: urlSignals.hasSuspiciousQueryKeyword ? 1 : 0,
    hasLongHostname: urlSignals.hasLongHostname ? 1 : 0,
    hasManySubdomains: urlSignals.hasManySubdomains ? 1 : 0,
    isShortenerHost: urlSignals.isShortenerHost ? 1 : 0,
    liveDomEnriched: features.enrichment?.liveDomUsed ? 1 : 0,
    liveDomFetchError: features.enrichment?.skippedReason ? 1 : 0,
    highRiskPathHint: /(login|verify|signin|account|secure|billing|payment|invoice|refund|otp)/i.test(pathname) ? 1 : 0,
    lowTextDensity: visibleTextLength > 0 && visibleTextLength < 140 ? 1 : 0,
    emailContext: features.source === "email" ? 1 : 0
  };

  return vector;
}

export function runLightweightModel(features: PageFeatures): LightweightModelResult {
  const profile = loadProfile();
  const vector = featureVector(features);
  const contributions: Array<{ key: string; value: number; weight: number; contribution: number }> = [];

  let logit = profile.intercept;
  for (const [key, value] of Object.entries(vector)) {
    const weight = Number(profile.featureWeights[key as keyof LightweightModelFeatureWeights] || 0);
    const contribution = value * weight;
    if (contribution !== 0) {
      contributions.push({ key, value, weight, contribution: Number(contribution.toFixed(4)) });
    }
    logit += contribution;
  }

  const probability = clamp(sigmoid(logit), 0.001, 0.999);
  const score = Math.round(probability * 100);
  const confidence = clamp(0.5 + Math.abs(probability - 0.5) * 0.9, 0.5, 0.95);
  const reasons = contributions
    .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
    .slice(0, 5)
    .map((item) => `${item.key}=${item.value} (w=${item.weight.toFixed(2)})`);

  return {
    score,
    confidence: Number(confidence.toFixed(3)),
    probability: Number(probability.toFixed(4)),
    reasons,
    features: contributions.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution)).slice(0, 12),
    version: profile.version
  };
}
