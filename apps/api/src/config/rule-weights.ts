import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "../../../..");
const RULE_WEIGHTS_FILE = path.join(REPO_ROOT, "data", "rule_weights.json");

export const DEFAULT_RULE_WEIGHTS = {
  passwordFields: 20,
  externalSubmit: 25,
  mismatchedText: 15,
  suspiciousLinkTldBase: 10,
  suspiciousLinkTldPerLink: 4,
  urlIpHostname: 26,
  urlAtSymbol: 10,
  urlExcessiveSubdomains: 10,
  urlEncodedChars: 8,
  urlLongLength: 6,
  urlShortener: 8,
  urlUncommonPort: 8,
  urlKeywordBase: 12,
  urlKeywordPerToken: 4,
  urlBrandImpersonation: 34,
  hiddenElements: 10,
  iframeHeavy: 8,
  suspiciousHostnameTld: 12,
  brandOnCredentialPage: 12,
  mismatchedBrand: 22,
  mismatchedBrandLinks: 18,
  taiwanBrandActionPattern: 12,
  traditionalScamLanguage: 14,
  emailContext: 8,
  emailManyLinks: 10,
  emailLinkMismatch: 10,
  emailHighTrustSenderStyle: 6,
  emailUrgencyLanguage: 15,
  emailTraditionalScamLanguage: 16,
  emailSenderReplyToMismatch: 18,
  emailBrandDomainMismatch: 16,
  emailFreemailBrandClaim: 12
} as const;

export type RuleWeightKey = keyof typeof DEFAULT_RULE_WEIGHTS;
export type RuleWeights = Record<RuleWeightKey, number>;

let cachedWeights: RuleWeights | null = null;

function normalizeWeights(input: unknown): RuleWeights {
  const result: RuleWeights = { ...DEFAULT_RULE_WEIGHTS };

  if (!input || typeof input !== "object") {
    return result;
  }

  const candidate = input as Partial<Record<RuleWeightKey, number>>;

  for (const key of Object.keys(DEFAULT_RULE_WEIGHTS) as RuleWeightKey[]) {
    const value = candidate[key];
    if (typeof value === "number" && Number.isFinite(value)) {
      result[key] = Math.max(0, Math.min(40, Math.round(value)));
    }
  }

  return result;
}

export function getRuleWeights(): RuleWeights {
  if (cachedWeights) {
    return cachedWeights;
  }

  if (!existsSync(RULE_WEIGHTS_FILE)) {
    cachedWeights = { ...DEFAULT_RULE_WEIGHTS };
    return cachedWeights;
  }

  try {
    const parsed = JSON.parse(readFileSync(RULE_WEIGHTS_FILE, "utf8"));
    cachedWeights = normalizeWeights(parsed);
    return cachedWeights;
  } catch {
    cachedWeights = { ...DEFAULT_RULE_WEIGHTS };
    return cachedWeights;
  }
}
