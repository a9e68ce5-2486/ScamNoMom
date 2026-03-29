import type { AttackType, PageFeatures } from "../types/analysis.js";

export interface UrlRiskResult {
  score: number;
  confidence: number;
  reasons: string[];
  suggestedAttackType: AttackType | null;
}

const SUSPICIOUS_TLDS = new Set([
  "zip",
  "click",
  "top",
  "gq",
  "work",
  "country",
  "xyz",
  "icu",
  "shop",
  "live",
  "rest",
  "cfd",
  "sbs",
  "monster"
]);

const SHORTENER_HOSTS = new Set(["bit.ly", "tinyurl.com", "t.co", "rb.gy", "reurl.cc", "ppt.cc", "lihi.cc", "cutt.ly", "s.id"]);

const KEYWORD_WEIGHTS: Array<{ token: string; score: number; attack: AttackType }> = [
  { token: "login", score: 6, attack: "credential_harvest" },
  { token: "signin", score: 6, attack: "credential_harvest" },
  { token: "verify", score: 6, attack: "credential_harvest" },
  { token: "password", score: 8, attack: "credential_harvest" },
  { token: "account", score: 4, attack: "credential_harvest" },
  { token: "secure", score: 4, attack: "credential_harvest" },
  { token: "update", score: 4, attack: "credential_harvest" },
  { token: "billing", score: 5, attack: "payment_fraud" },
  { token: "invoice", score: 5, attack: "payment_fraud" },
  { token: "refund", score: 5, attack: "payment_fraud" },
  { token: "wallet", score: 5, attack: "payment_fraud" },
  { token: "bank", score: 5, attack: "payment_fraud" },
  { token: "otp", score: 6, attack: "phone_scam" },
  { token: "session", score: 4, attack: "credential_harvest" },
  { token: "token", score: 4, attack: "credential_harvest" },
  { token: "redirect", score: 3, attack: "credential_harvest" }
];

const BRAND_DOMAIN_RULES: Array<{ token: string; domains: string[] }> = [
  { token: "apple", domains: ["apple.com", "icloud.com"] },
  { token: "icloud", domains: ["icloud.com", "apple.com"] },
  { token: "microsoft", domains: ["microsoft.com", "live.com", "office.com"] },
  { token: "office", domains: ["office.com", "microsoft.com"] },
  { token: "paypal", domains: ["paypal.com"] },
  { token: "amazon", domains: ["amazon.com"] },
  { token: "netflix", domains: ["netflix.com"] },
  { token: "steam", domains: ["steampowered.com", "steamcommunity.com"] },
  { token: "roblox", domains: ["roblox.com"] },
  { token: "line", domains: ["line.me", "linebiz.com", "linebank.com.tw"] },
  { token: "shopee", domains: ["shopee.tw", "shopeemobile.com"] },
  { token: "momo", domains: ["momoshop.com.tw"] },
  { token: "pchome", domains: ["pchome.com.tw"] },
  { token: "ctbc", domains: ["ctbcbank.com", "ctbcbank.com.tw"] },
  { token: "cathay", domains: ["cathaybk.com.tw", "cathaylife.com.tw"] },
  { token: "esun", domains: ["esunbank.com", "esunbank.com.tw"] },
  { token: "taishin", domains: ["taishinbank.com.tw"] },
  { token: "fubon", domains: ["fubon.com", "fubon.com.tw", "taipeifubon.com.tw"] }
];

function normalizeHostname(hostname: string): string {
  return String(hostname || "").trim().toLowerCase();
}

function domainMatches(hostname: string, domain: string): boolean {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

function isIpv4Hostname(hostname: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
}

function countOf(text: string, pattern: RegExp): number {
  return (String(text || "").match(pattern) || []).length;
}

function shannonEntropy(text: string): number {
  const source = String(text || "");
  if (!source) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const char of source) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / source.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function extractKeywordScore(blob: string): { score: number; attackVotes: AttackType[]; matched: string[] } {
  let score = 0;
  const attackVotes: AttackType[] = [];
  const matched: string[] = [];
  const lower = blob.toLowerCase();
  for (const item of KEYWORD_WEIGHTS) {
    if (!lower.includes(item.token)) {
      continue;
    }
    score += item.score;
    attackVotes.push(item.attack);
    matched.push(item.token);
  }
  return { score, attackVotes, matched };
}

function pickSuggestedAttack(votes: AttackType[]): AttackType | null {
  if (votes.length === 0) {
    return null;
  }
  const bucket = new Map<AttackType, number>();
  for (const vote of votes) {
    bucket.set(vote, (bucket.get(vote) || 0) + 1);
  }
  return [...bucket.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || null;
}

export function analyzeUrlRisk(features: PageFeatures): UrlRiskResult {
  const hostname = normalizeHostname(features.hostname);
  const parsedUrl = (() => {
    try {
      return new URL(features.url);
    } catch {
      return null;
    }
  })();
  const path = (parsedUrl?.pathname || "").toLowerCase();
  const query = (parsedUrl?.search || "").toLowerCase();
  const fullUrl = String(features.url || "").toLowerCase();
  const labels = hostname.split(".").filter(Boolean);
  const tld = labels[labels.length - 1] || "";

  let score = 0;
  const reasons: string[] = [];
  const attackVotes: AttackType[] = [];

  const signalIpHost = features.urlSignals?.hasIpHost ?? isIpv4Hostname(hostname);
  const signalAtSymbol = features.urlSignals?.hasAtSymbol ?? fullUrl.includes("@");
  const signalPunycode = features.urlSignals?.hasPunycode ?? hostname.includes("xn--");
  const signalLongHost = features.urlSignals?.hasLongHostname ?? hostname.length >= 35;
  const signalManySubdomains = features.urlSignals?.hasManySubdomains ?? labels.length >= 4;
  const signalShortener = features.urlSignals?.isShortenerHost ?? SHORTENER_HOSTS.has(hostname);
  const signalHexEncoding = features.urlSignals?.hasHexEncoding ?? /%[0-9a-f]{2}/i.test(fullUrl);

  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 14;
    reasons.push("Hostname uses a high-risk top-level domain.");
    attackVotes.push("credential_harvest");
  }

  if (signalIpHost) {
    score += 26;
    reasons.push("Hostname is a raw IPv4 address.");
    attackVotes.push("credential_harvest");
  }

  if (signalAtSymbol) {
    score += 10;
    reasons.push("URL contains '@', a common obfuscation pattern.");
  }

  if (signalPunycode) {
    score += 12;
    reasons.push("Hostname contains punycode, possible homograph risk.");
    attackVotes.push("brand_impersonation");
  }

  if (signalLongHost) {
    score += 8;
    reasons.push("Hostname is unusually long.");
  }

  if (signalManySubdomains) {
    score += 10;
    reasons.push("Hostname has many subdomains.");
  }

  if (signalShortener) {
    score += 10;
    reasons.push("URL uses a shortener host.");
  }

  if (signalHexEncoding) {
    score += 8;
    reasons.push("URL uses encoded characters.");
  }

  if (parsedUrl?.protocol === "http:") {
    score += 8;
    reasons.push("URL uses HTTP instead of HTTPS.");
  }

  const keywordBlob = `${hostname} ${path} ${query}`;
  const keywordResult = extractKeywordScore(keywordBlob);
  if (keywordResult.score > 0) {
    score += Math.min(28, keywordResult.score);
    reasons.push(`URL contains phishing bait keywords: ${keywordResult.matched.slice(0, 4).join(", ")}.`);
    attackVotes.push(...keywordResult.attackVotes);
  }

  const hyphenCount = features.urlSignals?.hyphenCount ?? countOf(hostname, /-/g);
  if (hyphenCount >= 3) {
    score += 8;
    reasons.push("Hostname has many hyphens.");
  }

  const digitCount = features.urlSignals?.digitCount ?? countOf(hostname, /\d/g);
  if (digitCount >= 5) {
    score += 8;
    reasons.push("Hostname has many digits.");
  }

  const entropy = shannonEntropy(hostname.replace(/\./g, ""));
  if (entropy >= 3.9 && hostname.length >= 14) {
    score += 8;
    reasons.push("Hostname appears algorithmically random.");
  }

  for (const rule of BRAND_DOMAIN_RULES) {
    if (!hostname.includes(rule.token)) {
      continue;
    }
    const official = rule.domains.some((domain) => domainMatches(hostname, domain));
    if (!official) {
      score += 26;
      reasons.push(`Hostname includes brand token '${rule.token}' outside official domains.`);
      attackVotes.push("brand_impersonation");
    }
  }

  const finalScore = clampScore(score);
  const confidence = Math.max(0.45, Math.min(0.97, Number((0.44 + finalScore / 115).toFixed(3))));

  return {
    score: finalScore,
    confidence,
    reasons: [...new Set(reasons)].slice(0, 8),
    suggestedAttackType: pickSuggestedAttack(attackVotes)
  };
}
