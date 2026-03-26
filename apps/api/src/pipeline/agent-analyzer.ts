import { findMismatchedBrandLinks, findMismatchedBrands } from "../config/tw-brand-domains.js";
import { hasKeywordMatch } from "../config/tw-scam-keywords.js";
import { resolveRedirectChain } from "./redirect-resolver.js";
import { extractRuleSignals } from "./rule-signals.js";
import type { AttackType, PageFeatures } from "../types/analysis.js";

interface AgentAnalyzerInput {
  baseScore: number;
  attackType: AttackType;
}

export interface AgentAnalyzerResult {
  executed: boolean;
  score: number;
  confidence: number;
  reasons: string[];
  attackType?: AttackType;
  redirectFindings?: Array<{
    originalUrl: string;
    finalUrl: string;
    hopCount: number;
  }>;
}

const SHORTENER_HOSTS = new Set([
  "bit.ly",
  "reurl.cc",
  "tinyurl.com",
  "t.co",
  "rb.gy",
  "lihi.cc",
  "ppt.cc",
  "rebrand.ly",
  "shorturl.at",
  "cutt.ly"
]);

const RISK_PATH_PATTERN = /login|signin|verify|secure|account|billing|payment|invoice|refund|delivery|tracking|otp|password/i;

function clamp(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function countHostnameRiskSignals(hostname: string): number {
  const labels = hostname.split(".").filter(Boolean);
  const hyphenCount = (hostname.match(/-/g) || []).length;
  const digitCount = (hostname.match(/\d/g) || []).length;
  let signals = 0;

  if (hostname.includes("xn--")) {
    signals += 2;
  }

  if (labels.length >= 4) {
    signals += 1;
  }

  if (hyphenCount >= 2) {
    signals += 1;
  }

  if (digitCount >= 4) {
    signals += 1;
  }

  return signals;
}

function parseEmailDomain(value?: string): string | null {
  const text = String(value || "").trim().toLowerCase();
  if (!text) {
    return null;
  }

  const directMatch = text.match(/@([a-z0-9.-]+\.[a-z]{2,})/i);
  if (directMatch) {
    return directMatch[1].toLowerCase();
  }

  return null;
}

function domainsDiffer(a: string | null, b: string | null): boolean {
  if (!a || !b) {
    return false;
  }

  return a !== b;
}

export async function runAgentAnalyzer(features: PageFeatures, input: AgentAnalyzerInput): Promise<AgentAnalyzerResult> {
  let score = input.baseScore;
  const reasons: string[] = [];
  let attackType = input.attackType;

  const url = new URL(features.url);
  const hostnameRiskSignals = countHostnameRiskSignals(features.hostname.toLowerCase());
  const ruleSignals = extractRuleSignals(features);
  const shortenerLinks = features.links.hostnames.filter((hostname) => SHORTENER_HOSTS.has(hostname.toLowerCase()));
  const offDomainLinks = features.links.hostnames.filter((hostname) => hostname && hostname !== features.hostname);
  const mismatchedBrands = findMismatchedBrands(features.hostname, features.brandSignals);
  const mismatchedBrandLinks = findMismatchedBrandLinks(features.links.hostnames, features.brandSignals);
  const emailSenderDomain = parseEmailDomain(features.email?.sender);
  const emailReplyToDomain = parseEmailDomain(features.email?.replyTo);
  const emailText = `${features.email?.subject ?? ""} ${features.email?.bodyText ?? ""}`;
  const visibleText = `${features.title ?? ""} ${features.visibleText ?? ""} ${emailText}`;
  const redirectCandidates = (features.links.urls || []).slice(0, 5);
  const redirectFindings = [];

  if (shortenerLinks.length > 0) {
    score += 16;
    reasons.push(`Shortened or redirection-style links were detected: ${shortenerLinks.slice(0, 3).join(", ")}.`);
  }

  for (const urlCandidate of redirectCandidates) {
    const resolution = await resolveRedirectChain(urlCandidate);
    if (resolution.finalUrl !== resolution.originalUrl || resolution.hopCount > 0) {
      redirectFindings.push({
        originalUrl: resolution.originalUrl,
        finalUrl: resolution.finalUrl,
        hopCount: resolution.hopCount
      });
    }
  }

  if (redirectFindings.length > 0) {
    score += 14;
    reasons.push("Redirect-style links resolve to a different final destination.");
  }

  if (hostnameRiskSignals >= 2) {
    score += 14;
    reasons.push("Hostname structure looks algorithmic or disguise-oriented.");
  }

  if (offDomainLinks.length >= 5) {
    score += 10;
    reasons.push("Page references many off-domain link targets.");
  }

  if (mismatchedBrands.length > 0 && mismatchedBrandLinks.length > 0) {
    score += 18;
    reasons.push("Brand references are inconsistent with both the current domain and linked destinations.");
    attackType = attackType === "unknown" ? "brand_impersonation" : attackType;
  }

  if (features.forms.passwordFields > 0 && RISK_PATH_PATTERN.test(url.pathname)) {
    score += 15;
    reasons.push("Credential or verification-style URL path appears together with password capture.");
    attackType = "credential_harvest";
  }

  if (
    hasKeywordMatch(visibleText, "payment") &&
    (hasKeywordMatch(visibleText, "urgency") || hasKeywordMatch(visibleText, "credential"))
  ) {
    score += 14;
    reasons.push("Payment-related language appears together with urgent or verification-oriented messaging.");
    attackType = attackType === "credential_harvest" ? attackType : "payment_fraud";
  }

  if (features.source === "email") {
    if (domainsDiffer(emailSenderDomain, emailReplyToDomain)) {
      score += 18;
      reasons.push("Email sender domain and reply-to domain do not match.");
    }

    if (ruleSignals.emailUsesFreemailForBrandClaim) {
      score += 12;
      reasons.push("Email claims a trusted brand but uses a freemail sender domain.");
      attackType = attackType === "unknown" ? "brand_impersonation" : attackType;
    }

    if (features.brandSignals.length > 0 && emailSenderDomain) {
      const mismatchedEmailBrand = findMismatchedBrands(emailSenderDomain, features.brandSignals);
      if (mismatchedEmailBrand.length > 0) {
        score += 14;
        reasons.push("Email sender domain does not match the claimed brand.");
        attackType = attackType === "unknown" ? "brand_impersonation" : attackType;
      }
    }

    if (features.email?.linkCount && features.email.linkCount >= 8) {
      score += 8;
      reasons.push("Email contains an unusually high number of links.");
    }
  }

  const normalizedScore = clamp(score);
  const confidence = reasons.length >= 3 ? 0.8 : reasons.length > 0 ? 0.68 : 0.6;

  return {
    executed: true,
    score: normalizedScore,
    confidence,
    reasons,
    attackType: attackType === input.attackType ? undefined : attackType,
    redirectFindings
  };
}
