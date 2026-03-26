import { getRuleWeights } from "../config/rule-weights.js";
import type { PageFeatures, RuleResult } from "../types/analysis.js";
import { extractRuleSignals } from "./rule-signals.js";

function clamp(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function runRuleEngine(features: PageFeatures): RuleResult {
  const weights = getRuleWeights();
  const signals = extractRuleSignals(features);
  let score = 0;
  const reasons: string[] = [];

  if (signals.hasPasswordFields) {
    score += weights.passwordFields;
    reasons.push("Page contains password input fields.");
  }

  if (signals.externalSubmitCount > 0) {
    score += weights.externalSubmit;
    reasons.push("Form submission targets an external domain.");
  }

  if (signals.mismatchedTextCount > 0) {
    score += weights.mismatchedText;
    reasons.push("Visible link text does not match destination.");
  }

  if (signals.suspiciousTldCount > 0) {
    score += weights.suspiciousLinkTldBase + signals.suspiciousTldCount * weights.suspiciousLinkTldPerLink;
    reasons.push("One or more links use suspicious top-level domains.");
  }

  if (signals.hiddenElementCount > 5) {
    score += weights.hiddenElements;
    reasons.push("Page contains multiple hidden elements.");
  }

  if (signals.iframeCount > 2) {
    score += weights.iframeHeavy;
    reasons.push("Page uses multiple iframes.");
  }

  if (signals.hostnameUsesSuspiciousTld) {
    score += weights.suspiciousHostnameTld;
    reasons.push("Page hostname uses a suspicious top-level domain.");
  }

  if (signals.brandOnCredentialPage) {
    score += weights.brandOnCredentialPage;
    reasons.push("Brand-like language appears on a credential collection page.");
  }

  if (signals.mismatchedBrands.length > 0) {
    score += weights.mismatchedBrand;
    reasons.push(`Brand mentions do not match the current domain: ${signals.mismatchedBrands.join(", ")}.`);
  }

  if (signals.mismatchedBrandLinks.length > 0) {
    score += weights.mismatchedBrandLinks;
    reasons.push(`Brand mentions do not match linked domains: ${signals.mismatchedBrandLinks.join(", ")}.`);
  }

  if (signals.hasTaiwanBrandActionPattern) {
    score += weights.taiwanBrandActionPattern;
    reasons.push("Taiwan brand or payment-service language appears with actionable links or forms.");
  }

  if (signals.hasTraditionalScamLanguage) {
    score += weights.traditionalScamLanguage;
    reasons.push("Traditional Chinese scam or phishing language was detected.");
  }

  if (signals.emailContext) {
    score += weights.emailContext;
    reasons.push("Analysis is based on an email message context.");

    if (signals.emailHasManyLinks) {
      score += weights.emailManyLinks;
      reasons.push("Email contains multiple links.");
    }

    if (signals.emailLinkMismatch) {
      score += weights.emailLinkMismatch;
      reasons.push("Email link text and destination do not align.");
    }

    if (signals.emailHighTrustSenderStyle) {
      score += weights.emailHighTrustSenderStyle;
      reasons.push("Sender name uses a high-trust service style.");
    }

    if (signals.emailSenderReplyToMismatch) {
      score += weights.emailSenderReplyToMismatch;
      reasons.push("Email sender domain and reply-to domain do not match.");
    }

    if (signals.emailBrandDomainMismatch) {
      score += weights.emailBrandDomainMismatch;
      reasons.push("Email sender domain does not match the claimed brand.");
    }

    if (signals.emailUsesFreemailForBrandClaim) {
      score += weights.emailFreemailBrandClaim;
      reasons.push("Brand-like email uses a freemail sender domain instead of an official domain.");
    }

    if (signals.emailUrgencyLanguage) {
      score += weights.emailUrgencyLanguage;
      reasons.push("Email language uses common phishing urgency or verification patterns.");
    }

    if (signals.emailTraditionalScamLanguage) {
      score += weights.emailTraditionalScamLanguage;
      reasons.push(`Email contains common Traditional Chinese scam phrases: ${signals.emailMatchedKeywords.slice(0, 4).join(", ")}.`);
    }
  }

  return {
    score: clamp(score),
    reasons
  };
}
