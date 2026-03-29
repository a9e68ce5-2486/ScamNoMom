import { findMismatchedBrandLinks, findMismatchedBrands } from "../config/tw-brand-domains.js";
import { getMatchedKeywords, hasKeywordMatch } from "../config/tw-scam-keywords.js";
import type { PageFeatures } from "../types/analysis.js";

const TW_TRUST_BRAND_PATTERN =
  /國泰|玉山|台新|中信|中國信託|富邦|永豐|兆豐|郵局|蝦皮|momo|pchome|露天|博客來|line|街口|全支付|全盈\+pay|7-11|統一超商|全家|黑貓|新竹物流|宅配通|監理站|國稅局|健保署|地檢署|警政署/;

export interface RuleSignalSnapshot {
  hasPasswordFields: boolean;
  externalSubmitCount: number;
  mismatchedTextCount: number;
  suspiciousTldCount: number;
  hiddenElementCount: number;
  iframeCount: number;
  hostnameUsesSuspiciousTld: boolean;
  brandOnCredentialPage: boolean;
  mismatchedBrands: string[];
  mismatchedBrandLinks: string[];
  hasTaiwanBrandActionPattern: boolean;
  hasTraditionalScamLanguage: boolean;
  emailContext: boolean;
  emailHasManyLinks: boolean;
  emailLinkMismatch: boolean;
  emailHighTrustSenderStyle: boolean;
  emailUrgencyLanguage: boolean;
  emailTraditionalScamLanguage: boolean;
  emailSenderDomain: string | null;
  emailReplyToDomain: string | null;
  emailSenderReplyToMismatch: boolean;
  emailBrandDomainMismatch: boolean;
  emailUsesFreemailForBrandClaim: boolean;
  emailMatchedKeywords: string[];
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

function isFreemailDomain(domain: string | null): boolean {
  if (!domain) {
    return false;
  }

  return [
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "yahoo.com.tw",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com"
  ].includes(domain);
}

export function extractRuleSignals(features: PageFeatures): RuleSignalSnapshot {
  const emailText = `${features.email?.subject ?? ""} ${features.email?.bodyText ?? ""}`.toLowerCase();
  const fullText = `${features.title ?? ""} ${features.visibleText ?? ""} ${features.email?.subject ?? ""} ${features.email?.bodyText ?? ""}`;
  const normalizedText = fullText.toLowerCase();
  const mismatchedBrands = findMismatchedBrands(features.hostname, features.brandSignals).map((entry) => entry.brand);
  const mismatchedBrandLinks = findMismatchedBrandLinks(features.links.hostnames, features.brandSignals).map((entry) => entry.brand);
  const hostnameTld = features.hostname.split(".").pop()?.toLowerCase() ?? "";
  const emailKeywordText = `${features.email?.subject ?? ""} ${features.email?.bodyText ?? ""}`;
  const emailSenderDomain = parseEmailDomain(features.email?.sender);
  const emailReplyToDomain = parseEmailDomain(features.email?.replyTo);
  const emailMatchedKeywords = [
    ...getMatchedKeywords(emailKeywordText, "credential"),
    ...getMatchedKeywords(emailKeywordText, "urgency"),
    ...getMatchedKeywords(emailKeywordText, "payment"),
    ...getMatchedKeywords(emailKeywordText, "logistics"),
    ...getMatchedKeywords(emailKeywordText, "prize"),
    ...getMatchedKeywords(emailKeywordText, "investment"),
    ...getMatchedKeywords(emailKeywordText, "customerService"),
    ...getMatchedKeywords(emailKeywordText, "government"),
    ...getMatchedKeywords(emailKeywordText, "qr")
  ];
  const emailBrandDomainMismatch =
    features.source === "email" &&
    Boolean(emailSenderDomain) &&
    findMismatchedBrands(emailSenderDomain || "", features.brandSignals).length > 0;
  const emailUsesFreemailForBrandClaim =
    features.source === "email" &&
    features.brandSignals.length > 0 &&
    isFreemailDomain(emailSenderDomain);

  return {
    hasPasswordFields: features.forms.passwordFields > 0,
    externalSubmitCount: features.forms.externalSubmitCount,
    mismatchedTextCount: features.links.mismatchedTextCount,
    suspiciousTldCount: features.links.suspiciousTldCount,
    hiddenElementCount: features.dom.hiddenElementCount,
    iframeCount: features.dom.iframeCount,
    hostnameUsesSuspiciousTld: ["zip", "click", "top", "gq", "work", "country"].includes(hostnameTld),
    brandOnCredentialPage: features.brandSignals.length > 0 && features.forms.passwordFields > 0,
    mismatchedBrands,
    mismatchedBrandLinks,
    hasTaiwanBrandActionPattern: TW_TRUST_BRAND_PATTERN.test(fullText) && (features.links.total > 0 || features.forms.total > 0),
    hasTraditionalScamLanguage:
      hasKeywordMatch(fullText, "credential") ||
      hasKeywordMatch(fullText, "urgency") ||
      hasKeywordMatch(fullText, "payment") ||
      hasKeywordMatch(fullText, "logistics") ||
      hasKeywordMatch(fullText, "prize") ||
      hasKeywordMatch(fullText, "investment") ||
      hasKeywordMatch(fullText, "customerService") ||
      hasKeywordMatch(fullText, "government") ||
      hasKeywordMatch(fullText, "qr"),
    emailContext: features.source === "email" && Boolean(features.email),
    emailHasManyLinks: (features.email?.linkCount ?? 0) > 3,
    emailLinkMismatch: features.links.mismatchedTextCount > 0,
    emailHighTrustSenderStyle: Boolean(features.email?.sender && /support|security|billing|admin|no-reply/i.test(features.email.sender)),
    emailUrgencyLanguage:
      /\bverify\b|\breset\b|\burgent\b|\bsuspended\b|\bconfirm\b/.test(emailText) ||
      /(立即|緊急|24小時內|今日內|帳戶異常|停權|停用)/.test(normalizedText),
    emailTraditionalScamLanguage: emailMatchedKeywords.length > 0,
    emailSenderDomain,
    emailReplyToDomain,
    emailSenderReplyToMismatch: Boolean(emailSenderDomain && emailReplyToDomain && emailSenderDomain !== emailReplyToDomain),
    emailBrandDomainMismatch,
    emailUsesFreemailForBrandClaim,
    emailMatchedKeywords
  };
}
