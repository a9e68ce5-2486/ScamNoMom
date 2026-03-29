export type RiskLevel = "low" | "medium" | "high";
export type Decision = "allow" | "warn" | "escalate" | "block";
export type AttackType =
  | "credential_harvest"
  | "brand_impersonation"
  | "malware_delivery"
  | "payment_fraud"
  | "investment_scam"
  | "customer_service_scam"
  | "government_impersonation"
  | "romance_scam"
  | "phone_scam"
  | "unknown";

export interface TextAnalysisInput {
  source: "text";
  channel: "sms" | "line" | "messenger" | "telegram" | "phone_transcript" | "manual_report" | "other";
  text: string;
  title?: string;
  claimedBrand?: string;
  metadata?: {
    sender?: string;
    contact?: string;
  };
}

export interface PageFeatures {
  url: string;
  hostname: string;
  source: "web" | "email";
  title?: string;
  visibleText?: string;
  forms: {
    total: number;
    passwordFields: number;
    externalSubmitCount: number;
  };
  links: {
    total: number;
    mismatchedTextCount: number;
    suspiciousTldCount: number;
    hostnames: string[];
    urls: string[];
  };
  dom: {
    hiddenElementCount: number;
    iframeCount: number;
  };
  brandSignals: string[];
  urlSignals?: {
    dotCount?: number;
    hyphenCount?: number;
    digitCount?: number;
    length?: number;
    hasIpHost?: boolean;
    hasAtSymbol?: boolean;
    hasPunycode?: boolean;
    hasHexEncoding?: boolean;
    hasSuspiciousPathKeyword?: boolean;
    hasSuspiciousQueryKeyword?: boolean;
    hasLongHostname?: boolean;
    hasManySubdomains?: boolean;
    isShortenerHost?: boolean;
  };
  email?: {
    provider: "gmail" | "outlook" | "yahoo" | "proton" | "generic";
    subject?: string;
    sender?: string;
    replyTo?: string;
    bodyText?: string;
    linkCount: number;
  };
  liveDom?: {
    enriched: boolean;
    source?: "api_fetch" | "none";
    fetchedAt?: string;
    cacheHit?: boolean;
    fetchError?: string;
  };
  enrichment?: {
    liveDomUsed?: boolean;
    skippedReason?: string;
    cacheHit?: boolean;
    fetchedAt?: string;
  };
}

export interface RuleResult {
  score: number;
  reasons: string[];
}

export interface LlmResult {
  riskLevel: RiskLevel;
  score: number;
  reasons: string[];
  attackType: AttackType;
  confidence: number;
  provider: "openai" | "ollama" | "fallback";
}

export interface AnalysisResult {
  source: "web" | "email" | "text";
  riskLevel: RiskLevel;
  score: number;
  reasons: string[];
  confidence: number;
  attackType: AttackType;
  recommendedAction: Decision;
  needsAgent: boolean;
  analyzedAt: string;
  provider: "openai" | "ollama" | "fallback";
  enrichment?: {
    liveDomUsed: boolean;
    skippedReason?: string;
    cacheHit?: boolean;
  };
  agent?: {
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
    threatIntel?: {
      checkedHostnames: string[];
      blacklistMatches: string[];
      riskyIpHosts: string[];
      dnsFindings: Array<{
        hostname: string;
        aRecordCount: number;
        nsRecordCount: number;
        mxRecordCount: number;
        hasSpfRecord: boolean;
        lookupError?: string;
      }>;
      external?: {
        enabled: boolean;
        rdap?: {
          hostname: string;
          registrationDate?: string;
          lastChangedDate?: string;
          registrar?: string;
          domainAgeDays?: number;
        };
        blacklist?: {
          checked: boolean;
          listed: boolean;
          provider?: string;
          reason?: string;
        };
        providers?: Array<{
          provider: string;
          checked: boolean;
          scoreDelta: number;
          confidence: number;
          reasons: string[];
        }>;
        policy?: {
          providerCount: number;
          positiveProviderCount: number;
          rawScoreDelta: number;
          adjustedScoreDelta: number;
          finalScoreDelta: number;
          confidence: number;
          capApplied: boolean;
          penaltyApplied: boolean;
        };
      };
      emailAuth?: {
        domain: string;
        mxRecordCount: number;
        hasSpfRecord: boolean;
        hasDmarcRecord: boolean;
        dmarcPolicy?: "none" | "quarantine" | "reject";
        discoverableDkimSelectors: string[];
        checkedDkimSelectors: string[];
      };
    };
  };
  evidence: {
    ruleScore: number;
    llmScore: number;
    mlScore?: number;
    urlRiskScore?: number;
    routerDecision: Decision;
    agentScore?: number;
    initialRouterDecision?: Decision;
    enrichment?: {
      liveDomUsed: boolean;
      skippedReason?: string;
      cacheHit?: boolean;
    };
    modelContributions?: {
      rule: number;
      llm: number;
      urlRisk: number;
      ml: number;
    };
    modelVersion?: string;
  };
}
