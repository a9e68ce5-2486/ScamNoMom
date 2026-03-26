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
  email?: {
    provider: "gmail" | "outlook" | "yahoo" | "proton" | "generic";
    subject?: string;
    sender?: string;
    replyTo?: string;
    bodyText?: string;
    linkCount: number;
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
    };
  };
  evidence: {
    ruleScore: number;
    llmScore: number;
    routerDecision: Decision;
    agentScore?: number;
    initialRouterDecision?: Decision;
  };
}
