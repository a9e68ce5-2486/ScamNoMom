import { getLlmConfig, hasOllamaConfig, hasOpenAiConfig } from "../config/llm.js";
import { hasKeywordMatch } from "../config/tw-scam-keywords.js";
import type { LlmResult, PageFeatures, RiskLevel } from "../types/analysis.js";

const LLM_REQUEST_TIMEOUT_MS = 12000;
const SUPPORTED_ATTACK_TYPES: LlmResult["attackType"][] = [
  "credential_harvest",
  "brand_impersonation",
  "malware_delivery",
  "payment_fraud",
  "investment_scam",
  "customer_service_scam",
  "government_impersonation",
  "romance_scam",
  "phone_scam",
  "unknown"
];
const TW_BRAND_PATTERN =
  /國泰|玉山|台新|中信|中國信託|富邦|永豐|兆豐|郵局|蝦皮|momo|pchome|露天|博客來|line|7-11|全家|黑貓|新竹物流|宅配通/;

function scoreToRiskLevel(score: number): RiskLevel {
  if (score >= 70) {
    return "high";
  }

  if (score >= 40) {
    return "medium";
  }

  return "low";
}

function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), LLM_REQUEST_TIMEOUT_MS);
  return fetch(url, {
    ...init,
    signal: controller.signal
  }).finally(() => clearTimeout(timeout));
}

function normalizeAttackType(value: unknown): LlmResult["attackType"] {
  const parsed = String(value || "unknown").toLowerCase() as LlmResult["attackType"];
  return SUPPORTED_ATTACK_TYPES.includes(parsed) ? parsed : "unknown";
}

function buildFallbackResult(features: PageFeatures): LlmResult {
  const text = `${features.title ?? ""} ${features.visibleText ?? ""} ${features.email?.subject ?? ""} ${features.email?.bodyText ?? ""}`.toLowerCase();
  let score = 10;
  const reasons: string[] = [];
  let attackType: LlmResult["attackType"] = "unknown";

  if (/\bverify\b|\blogin\b|\bpassword\b|\baccount\b/.test(text)) {
    score += 30;
    reasons.push("Language suggests account verification or credential entry.");
    attackType = "credential_harvest";
  }

  if (hasKeywordMatch(text, "credential")) {
    score += 28;
    reasons.push("Traditional Chinese text suggests account verification or credential entry.");
    attackType = attackType === "unknown" ? "credential_harvest" : attackType;
  }

  if (/\burgent\b|\bimmediately\b|\bsuspended\b|\bexpired\b/.test(text)) {
    score += 18;
    reasons.push("Page uses urgency or pressure tactics.");
  }

  if (hasKeywordMatch(text, "urgency")) {
    score += 18;
    reasons.push("Traditional Chinese urgency or suspension language was detected.");
  }

  if (features.brandSignals.length > 0) {
    score += 16;
    reasons.push("Brand references indicate possible impersonation.");
    attackType = attackType === "unknown" ? "brand_impersonation" : attackType;
  }

  if (TW_BRAND_PATTERN.test(text)) {
    score += 16;
    reasons.push("Taiwan brand, bank, or logistics references indicate possible impersonation.");
    attackType = attackType === "unknown" ? "brand_impersonation" : attackType;
  }

  if (features.forms.passwordFields > 0 && /\bpayment\b|\bbank\b|\binvoice\b/.test(text)) {
    score += 20;
    reasons.push("Financial language appears near a credential capture flow.");
    attackType = "payment_fraud";
  }

  if (hasKeywordMatch(text, "payment") || hasKeywordMatch(text, "logistics") || hasKeywordMatch(text, "prize")) {
    score += 20;
    reasons.push("Traditional Chinese scam language related to payment, logistics, or prizes was detected.");
    attackType = attackType === "credential_harvest" ? attackType : "payment_fraud";
  }

  if (hasKeywordMatch(text, "investment")) {
    score += 22;
    reasons.push("Traditional Chinese investment-scam language was detected.");
    attackType = "investment_scam";
  }

  if (hasKeywordMatch(text, "customerService")) {
    score += 18;
    reasons.push("Traditional Chinese fake-customer-service scam language was detected.");
    attackType = attackType === "credential_harvest" ? attackType : "customer_service_scam";
  }

  if (hasKeywordMatch(text, "government")) {
    score += 16;
    reasons.push("Traditional Chinese government-notice scam language was detected.");
    attackType = attackType === "unknown" ? "government_impersonation" : attackType;
  }

  if (hasKeywordMatch(text, "qr")) {
    score += 14;
    reasons.push("QR-code-based scam language was detected.");
  }

  if (/atm|otp|驗證碼|一次性密碼|不要掛電話|客服專員|解除分期/i.test(text)) {
    score += 20;
    reasons.push("Taiwan phone/social-engineering transfer script was detected.");
    attackType = attackType === "unknown" ? "phone_scam" : attackType;
  }

  if (/遊戲點數|gift card|虛擬點數|mycard|gash|steam/i.test(text)) {
    score += 16;
    reasons.push("Gift-card or virtual-point transfer script was detected.");
    attackType = attackType === "unknown" ? "payment_fraud" : attackType;
  }

  const normalizedScore = Math.max(0, Math.min(100, Math.round(score)));

  return {
    riskLevel: scoreToRiskLevel(normalizedScore),
    score: normalizedScore,
    reasons,
    attackType,
    confidence: 0.55,
    provider: "fallback"
  };
}

function buildPrompt(features: PageFeatures): string {
  const summary = {
    source: features.source,
    url: features.url,
    hostname: features.hostname,
    title: features.title ?? "",
    forms: features.forms,
    links: features.links,
    dom: features.dom,
    brandSignals: features.brandSignals,
    visibleTextExcerpt: (features.visibleText ?? "").slice(0, 2500),
    email: features.email
      ? {
          provider: features.email.provider,
          subject: features.email.subject ?? "",
          sender: features.email.sender ?? "",
          replyTo: features.email.replyTo ?? "",
          bodyTextExcerpt: (features.email.bodyText ?? "").slice(0, 2500),
          linkCount: features.email.linkCount
        }
      : null
  };

  return [
    "Analyze whether this page is likely a phishing page.",
    "Return a conservative security assessment based on content, impersonation signals, credential collection behavior, urgency cues, and destination/link inconsistencies.",
    "Input summary:",
    JSON.stringify(summary, null, 2)
  ].join("\n");
}

function buildSchema() {
  return {
    type: "json_schema",
    name: "scamnomom_analysis",
    strict: true,
    schema: {
      type: "object",
      additionalProperties: false,
      properties: {
        riskLevel: {
          type: "string",
          enum: ["low", "medium", "high"]
        },
        score: {
          type: "number",
          minimum: 0,
          maximum: 100
        },
        reasons: {
          type: "array",
          items: { type: "string" }
        },
        attackType: {
          type: "string",
          enum: [
            "credential_harvest",
            "brand_impersonation",
            "malware_delivery",
            "payment_fraud",
            "investment_scam",
            "customer_service_scam",
            "government_impersonation",
            "romance_scam",
            "phone_scam",
            "unknown"
          ]
        },
        confidence: {
          type: "number",
          minimum: 0,
          maximum: 1
        }
      },
      required: ["riskLevel", "score", "reasons", "attackType", "confidence"]
    }
  };
}

function normalizeLlmResult(data: LlmResult): LlmResult {
  return {
    riskLevel: data.riskLevel,
    score: Math.max(0, Math.min(100, Math.round(data.score))),
    reasons: Array.isArray(data.reasons) ? data.reasons.slice(0, 6) : [],
    attackType: normalizeAttackType(data.attackType),
    confidence: Math.max(0, Math.min(1, data.confidence)),
    provider: data.provider
  };
}

async function runOpenAiAnalyzer(features: PageFeatures): Promise<LlmResult> {
  const { apiKey, model } = getLlmConfig().openai;
  const response = await fetchWithTimeout("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model,
      instructions:
        "You are a phishing detection analyst. Return only structured output. Be cautious and avoid overclaiming when evidence is weak.",
      input: buildPrompt(features),
      text: {
        format: buildSchema(),
        verbosity: "low"
      }
    })
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(`OpenAI request failed with ${response.status}: ${message}`);
  }

  const data = (await response.json()) as { output_text?: string };
  if (!data.output_text) {
    throw new Error("OpenAI response did not include output_text.");
  }

  return normalizeLlmResult({
    ...(JSON.parse(data.output_text) as Omit<LlmResult, "provider">),
    provider: "openai"
  });
}

function extractJsonObject(raw: string): string {
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");

  if (start === -1 || end === -1 || end <= start) {
    throw new Error("No JSON object found in model output.");
  }

  return raw.slice(start, end + 1);
}

async function runOllamaAnalyzer(features: PageFeatures): Promise<LlmResult> {
  const { baseUrl, model } = getLlmConfig().ollama;
  const response = await fetchWithTimeout(`${baseUrl}/api/generate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model,
      stream: false,
      format: "json",
      system:
        "You are a phishing detection analyst. Return only JSON with keys riskLevel, score, reasons, attackType, confidence. Be conservative and avoid overclaiming.",
      prompt: `${buildPrompt(features)}

Return JSON only using this schema:
{
  "riskLevel": "low | medium | high",
  "score": 0,
  "reasons": ["short reason"],
  "attackType": "credential_harvest | brand_impersonation | malware_delivery | payment_fraud | investment_scam | customer_service_scam | government_impersonation | romance_scam | phone_scam | unknown",
  "confidence": 0.0
}`
    })
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(`Ollama request failed with ${response.status}: ${message}`);
  }

  const data = (await response.json()) as { response?: string };
  if (!data.response) {
    throw new Error("Ollama response did not include response text.");
  }

  return normalizeLlmResult({
    ...(JSON.parse(extractJsonObject(data.response)) as Omit<LlmResult, "provider">),
    provider: "ollama"
  });
}

export async function runLlmAnalyzer(features: PageFeatures): Promise<LlmResult> {
  const config = getLlmConfig();

  if (config.provider === "fallback") {
    return buildFallbackResult(features);
  }

  if (config.provider === "openai") {
    if (!hasOpenAiConfig()) {
      return buildFallbackResult(features);
    }

    try {
      return await runOpenAiAnalyzer(features);
    } catch {
      return buildFallbackResult(features);
    }
  }

  if (config.provider === "ollama") {
    if (!hasOllamaConfig()) {
      return buildFallbackResult(features);
    }

    try {
      return await runOllamaAnalyzer(features);
    } catch {
      return buildFallbackResult(features);
    }
  }

  if (hasOpenAiConfig()) {
    try {
      return await runOpenAiAnalyzer(features);
    } catch {
      // Fall through to Ollama or heuristic fallback.
    }
  }

  if (hasOllamaConfig()) {
    try {
      return await runOllamaAnalyzer(features);
    } catch {
      return buildFallbackResult(features);
    }
  }

  return buildFallbackResult(features);
}
