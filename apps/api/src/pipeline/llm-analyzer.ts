import { getLlmConfig, hasOllamaConfig, hasOpenAiConfig } from "../config/llm.js";
import type { LlmResult, PageFeatures, RiskLevel, TextAnalysisInput } from "../types/analysis.js";
import { extractRuleSignals } from "./rule-signals.js";

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

/**
 * Fallback LLM result for page/email analysis when no LLM provider is reachable.
 *
 * Scoped to English-language semantic signals only — TW-language keyword scoring
 * and all structural signals (forms, links, brand mismatches, email sender alignment)
 * are already handled by runRuleEngine. Duplicating them here would cause
 * double-counting in the weighted combination in analyze.ts.
 *
 * attackType is inferred from rule signals without adding to the score.
 */
function buildFallbackResult(features: PageFeatures): LlmResult {
  const text = `${features.title ?? ""} ${features.visibleText ?? ""} ${features.email?.subject ?? ""} ${features.email?.bodyText ?? ""}`.toLowerCase();
  let score = 0;
  const reasons: string[] = [];
  let attackType: LlmResult["attackType"] = "unknown";

  // English-only semantic signals not covered by runRuleEngine
  if (/\bverify\b|\bconfirm your\b|\bsign[- ]in\b|\bpassword\b|\baccount\b/.test(text)) {
    score += 18;
    reasons.push("English credential or account verification language detected.");
    attackType = "credential_harvest";
  }

  if (/\burgent\b|\bimmediately\b|\bsuspended\b|\bexpired\b|\baction required\b/.test(text)) {
    score += 12;
    reasons.push("English urgency or pressure language detected.");
  }

  if (/\bpayment\b|\binvoice\b|\bbilling\b|\bwire transfer\b/.test(text)) {
    score += 12;
    reasons.push("English financial or payment-related language detected.");
    attackType = attackType === "unknown" ? "payment_fraud" : attackType;
  }

  if (/gift card|wire transfer|western union|otp code|atm code|send money now/i.test(text)) {
    score += 18;
    reasons.push("High-risk English transfer or social engineering language detected.");
    attackType = attackType === "unknown" ? "phone_scam" : attackType;
  }

  // Infer attackType from rule signals — no score contribution to avoid double-counting
  if (attackType === "unknown") {
    const signals = extractRuleSignals(features);
    if (signals.mismatchedBrands.length > 0 || signals.mismatchedBrandLinks.length > 0) {
      attackType = "brand_impersonation";
    } else if (features.brandSignals.length > 0 && (signals.hasPasswordFields || signals.externalSubmitCount > 0)) {
      attackType = "brand_impersonation";
    } else if (signals.hasPasswordFields || signals.externalSubmitCount > 0) {
      attackType = "credential_harvest";
    } else if (signals.hasTraditionalScamLanguage) {
      attackType = "payment_fraud";
    }
  }

  const normalizedScore = Math.max(0, Math.min(100, Math.round(score)));

  return {
    riskLevel: scoreToRiskLevel(normalizedScore),
    score: normalizedScore,
    reasons,
    attackType,
    // Lower confidence than a real LLM call — rule engine carries the structural weight
    confidence: 0.48,
    provider: "fallback"
  };
}

/**
 * Zero-score placeholder returned when no LLM is available for text/SMS analysis.
 * The static keyword analysis in text-analyzer.ts is the primary signal in this path.
 */
function buildTextFallbackResult(): LlmResult {
  return {
    riskLevel: "low",
    score: 0,
    reasons: [],
    attackType: "unknown",
    confidence: 0.3,
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

function buildTextPrompt(input: TextAnalysisInput): string {
  const summary = {
    source: "text_message",
    channel: input.channel,
    claimedBrand: input.claimedBrand ?? null,
    title: input.title ?? "",
    textExcerpt: input.text.slice(0, 3000),
    metadata: input.metadata ?? null
  };

  return [
    "Analyze whether this text message, SMS, or chat message is a scam or phishing attempt.",
    "Focus on: urgency tactics, brand impersonation, requests for OTP/ATM/transfers, investment promises, romance scam patterns, and fake government or logistics notices.",
    "Be especially alert to Traditional Chinese scam patterns common in Taiwan (假客服、假物流、投資詐騙、感情詐騙、假政府通知).",
    "Return a conservative assessment — only flag when there are clear indicators.",
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

function extractJsonObject(raw: string): string {
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");

  if (start === -1 || end === -1 || end <= start) {
    throw new Error("No JSON object found in model output.");
  }

  return raw.slice(start, end + 1);
}

// ─── Page / Email analyzers ───────────────────────────────────────────────────

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

// ─── Text / SMS / Messaging analyzers ────────────────────────────────────────

async function runOpenAiTextAnalyzer(input: TextAnalysisInput): Promise<LlmResult> {
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
        "You are a scam detection analyst specializing in Taiwan SMS, LINE, and messaging fraud. Return only structured output. Be conservative — only flag when there are clear scam indicators.",
      input: buildTextPrompt(input),
      text: {
        format: buildSchema(),
        verbosity: "low"
      }
    })
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(`OpenAI text request failed with ${response.status}: ${message}`);
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

async function runOllamaTextAnalyzer(input: TextAnalysisInput): Promise<LlmResult> {
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
        "You are a scam detection analyst for Taiwan SMS and messaging fraud. Return only JSON. Be conservative — only flag when there are clear scam indicators.",
      prompt: `${buildTextPrompt(input)}

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
    throw new Error(`Ollama text request failed with ${response.status}: ${message}`);
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

/**
 * LLM analysis for text/SMS/messaging input.
 *
 * When no LLM is configured, returns a zero-score placeholder so that the
 * static keyword analysis in text-analyzer.ts remains the primary signal.
 * When an LLM is available, its result is blended with static analysis in
 * text-analyzer.ts (static × 0.4 + LLM × 0.6).
 */
export async function runTextLlmAnalyzer(input: TextAnalysisInput): Promise<LlmResult> {
  const config = getLlmConfig();

  if (config.provider === "fallback") {
    return buildTextFallbackResult();
  }

  if (config.provider === "openai") {
    if (!hasOpenAiConfig()) {
      return buildTextFallbackResult();
    }

    try {
      return await runOpenAiTextAnalyzer(input);
    } catch {
      return buildTextFallbackResult();
    }
  }

  if (config.provider === "ollama") {
    if (!hasOllamaConfig()) {
      return buildTextFallbackResult();
    }

    try {
      return await runOllamaTextAnalyzer(input);
    } catch {
      return buildTextFallbackResult();
    }
  }

  if (hasOpenAiConfig()) {
    try {
      return await runOpenAiTextAnalyzer(input);
    } catch {
      // Fall through to Ollama or placeholder.
    }
  }

  if (hasOllamaConfig()) {
    try {
      return await runOllamaTextAnalyzer(input);
    } catch {
      return buildTextFallbackResult();
    }
  }

  return buildTextFallbackResult();
}
