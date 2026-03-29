import { getThreatIntelConfig, shouldUseExternalThreatIntel, type ThreatIntelConfig } from "../config/threat-intel.js";
import {
  EXTERNAL_THREAT_INTEL_PROVIDERS,
  type ExternalThreatIntelInput,
  type ExternalThreatIntelProviderResult
} from "./external-threat-providers.js";

export interface ExternalThreatIntelResult {
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
  providers: ExternalThreatIntelProviderResult[];
  policy: {
    providerCount: number;
    positiveProviderCount: number;
    rawScoreDelta: number;
    adjustedScoreDelta: number;
    finalScoreDelta: number;
    confidence: number;
    capApplied: boolean;
    penaltyApplied: boolean;
  };
  reasons: string[];
  confidence: number;
  scoreDelta: number;
}

function normalizeHostname(value: string): string {
  return String(value || "").trim().toLowerCase();
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

export function applyThreatIntelPolicy(
  providerResults: ExternalThreatIntelProviderResult[],
  config: ThreatIntelConfig
): ExternalThreatIntelResult["policy"] {
  const scoreContributors = providerResults.filter((result) => result.scoreDelta > 0);
  const rawScoreDelta = providerResults.reduce((sum, result) => sum + Math.max(0, result.scoreDelta), 0);
  let adjustedScoreDelta = rawScoreDelta;
  let penaltyApplied = false;

  if (scoreContributors.length === 1 && rawScoreDelta > 0) {
    adjustedScoreDelta = Math.round(rawScoreDelta * config.policy.singleProviderPenalty);
    penaltyApplied = true;
  }

  if (scoreContributors.length >= 2 && adjustedScoreDelta > 0) {
    adjustedScoreDelta += config.policy.multiProviderBoost;
  }

  const finalScoreDelta = clamp(Math.round(adjustedScoreDelta), 0, config.policy.maxScoreDelta);
  const confidenceBase = scoreContributors.length
    ? scoreContributors.reduce((sum, result) => sum + result.confidence, 0) / scoreContributors.length
    : 0.35;
  const confidence = clamp(
    confidenceBase + (scoreContributors.length >= 2 ? 0.08 : 0) - (penaltyApplied ? 0.04 : 0),
    0.2,
    0.95
  );

  return {
    providerCount: providerResults.length,
    positiveProviderCount: scoreContributors.length,
    rawScoreDelta: Math.round(rawScoreDelta),
    adjustedScoreDelta: Math.round(adjustedScoreDelta),
    finalScoreDelta,
    confidence: Number(confidence.toFixed(3)),
    capApplied: finalScoreDelta < Math.round(adjustedScoreDelta),
    penaltyApplied
  };
}

export async function runExternalThreatIntel(input: ExternalThreatIntelInput): Promise<ExternalThreatIntelResult> {
  if (!shouldUseExternalThreatIntel()) {
    return {
      enabled: false,
      providers: [],
      policy: {
        providerCount: 0,
        positiveProviderCount: 0,
        rawScoreDelta: 0,
        adjustedScoreDelta: 0,
        finalScoreDelta: 0,
        confidence: 0,
        capApplied: false,
        penaltyApplied: false
      },
      reasons: [],
      confidence: 0,
      scoreDelta: 0
    };
  }

  const config = getThreatIntelConfig();
  const normalizedInput: ExternalThreatIntelInput = {
    ...input,
    primaryHostname: normalizeHostname(input.primaryHostname),
    relatedHostnames: [...new Set((input.relatedHostnames || []).map(normalizeHostname).filter(Boolean))]
  };

  const providerResults = await Promise.all(
    EXTERNAL_THREAT_INTEL_PROVIDERS.map(async (provider) => {
      if (!provider.shouldRun(config, normalizedInput)) {
        return {
          provider: provider.name,
          checked: false,
          scoreDelta: 0,
          confidence: 0,
          reasons: []
        } satisfies ExternalThreatIntelProviderResult;
      }

      try {
        return await provider.run(config, normalizedInput);
      } catch (error) {
        return {
          provider: provider.name,
          checked: true,
          scoreDelta: 0,
          confidence: 0.25,
          reasons: [`${provider.name} provider failed: ${error instanceof Error ? error.message : String(error)}`]
        } satisfies ExternalThreatIntelProviderResult;
      }
    })
  );

  const policy = applyThreatIntelPolicy(providerResults, config);
  const reasons = providerResults.flatMap((result) => result.reasons);
  const rdapEvidence = providerResults.find((result) => result.provider === "rdap")?.evidence as
    | ExternalThreatIntelResult["rdap"]
    | undefined;
  const blacklistEvidence = providerResults.find((result) => result.provider === "blacklist")
    ?.evidence as ExternalThreatIntelResult["blacklist"] | undefined;

  return {
    enabled: true,
    rdap: rdapEvidence?.hostname ? rdapEvidence : undefined,
    blacklist: blacklistEvidence
      ? {
          checked: Boolean(blacklistEvidence.checked),
          listed: Boolean(blacklistEvidence.listed),
          provider: blacklistEvidence.provider,
          reason: blacklistEvidence.reason
        }
      : undefined,
    providers: providerResults,
    policy,
    reasons,
    confidence: policy.confidence,
    scoreDelta: policy.finalScoreDelta
  };
}
