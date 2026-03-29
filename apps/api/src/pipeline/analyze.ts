import { runAgentAnalyzer } from "./agent-analyzer.js";
import { applyUserCalibration } from "./calibration.js";
import { detectInterventionRisk } from "./intervention.js";
import { runLightweightModel } from "./lightweight-model.js";
import { enrichPageFeaturesLive } from "./live-page-enricher.js";
import { runLlmAnalyzer } from "./llm-analyzer.js";
import { routeDecision } from "./router.js";
import { runRuleEngine } from "./rule-engine.js";
import { analyzeUrlRisk } from "./url-risk-analyzer.js";
import type { AnalysisResult, PageFeatures, RiskLevel, UserCalibrationProfile } from "../types/analysis.js";

function scoreToRiskLevel(score: number): RiskLevel {
  if (score >= 70) {
    return "high";
  }

  if (score >= 40) {
    return "medium";
  }

  return "low";
}

function mergeReasons(...reasonGroups: Array<string[] | undefined>): string[] {
  const merged: string[] = [];
  for (const group of reasonGroups) {
    if (!Array.isArray(group)) {
      continue;
    }
    merged.push(...group);
  }
  return [...new Set(merged)];
}

function resolveFinalDecision(score: number): AnalysisResult["recommendedAction"] {
  if (score >= 70) {
    return "block";
  }

  if (score >= 40) {
    return "warn";
  }

  return "allow";
}

function isSparseSample(features: PageFeatures): boolean {
  return !String(features.visibleText || "").trim() && (features.forms.total ?? 0) === 0 && (features.dom.iframeCount ?? 0) === 0;
}

export async function analyzeFeatures(features: PageFeatures, calibration?: UserCalibrationProfile): Promise<AnalysisResult> {
  const fastRule = runRuleEngine(features);
  const fastUrlRisk = analyzeUrlRisk(features);
  const fastScore = Math.round(fastRule.score * 0.65 + fastUrlRisk.score * 0.35);
  const enrichment = await enrichPageFeaturesLive(features, fastScore);
  const effectiveFeatures = enrichment.features;
  const ruleResult = runRuleEngine(effectiveFeatures);
  const urlRisk = analyzeUrlRisk(effectiveFeatures);
  const llmResult = await runLlmAnalyzer(effectiveFeatures);
  const mlResult = await runLightweightModel(effectiveFeatures);
  const urlOnlySample = isSparseSample(effectiveFeatures);
  const modelContributions =
    effectiveFeatures.source === "email"
      ? {
          rule: 0.4,
          llm: 0.45,
          urlRisk: 0.05,
          ml: 0.1
        }
      : urlOnlySample
        ? {
            rule: 0.45,
            llm: 0.12,
            urlRisk: 0.23,
            ml: 0.2
          }
        : {
            rule: 0.27,
            llm: 0.35,
            urlRisk: 0.18,
            ml: 0.2
          };
  const combinedScore = Math.round(
    Math.max(
      ruleResult.score * modelContributions.rule +
        llmResult.score * modelContributions.llm +
        urlRisk.score * modelContributions.urlRisk +
        mlResult.score * modelContributions.ml,
      urlRisk.score * (urlOnlySample ? 1.0 : 0.9)
    )
  );
  const interventionText =
    effectiveFeatures.source === "email"
      ? `${effectiveFeatures.title ?? ""} ${effectiveFeatures.visibleText ?? ""} ${effectiveFeatures.email?.subject ?? ""} ${effectiveFeatures.email?.bodyText ?? ""}`
      : `${effectiveFeatures.title ?? ""} ${effectiveFeatures.visibleText ?? ""}`;
  const intervention = detectInterventionRisk({
    source: effectiveFeatures.source,
    text: interventionText
  });
  const scoreWithIntervention = Math.max(combinedScore, Math.min(100, combinedScore + Math.round(intervention.score * 0.45)));
  const calibrationApplied = applyUserCalibration({
    baseScore: scoreWithIntervention,
    attackType: llmResult.attackType,
    profile: calibration,
    intervention
  });
  const initialRouterDecision = routeDecision(calibrationApplied.score, intervention.severity === "high");

  const agentResult =
    initialRouterDecision === "escalate"
      ? await runAgentAnalyzer(effectiveFeatures, {
          baseScore: calibrationApplied.score,
          attackType: llmResult.attackType
        })
      : null;

  const finalAttackType = agentResult?.attackType ?? llmResult.attackType;
  const finalScoreRaw = agentResult?.score ?? calibrationApplied.score;
  const calibratedFinal = agentResult
    ? applyUserCalibration({
        baseScore: finalScoreRaw,
        attackType: finalAttackType,
        profile: calibration,
        intervention
      })
    : calibrationApplied;
  const finalScore = calibratedFinal.score;
  const finalDecision = agentResult ? resolveFinalDecision(finalScore) : initialRouterDecision;
  const finalReasons = agentResult
    ? [...new Set([...mergeReasons([...ruleResult.reasons, ...urlRisk.reasons], llmResult.reasons), ...agentResult.reasons])]
    : mergeReasons([...ruleResult.reasons, ...urlRisk.reasons], llmResult.reasons);
  const finalConfidence = agentResult
    ? Math.max(llmResult.confidence, agentResult.confidence)
    : llmResult.confidence;

  return {
    source: effectiveFeatures.source,
    riskLevel: scoreToRiskLevel(finalScore),
    score: finalScore,
    reasons: finalReasons,
    confidence: Math.max(finalConfidence, mlResult.confidence * 0.75),
    attackType: finalAttackType,
    recommendedAction: finalDecision,
    needsAgent: Boolean(agentResult),
    analyzedAt: new Date().toISOString(),
    provider: llmResult.provider,
    intervention,
    calibration: calibratedFinal.evidence,
    agent: agentResult ?? undefined,
    enrichment: enrichment.meta.used
      ? {
          liveDomUsed: true,
          cacheHit: enrichment.meta.cacheHit
        }
      : {
          liveDomUsed: false,
          skippedReason: enrichment.meta.reason
        },
    evidence: {
      ruleScore: Math.max(ruleResult.score, urlRisk.score),
      llmScore: llmResult.score,
      mlScore: mlResult.score,
      urlRiskScore: urlRisk.score,
      interventionScore: intervention.score,
      baseCombinedScore: combinedScore,
      calibratedScore: finalScore,
      routerDecision: finalDecision,
      agentScore: agentResult?.score,
      initialRouterDecision,
      enrichment: {
        liveDomUsed: enrichment.meta.used,
        skippedReason: enrichment.meta.reason,
        cacheHit: enrichment.meta.cacheHit
      },
      modelContributions,
      modelVersion: mlResult.version
    }
  };
}
