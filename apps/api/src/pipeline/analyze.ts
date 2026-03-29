import { runAgentAnalyzer } from "./agent-analyzer.js";
import { runLlmAnalyzer } from "./llm-analyzer.js";
import { routeDecision } from "./router.js";
import { runRuleEngine } from "./rule-engine.js";
import type { AnalysisResult, PageFeatures, RiskLevel } from "../types/analysis.js";

function scoreToRiskLevel(score: number): RiskLevel {
  if (score >= 70) {
    return "high";
  }

  if (score >= 40) {
    return "medium";
  }

  return "low";
}

function mergeReasons(ruleReasons: string[], llmReasons: string[]): string[] {
  return [...new Set([...ruleReasons, ...llmReasons])];
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

export async function analyzeFeatures(features: PageFeatures): Promise<AnalysisResult> {
  const ruleResult = runRuleEngine(features);
  const llmResult = await runLlmAnalyzer(features);
  const urlOnlySample = !String(features.visibleText || "").trim() && (features.forms.total ?? 0) === 0 && (features.dom.iframeCount ?? 0) === 0;
  const combinedScore = urlOnlySample
    ? Math.round(ruleResult.score * 0.75 + llmResult.score * 0.25)
    : Math.round(ruleResult.score * 0.4 + llmResult.score * 0.6);
  const initialRouterDecision = routeDecision(combinedScore);

  const agentResult =
    initialRouterDecision === "escalate"
      ? await runAgentAnalyzer(features, {
          baseScore: combinedScore,
          attackType: llmResult.attackType
        })
      : null;

  const finalScore = agentResult?.score ?? combinedScore;
  const finalDecision = agentResult ? resolveFinalDecision(finalScore) : initialRouterDecision;
  const finalReasons = agentResult
    ? [...new Set([...mergeReasons(ruleResult.reasons, llmResult.reasons), ...agentResult.reasons])]
    : mergeReasons(ruleResult.reasons, llmResult.reasons);
  const finalAttackType = agentResult?.attackType ?? llmResult.attackType;
  const finalConfidence = agentResult
    ? Math.max(llmResult.confidence, agentResult.confidence)
    : llmResult.confidence;

  return {
    source: features.source,
    riskLevel: scoreToRiskLevel(finalScore),
    score: finalScore,
    reasons: finalReasons,
    confidence: finalConfidence,
    attackType: finalAttackType,
    recommendedAction: finalDecision,
    needsAgent: Boolean(agentResult),
    analyzedAt: new Date().toISOString(),
    provider: llmResult.provider,
    agent: agentResult ?? undefined,
    evidence: {
      ruleScore: ruleResult.score,
      llmScore: llmResult.score,
      routerDecision: finalDecision,
      agentScore: agentResult?.score,
      initialRouterDecision
    }
  };
}
