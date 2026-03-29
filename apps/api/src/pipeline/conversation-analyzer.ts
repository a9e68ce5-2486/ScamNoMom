import { hasKeywordMatch } from "../config/tw-scam-keywords.js";
import type {
  AnalysisResult,
  AttackType,
  ConversationAnalysisInput,
  ConversationTurn,
  Decision,
  RiskLevel,
  UserCalibrationProfile
} from "../types/analysis.js";
import { applyUserCalibration } from "./calibration.js";
import { detectInterventionRisk } from "./intervention.js";

function scoreToRiskLevel(score: number): RiskLevel {
  if (score >= 70) {
    return "high";
  }
  if (score >= 40) {
    return "medium";
  }
  return "low";
}

function scoreToDecision(score: number): Decision {
  if (score >= 70) {
    return "block";
  }
  if (score >= 40) {
    return "warn";
  }
  return "allow";
}

function normalizeTurns(turns: ConversationTurn[]): ConversationTurn[] {
  return turns
    .map((turn) => ({
      role: turn.role,
      text: String(turn.text || "").trim().slice(0, 2000),
      timestamp: turn.timestamp
    }))
    .filter((turn) => turn.text.length > 0)
    .slice(-24);
}

function inferAttackType(text: string, counters: Record<string, number>): AttackType {
  if (counters.investment > 0) {
    return "investment_scam";
  }
  if (counters.customerService > 0 || counters.phone > 0) {
    return "customer_service_scam";
  }
  if (counters.government > 0) {
    return "government_impersonation";
  }
  if (counters.payment > 0) {
    return "payment_fraud";
  }
  if (counters.credential > 0) {
    return "credential_harvest";
  }
  if (/戀愛|寶貝|見面|借我|匯給我/i.test(text)) {
    return "romance_scam";
  }
  return "unknown";
}

function sequenceRiskScore(turns: ConversationTurn[]): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  const merged = turns.map((turn) => `[${turn.role}] ${turn.text}`).join("\n");
  const lower = merged.toLowerCase();
  let score = 0;

  const counters = {
    credential: hasKeywordMatch(lower, "credential") ? 1 : 0,
    urgency: hasKeywordMatch(lower, "urgency") ? 1 : 0,
    payment: hasKeywordMatch(lower, "payment") || hasKeywordMatch(lower, "logistics") ? 1 : 0,
    investment: hasKeywordMatch(lower, "investment") ? 1 : 0,
    customerService: hasKeywordMatch(lower, "customerService") ? 1 : 0,
    government: hasKeywordMatch(lower, "government") ? 1 : 0,
    phone: /不要掛電話|客服專員|解除分期|atm|驗證碼|otp/i.test(merged) ? 1 : 0
  };

  if (counters.credential) {
    score += 24;
    reasons.push("Conversation includes account verification or credential collection cues.");
  }
  if (counters.urgency) {
    score += 18;
    reasons.push("Conversation uses urgency pressure, common in scam scripts.");
  }
  if (counters.payment) {
    score += 20;
    reasons.push("Conversation requests payment/transfer-like action.");
  }
  if (counters.investment) {
    score += 24;
    reasons.push("Conversation shows investment scam language patterns.");
  }
  if (counters.customerService || counters.phone) {
    score += 24;
    reasons.push("Conversation resembles customer-service / call-center fraud script.");
  }
  if (counters.government) {
    score += 18;
    reasons.push("Conversation includes government or legal intimidation cues.");
  }

  const moveOffPlatform = /(加line|加賴|私訊|改到telegram|改到line|跳過平台)/i.test(merged);
  if (moveOffPlatform) {
    score += 16;
    reasons.push("Counterparty tries to move communication off platform.");
  }

  const lateTurns = turns.slice(-3).map((turn) => turn.text).join(" ");
  const latePressure = /(現在|立刻|馬上|today|right now|立即|5分鐘內|10分鐘內)/i.test(lateTurns);
  const lateMoney = /(匯款|轉帳|付款|otp|驗證碼|信用卡|銀行帳號)/i.test(lateTurns);
  if (latePressure && lateMoney) {
    score += 16;
    reasons.push("Latest turns escalate into urgent financial action.");
  }

  const repeatedAsks = turns
    .filter((turn) => turn.role === "counterparty")
    .map((turn) => turn.text)
    .join(" ");
  if ((repeatedAsks.match(/(匯款|轉帳|驗證碼|otp|帳號|密碼)/gi) || []).length >= 3) {
    score += 14;
    reasons.push("Repeated requests for sensitive actions detected.");
  }

  return {
    score: Math.max(0, Math.min(100, Math.round(score))),
    reasons
  };
}

export async function analyzeConversation(
  input: ConversationAnalysisInput,
  calibrationProfile?: UserCalibrationProfile
): Promise<AnalysisResult> {
  const turns = normalizeTurns(input.turns || []);
  const sequence = sequenceRiskScore(turns);
  const joinedText = turns.map((turn) => turn.text).join(" ");
  const attackType = inferAttackType(joinedText, {
    credential: hasKeywordMatch(joinedText, "credential") ? 1 : 0,
    urgency: hasKeywordMatch(joinedText, "urgency") ? 1 : 0,
    payment: hasKeywordMatch(joinedText, "payment") ? 1 : 0,
    investment: hasKeywordMatch(joinedText, "investment") ? 1 : 0,
    customerService: hasKeywordMatch(joinedText, "customerService") ? 1 : 0,
    government: hasKeywordMatch(joinedText, "government") ? 1 : 0,
    phone: /atm|otp|驗證碼|一次性密碼/i.test(joinedText) ? 1 : 0
  });
  const intervention = detectInterventionRisk({
    text: joinedText,
    source: "conversation"
  });

  const baseScore = Math.max(sequence.score, Math.round(sequence.score * 0.75 + intervention.score * 0.25));
  const calibrated = applyUserCalibration({
    baseScore,
    attackType,
    profile: calibrationProfile,
    intervention
  });

  const finalReasons = [...sequence.reasons];
  if (intervention.reasons.length > 0) {
    finalReasons.push(...intervention.reasons.slice(0, 2));
  }
  if (turns.length >= 4) {
    finalReasons.push("Multi-turn sequence analysis applied.");
  }

  return {
    source: "conversation",
    riskLevel: scoreToRiskLevel(calibrated.score),
    score: calibrated.score,
    reasons: finalReasons.length ? [...new Set(finalReasons)] : ["No strong scam signal detected in the conversation."],
    confidence: calibrated.score >= 70 ? 0.85 : calibrated.score >= 40 ? 0.7 : 0.58,
    attackType,
    recommendedAction: scoreToDecision(calibrated.score),
    needsAgent: false,
    analyzedAt: new Date().toISOString(),
    provider: "fallback",
    intervention,
    calibration: calibrated.evidence,
    evidence: {
      ruleScore: sequence.score,
      llmScore: sequence.score,
      interventionScore: intervention.score,
      baseCombinedScore: baseScore,
      calibratedScore: calibrated.score,
      routerDecision: scoreToDecision(calibrated.score)
    }
  };
}
