import { hasKeywordMatch } from "../config/tw-scam-keywords.js";
import type { AnalysisResult, AttackType, Decision, RiskLevel, TextAnalysisInput, UserCalibrationProfile } from "../types/analysis.js";
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

export async function analyzeText(
  input: TextAnalysisInput,
  options?: { calibration?: UserCalibrationProfile }
): Promise<AnalysisResult> {
  const text = `${input.title ?? ""} ${input.text}`.toLowerCase();
  const twText = `${input.title ?? ""} ${input.text}`;
  let ruleScore = 0;
  let llmScore = 0;
  const reasons: string[] = [];
  let attackType: AttackType = "unknown";

  if (hasKeywordMatch(text, "credential")) {
    ruleScore += 26;
    reasons.push("Message contains account verification or credential-related language.");
    attackType = "credential_harvest";
  }

  if (hasKeywordMatch(text, "urgency")) {
    ruleScore += 18;
    reasons.push("Message uses urgency or pressure language.");
  }

  if (hasKeywordMatch(text, "payment")) {
    ruleScore += 22;
    reasons.push("Message references payment, transfer, or refund-related action.");
    attackType = attackType === "credential_harvest" ? attackType : "payment_fraud";
  }

  if (hasKeywordMatch(text, "logistics")) {
    ruleScore += 18;
    reasons.push("Message resembles a fake logistics or delivery notice.");
    attackType = attackType === "unknown" ? "payment_fraud" : attackType;
  }

  if (hasKeywordMatch(text, "prize")) {
    ruleScore += 16;
    reasons.push("Message resembles a prize or giveaway scam.");
    attackType = attackType === "unknown" ? "payment_fraud" : attackType;
  }

  if (hasKeywordMatch(text, "investment")) {
    ruleScore += 28;
    reasons.push("Message contains investment-scam language.");
    attackType = "investment_scam";
  }

  if (hasKeywordMatch(text, "customerService")) {
    ruleScore += 24;
    reasons.push("Message resembles fake customer-service or installment scam language.");
    attackType = "customer_service_scam";
  }

  if (hasKeywordMatch(text, "government")) {
    ruleScore += 22;
    reasons.push("Message resembles fake government, police, court, or tax notice language.");
    attackType = "government_impersonation";
  }

  if (hasKeywordMatch(text, "qr")) {
    ruleScore += 18;
    reasons.push("Message tries to induce QR-code-based login or payment behavior.");
  }

  if (/atm|otp|驗證碼|一次性密碼|解除分期|匯款|轉帳|不要掛電話/i.test(text)) {
    llmScore += 30;
    reasons.push("Message content matches high-risk social-engineering transfer behavior.");
    attackType = attackType === "unknown" ? "phone_scam" : attackType;
  }

  if (/加line|加賴|私訊我|投資群|老師帶單|保證獲利/i.test(text)) {
    llmScore += 28;
    reasons.push("Message tries to move the victim into a higher-control scam flow.");
    attackType = attackType === "unknown" ? "investment_scam" : attackType;
  }

  if (/寶貝|想你|見面|借我|幫我匯|幫我轉/i.test(text)) {
    llmScore += 18;
    reasons.push("Message contains romance-scam or trust-building transfer cues.");
    attackType = attackType === "unknown" ? "romance_scam" : attackType;
  }

  if (/網拍|二手|拍賣|facebook market|旋轉拍賣|賣貨便|交貨便|私下交易|跳過平台|改line/i.test(text)) {
    llmScore += 20;
    reasons.push("Message resembles off-platform transaction scam patterns common in Taiwan.");
    attackType = attackType === "unknown" ? "payment_fraud" : attackType;
  }

  if (/遊戲點數|買點數|購買點數|steam卡|apple禮品卡|google play卡|超商代碼繳費/i.test(text)) {
    llmScore += 26;
    reasons.push("Message requests gift cards or game points, a common transfer fraud pattern.");
    attackType = attackType === "unknown" ? "phone_scam" : attackType;
  }

  if (/監管帳戶|安全帳戶|資金保全|凍結帳戶|配合調查|地檢署|警政署|刑事局/i.test(twText)) {
    llmScore += 24;
    reasons.push("Message includes fake law-enforcement or judicial transfer narratives.");
    attackType = attackType === "unknown" ? "government_impersonation" : attackType;
  }

  const baseScore = Math.max(0, Math.min(100, Math.round(ruleScore * 0.55 + llmScore * 0.45)));
  const intervention = detectInterventionRisk({
    source: "text",
    text: `${input.title ?? ""} ${input.text}`
  });
  const riskAdjustedScore = Math.max(baseScore, Math.min(100, baseScore + Math.round(intervention.score * 0.4)));
  const calibration = applyUserCalibration({
    baseScore: riskAdjustedScore,
    attackType,
    profile: options?.calibration,
    intervention
  });
  const combinedScore = calibration.score;

  return {
    source: "text",
    riskLevel: scoreToRiskLevel(combinedScore),
    score: combinedScore,
    reasons: reasons.length > 0 ? reasons : ["No strong scam signal detected in the provided text."],
    confidence: combinedScore >= 70 ? 0.82 : combinedScore >= 40 ? 0.68 : 0.56,
    attackType,
    recommendedAction: scoreToDecision(combinedScore),
    needsAgent: false,
    analyzedAt: new Date().toISOString(),
    provider: "fallback",
    intervention,
    calibration: calibration.evidence,
    evidence: {
      ruleScore,
      llmScore,
      interventionScore: intervention.score,
      baseCombinedScore: baseScore,
      calibratedScore: combinedScore,
      routerDecision: scoreToDecision(combinedScore)
    }
  };
}
