import type { AnalysisResult, AttackType, Decision, RiskLevel, TextAnalysisInput, UserCalibrationProfile } from "../types/analysis.js";
import { applyUserCalibration } from "./calibration.js";
import { detectInterventionRisk } from "./intervention.js";
import { runTextLlmAnalyzer } from "./llm-analyzer.js";

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
  let keywordScore = 0;
  let heuristicScore = 0;
  const reasons: string[] = [];
  let attackType: AttackType = "unknown";

  // ── Static keyword analysis (TW-specific rules) ───────────────────────────

  if (/驗證|登入|登錄|密碼|帳戶|帳號|身分驗證|重新登入|確認帳號|帳戶異常/i.test(text)) {
    keywordScore += 26;
    reasons.push("Message contains account verification or credential-related language.");
    attackType = "credential_harvest";
  }

  if (/立即|緊急|停用|停權|異常登入|確認|補件|逾期|失敗|重新啟用|點擊連結|限時/i.test(text)) {
    keywordScore += 18;
    reasons.push("Message uses urgency or pressure language.");
  }

  if (/解除分期|重複扣款|付款|繳費|匯款|轉帳|銀行|信用卡|電子支付|街口|全支付|全盈\+pay|退款/i.test(text)) {
    keywordScore += 22;
    reasons.push("Message references payment, transfer, or refund-related action.");
    attackType = attackType === "credential_harvest" ? attackType : "payment_fraud";
  }

  if (/包裹|物流|配送|宅配|取貨|超商|黑貓|新竹物流|宅配通/i.test(text)) {
    keywordScore += 18;
    reasons.push("Message resembles a fake logistics or delivery notice.");
    attackType = attackType === "unknown" ? "payment_fraud" : attackType;
  }

  if (/中獎|領獎|抽獎|獎金|贈品/i.test(text)) {
    keywordScore += 16;
    reasons.push("Message resembles a prize or giveaway scam.");
    attackType = attackType === "unknown" ? "payment_fraud" : attackType;
  }

  if (/飆股|投資群|帶單|保證獲利|穩賺不賠|虛擬貨幣|加密貨幣|入金|出金|老師報牌|投顧/i.test(text)) {
    keywordScore += 28;
    reasons.push("Message contains investment-scam language.");
    attackType = "investment_scam";
  }

  if (/客服|專員|解除分期|誤設分期|訂單錯誤|重複下單|訂單異常|客服中心|來電處理/i.test(text)) {
    keywordScore += 24;
    reasons.push("Message resembles fake customer-service or installment scam language.");
    attackType = "customer_service_scam";
  }

  if (/監理站|交通罰單|罰單|稅務|國稅局|健保署|勞保局|法院|地檢署|警政署|政府通知/i.test(text)) {
    keywordScore += 22;
    reasons.push("Message resembles fake government, police, court, or tax notice language.");
    attackType = "government_impersonation";
  }

  if (/掃碼|掃描qr code|qr code|條碼繳費|行動條碼|掃碼登入|掃碼付款/i.test(text)) {
    keywordScore += 18;
    reasons.push("Message tries to induce QR-code-based login or payment behavior.");
  }

  // ── Heuristic patterns (high-signal social engineering behaviors) ──────────

  if (/atm|otp|驗證碼|一次性密碼|解除分期|匯款|轉帳|不要掛電話/i.test(text)) {
    heuristicScore += 30;
    reasons.push("Message content matches high-risk social-engineering transfer behavior.");
    attackType = attackType === "unknown" ? "phone_scam" : attackType;
  }

  if (/加line|加賴|私訊我|投資群|老師帶單|保證獲利/i.test(text)) {
    heuristicScore += 28;
    reasons.push("Message tries to move the victim into a higher-control scam flow.");
    attackType = attackType === "unknown" ? "investment_scam" : attackType;
  }

  if (/寶貝|想你|見面|借我|幫我匯|幫我轉/i.test(text)) {
    heuristicScore += 18;
    reasons.push("Message contains romance-scam or trust-building transfer cues.");
    attackType = attackType === "unknown" ? "romance_scam" : attackType;
  }

  if (/網拍|二手|拍賣|facebook market|旋轉拍賣|賣貨便|交貨便|私下交易|跳過平台|改line/i.test(text)) {
    heuristicScore += 20;
    reasons.push("Message resembles off-platform transaction scam patterns common in Taiwan.");
    attackType = attackType === "unknown" ? "payment_fraud" : attackType;
  }

  if (/遊戲點數|買點數|購買點數|steam卡|apple禮品卡|google play卡|超商代碼繳費/i.test(text)) {
    heuristicScore += 26;
    reasons.push("Message requests gift cards or game points, a common transfer fraud pattern.");
    attackType = attackType === "unknown" ? "phone_scam" : attackType;
  }

  if (/監管帳戶|安全帳戶|資金保全|凍結帳戶|配合調查|地檢署|警政署|刑事局/i.test(twText)) {
    heuristicScore += 24;
    reasons.push("Message includes fake law-enforcement or judicial transfer narratives.");
    attackType = attackType === "unknown" ? "government_impersonation" : attackType;
  }

  // ── Static combined score ─────────────────────────────────────────────────

  const staticScore = Math.max(0, Math.min(100, Math.round(keywordScore * 0.55 + heuristicScore * 0.45)));

  // ── LLM analysis ──────────────────────────────────────────────────────────
  //
  // When LLM is not configured (provider === "fallback"), runTextLlmAnalyzer
  // returns a zero-score placeholder and behavior is identical to the static-only path.
  // When LLM is available, it captures patterns the keyword list misses:
  //   - English-language phishing not in TW keyword list
  //   - Paraphrased scam language that evades keyword matching
  //   - Emerging terminology (AI/DeFi investment scams, new brand impersonation)

  const llmResult = await runTextLlmAnalyzer(input);

  const blendedScore =
    llmResult.provider !== "fallback"
      ? Math.min(100, Math.round(staticScore * 0.4 + llmResult.score * 0.6))
      : staticScore;

  // Prefer LLM's attack type only when static analysis couldn't determine one
  const effectiveAttackType =
    attackType === "unknown" && llmResult.attackType !== "unknown" ? llmResult.attackType : attackType;

  const mergedReasons = [...new Set([...reasons, ...llmResult.reasons])];

  // ── Intervention + calibration ────────────────────────────────────────────

  const intervention = detectInterventionRisk({
    source: "text",
    text: `${input.title ?? ""} ${input.text}`
  });

  const riskAdjustedScore = Math.max(
    blendedScore,
    Math.min(100, blendedScore + Math.round(intervention.score * 0.4))
  );

  const calibration = applyUserCalibration({
    baseScore: riskAdjustedScore,
    attackType: effectiveAttackType,
    profile: options?.calibration,
    intervention
  });

  const combinedScore = calibration.score;

  return {
    source: "text",
    riskLevel: scoreToRiskLevel(combinedScore),
    score: combinedScore,
    reasons: mergedReasons.length > 0 ? mergedReasons : ["No strong scam signal detected in the provided text."],
    confidence: combinedScore >= 70 ? 0.82 : combinedScore >= 40 ? 0.68 : 0.56,
    attackType: effectiveAttackType,
    recommendedAction: scoreToDecision(combinedScore),
    needsAgent: false,
    analyzedAt: new Date().toISOString(),
    provider: llmResult.provider,
    intervention,
    calibration: calibration.evidence,
    evidence: {
      ruleScore: keywordScore,
      llmScore: llmResult.score,
      interventionScore: intervention.score,
      baseCombinedScore: blendedScore,
      calibratedScore: combinedScore,
      routerDecision: scoreToDecision(combinedScore)
    }
  };
}
