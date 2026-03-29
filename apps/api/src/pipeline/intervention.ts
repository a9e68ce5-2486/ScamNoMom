import type { InterventionResult, PageFeatures } from "../types/analysis.js";

export interface InterventionInput {
  source: "web" | "email" | "text" | "conversation";
  text?: string;
  title?: string;
  visibleText?: string;
  email?: PageFeatures["email"];
}

const OTP_PATTERN = /(otp|一次性密碼|驗證碼|動態密碼|簡訊碼|security\s*code)/i;
const OTP_URGENCY_PATTERN = /(立即|馬上|立刻|5分鐘|10分鐘|不要掛電話|逾時|expire|expired|now)/i;
const TRANSFER_PATTERN = /(匯款|轉帳|轉賬|付款|入金|匯入|atm|網銀|internet banking|wire transfer)/i;
const CARD_BANK_PATTERN =
  /(信用卡|卡號|cvv|安全碼|有效期限|銀行帳號|帳戶號碼|提款卡|身分證字號|印鑑|存摺|網銀密碼)/i;
const INSTALLMENT_PATTERN = /(解除分期|誤設分期|重複扣款|客服專員|平台客服|訂單異常|錯誤訂單)/i;
const REMOTE_CONTROL_PATTERN = /(遠端|anydesk|teamviewer|螢幕分享|install app|下載app並操作)/i;
const OFF_PLATFORM_PATTERN = /(加line|加賴|私訊|跳過平台|私下交易|改用telegram|改用whatsapp)/i;

function clamp(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function uniq<T>(values: T[]): T[] {
  return [...new Set(values)];
}

function toInterventionText(input: InterventionInput): string {
  if (input.text) {
    return String(input.text || "");
  }
  return `${input.title || ""} ${input.visibleText || ""} ${input.email?.subject || ""} ${input.email?.bodyText || ""}`.trim();
}

export function detectInterventionRisk(input: InterventionInput): InterventionResult {
  const text = toInterventionText(input);
  const reasons: string[] = [];
  const actions: string[] = [];

  const signals = {
    otpRequest: OTP_PATTERN.test(text),
    otpUrgency: OTP_URGENCY_PATTERN.test(text),
    transferRequest: TRANSFER_PATTERN.test(text),
    cardOrBankDataRequest: CARD_BANK_PATTERN.test(text),
    installmentScamCue: INSTALLMENT_PATTERN.test(text),
    remoteControlRequest: REMOTE_CONTROL_PATTERN.test(text),
    offPlatformMove: OFF_PLATFORM_PATTERN.test(text)
  };

  let score = 0;

  if (signals.otpRequest) {
    score += 26;
    reasons.push("Detected OTP/security-code request behavior.");
    actions.push("Do not provide OTP or verification code to anyone.");
  }
  if (signals.otpUrgency) {
    score += 14;
    reasons.push("Detected urgency language around verification or account action.");
    actions.push("Pause immediately and verify through official channels.");
  }
  if (signals.transferRequest) {
    score += 24;
    reasons.push("Detected transfer/payment instruction pattern.");
    actions.push("Do not transfer funds before calling official support.");
  }
  if (signals.cardOrBankDataRequest) {
    score += 18;
    reasons.push("Detected card/bank sensitive data collection pattern.");
    actions.push("Do not share card number, CVV, bank account, or ID data.");
  }
  if (signals.installmentScamCue) {
    score += 20;
    reasons.push("Detected Taiwan-style installment/payment-correction scam script.");
    actions.push("For 'installment error' claims, hang up and contact official support yourself.");
  }
  if (signals.remoteControlRequest) {
    score += 24;
    reasons.push("Detected remote-control or app-install coercion pattern.");
    actions.push("Do not install remote-control apps or share your screen.");
  }
  if (signals.offPlatformMove) {
    score += 12;
    reasons.push("Detected off-platform migration attempt.");
    actions.push("Keep communication and payment inside official platform flows.");
  }

  if (signals.transferRequest && signals.otpRequest) {
    score += 12;
    reasons.push("Transfer and OTP requests co-occur, indicating high-risk account takeover flow.");
    actions.push("Contact your bank fraud hotline and 165 anti-fraud helpline immediately.");
  }

  const normalizedScore = clamp(score);
  const riskTransactionFlow = normalizedScore >= 35 || (signals.transferRequest && signals.otpRequest);
  const severity: InterventionResult["severity"] =
    normalizedScore >= 65 ? "high" : normalizedScore >= 35 ? "caution" : "none";

  return {
    score: normalizedScore,
    riskTransactionFlow,
    severity,
    reasons: uniq(reasons),
    suggestedActions: uniq(actions).slice(0, 5),
    signals
  };
}
