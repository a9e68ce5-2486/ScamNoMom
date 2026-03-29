import type { AttackType, CalibrationEvidence, InterventionResult, UserCalibrationProfile } from "../types/analysis.js";

interface NormalizedCalibrationProfile {
  riskTolerance: "low" | "balanced" | "high";
  sensitivityBoost: number;
  falsePositiveRateHint: number;
  highValueProtection: boolean;
}

export interface CalibrationApplyInput {
  baseScore: number;
  attackType: AttackType;
  profile?: UserCalibrationProfile;
  intervention?: InterventionResult;
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function normalizeProfile(profile?: UserCalibrationProfile): NormalizedCalibrationProfile {
  const riskTolerance = profile?.riskTolerance === "low" || profile?.riskTolerance === "high" ? profile.riskTolerance : "balanced";
  return {
    riskTolerance,
    sensitivityBoost: clamp(Number(profile?.sensitivityBoost ?? 0), -20, 20),
    falsePositiveRateHint: clamp(Number(profile?.falsePositiveRateHint ?? 0.15), 0, 0.8),
    highValueProtection: profile?.highValueProtection !== false
  };
}

export function applyUserCalibration(input: CalibrationApplyInput): { score: number; evidence: CalibrationEvidence } {
  const profile = normalizeProfile(input.profile);
  const notes: string[] = [];
  let scoreDelta = 0;

  if (profile.riskTolerance === "low") {
    scoreDelta += 6;
    notes.push("Risk tolerance low: increased conservative protection.");
  } else if (profile.riskTolerance === "high") {
    scoreDelta -= 6;
    notes.push("Risk tolerance high: reduced alert aggressiveness.");
  }

  if (profile.sensitivityBoost !== 0) {
    scoreDelta += profile.sensitivityBoost;
    notes.push(`Sensitivity boost applied: ${profile.sensitivityBoost > 0 ? "+" : ""}${profile.sensitivityBoost.toFixed(1)}.`);
  }

  const fprDelta = clamp((0.18 - profile.falsePositiveRateHint) * 22, -8, 8);
  if (Math.abs(fprDelta) >= 0.25) {
    scoreDelta += fprDelta;
    notes.push(`False-positive hint adjustment: ${fprDelta > 0 ? "+" : ""}${fprDelta.toFixed(1)}.`);
  }

  if (profile.highValueProtection) {
    const isCredentialOrMoney = ["credential_harvest", "payment_fraud", "phone_scam", "customer_service_scam"].includes(input.attackType);
    if (isCredentialOrMoney) {
      scoreDelta += 4;
      notes.push("High-value protection: protected flow attack type boost.");
    }
    if (input.intervention?.riskTransactionFlow) {
      scoreDelta += 8;
      notes.push("High-value protection: intervention detected OTP/transfer flow.");
    }
  }

  const calibrated = clamp(Math.round(input.baseScore + scoreDelta), 0, 100);
  return {
    score: calibrated,
    evidence: {
      applied: scoreDelta !== 0,
      scoreDelta: Number(scoreDelta.toFixed(2)),
      profile,
      notes
    }
  };
}
