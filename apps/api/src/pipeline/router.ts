import type { Decision } from "../types/analysis.js";

export function routeDecision(score: number, forceEscalate = false): Decision {
  if (score >= 70) {
    return "block";
  }

  if (forceEscalate) {
    return "escalate";
  }

  if (score >= 40) {
    return "escalate";
  }

  return "allow";
}
