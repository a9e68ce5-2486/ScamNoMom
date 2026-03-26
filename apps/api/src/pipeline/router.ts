import type { Decision } from "../types/analysis.js";

export function routeDecision(score: number): Decision {
  if (score >= 70) {
    return "block";
  }

  if (score >= 40) {
    return "escalate";
  }

  return "allow";
}
