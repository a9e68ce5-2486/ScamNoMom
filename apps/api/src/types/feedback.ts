import type { AnalysisResult, PageFeatures } from "./analysis.js";

export type FeedbackLabel = "safe" | "phishing";

export interface FeedbackRecord {
  id: string;
  createdAt: string;
  label: FeedbackLabel;
  notes?: string;
  analysis: AnalysisResult;
  features: PageFeatures;
}
