import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const REPORT_PATH = path.join(ROOT, "data/processed/external-feeds-test-report.json");
const OUTPUT_PATH = path.join(ROOT, "data/processed/external-threshold-suggestion.json");

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function quantile(sortedValues, q) {
  if (sortedValues.length === 0) {
    return 0;
  }
  if (sortedValues.length === 1) {
    return sortedValues[0];
  }
  const position = clamp(q, 0, 1) * (sortedValues.length - 1);
  const lowerIndex = Math.floor(position);
  const upperIndex = Math.ceil(position);
  if (lowerIndex === upperIndex) {
    return sortedValues[lowerIndex];
  }
  const ratio = position - lowerIndex;
  return sortedValues[lowerIndex] * (1 - ratio) + sortedValues[upperIndex] * ratio;
}

function toAction(score, warnThreshold, blockThreshold) {
  if (score >= blockThreshold) {
    return "block";
  }
  if (score >= warnThreshold) {
    return "warn";
  }
  return "allow";
}

async function main() {
  const raw = await readFile(REPORT_PATH, "utf8");
  const report = JSON.parse(raw);
  const records = Array.isArray(report?.samples) ? report.samples : [];
  const scored = records
    .map((record) => Number(record?.result?.score))
    .filter((score) => Number.isFinite(score))
    .sort((a, b) => a - b);

  if (scored.length === 0) {
    throw new Error("No scored samples available in external-feeds report.");
  }

  const p70 = quantile(scored, 0.7);
  const p85 = quantile(scored, 0.85);
  const p90 = quantile(scored, 0.9);
  const p95 = quantile(scored, 0.95);

  const warnThreshold = clamp(Math.round((p70 + p85) / 2), 22, 60);
  const blockThreshold = clamp(Math.max(warnThreshold + 12, Math.round((p90 + p95) / 2)), 42, 88);

  const actionDistribution = { allow: 0, warn: 0, block: 0 };
  for (const score of scored) {
    const action = toAction(score, warnThreshold, blockThreshold);
    actionDistribution[action] += 1;
  }

  const suggestion = {
    generatedAt: new Date().toISOString(),
    sourceReport: REPORT_PATH,
    sampleCount: scored.length,
    quantiles: {
      p70: Number(p70.toFixed(2)),
      p85: Number(p85.toFixed(2)),
      p90: Number(p90.toFixed(2)),
      p95: Number(p95.toFixed(2))
    },
    suggestedThresholds: {
      warnThreshold,
      blockThreshold
    },
    impliedActionDistribution: actionDistribution
  };

  await writeFile(OUTPUT_PATH, JSON.stringify(suggestion, null, 2));
  console.log(
    JSON.stringify(
      {
        ok: true,
        output: OUTPUT_PATH,
        suggestedThresholds: suggestion.suggestedThresholds,
        impliedActionDistribution: actionDistribution
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
