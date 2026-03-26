import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const FEEDBACK_PATH = path.join(ROOT, "apps/api/data/feedback.json");
const OUTPUT_DIR = path.join(ROOT, "data/processed");
const JSON_REPORT_PATH = path.join(OUTPUT_DIR, "evaluation-report.json");
const MD_REPORT_PATH = path.join(OUTPUT_DIR, "evaluation-report.md");

function safeDivide(numerator, denominator) {
  if (!denominator) {
    return 0;
  }

  return numerator / denominator;
}

function round(value) {
  return Number(value.toFixed(4));
}

function emptyMetrics() {
  return {
    total: 0,
    tp: 0,
    tn: 0,
    fp: 0,
    fn: 0,
    accuracy: 0,
    precision: 0,
    recall: 0,
    f1: 0,
    falsePositiveRate: 0,
    falseNegativeRate: 0
  };
}

function buildMetrics(records) {
  if (records.length === 0) {
    return emptyMetrics();
  }

  let tp = 0;
  let tn = 0;
  let fp = 0;
  let fn = 0;

  for (const record of records) {
    if (record.actual === "phishing" && record.predicted === "phishing") {
      tp += 1;
    } else if (record.actual === "safe" && record.predicted === "safe") {
      tn += 1;
    } else if (record.actual === "safe" && record.predicted === "phishing") {
      fp += 1;
    } else if (record.actual === "phishing" && record.predicted === "safe") {
      fn += 1;
    }
  }

  const accuracy = safeDivide(tp + tn, records.length);
  const precision = safeDivide(tp, tp + fp);
  const recall = safeDivide(tp, tp + fn);
  const f1 = safeDivide(2 * precision * recall, precision + recall);
  const falsePositiveRate = safeDivide(fp, fp + tn);
  const falseNegativeRate = safeDivide(fn, fn + tp);

  return {
    total: records.length,
    tp,
    tn,
    fp,
    fn,
    accuracy: round(accuracy),
    precision: round(precision),
    recall: round(recall),
    f1: round(f1),
    falsePositiveRate: round(falsePositiveRate),
    falseNegativeRate: round(falseNegativeRate)
  };
}

function toPredictedLabel(result, mode) {
  if (mode === "warn_threshold") {
    return result.score >= 40 ? "phishing" : "safe";
  }

  return result.score >= 70 ? "phishing" : "safe";
}

function summarizeBy(records, key) {
  const groups = new Map();

  for (const record of records) {
    const value = record[key] || "unknown";
    const list = groups.get(value) || [];
    list.push(record);
    groups.set(value, list);
  }

  return Object.fromEntries(
    Array.from(groups.entries()).map(([value, list]) => [value, buildMetrics(list)])
  );
}

function toMarkdown(report) {
  return `# ScamNoMom Evaluation Report

Generated at: ${report.generatedAt}

## Scope

- Evaluation source: labeled extension feedback
- Included records: ${report.summary.includedRecords}
- Skipped records: ${report.summary.skippedRecords}

## Warn Threshold

Classifies scores >= 40 as phishing.

\`\`\`json
${JSON.stringify(report.warnThreshold.metrics, null, 2)}
\`\`\`

## Block Threshold

Classifies scores >= 70 as phishing.

\`\`\`json
${JSON.stringify(report.blockThreshold.metrics, null, 2)}
\`\`\`

## Breakdown By Source

\`\`\`json
${JSON.stringify(report.warnThreshold.bySource, null, 2)}
\`\`\`

## Breakdown By Provider

\`\`\`json
${JSON.stringify(report.warnThreshold.byProvider, null, 2)}
\`\`\`
`;
}

async function readFeedbackRecords() {
  try {
    const raw = await readFile(FEEDBACK_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return [];
    }

    throw error;
  }
}

async function main() {
  const [{ analyzeFeatures }, feedbackRecords] = await Promise.all([
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/pipeline/analyze.js")).href),
    readFeedbackRecords()
  ]);

  const included = [];
  let skippedRecords = 0;

  for (const record of feedbackRecords) {
    if (!record?.features || !record?.label) {
      skippedRecords += 1;
      continue;
    }

    const result = await analyzeFeatures(record.features);
    included.push({
      id: record.id,
      actual: record.label,
      predictedWarn: toPredictedLabel(result, "warn_threshold"),
      predictedBlock: toPredictedLabel(result, "block_threshold"),
      score: result.score,
      source: record.features.source || "unknown",
      provider: result.provider || "unknown"
    });
  }

  const warnRecords = included.map((record) => ({
    ...record,
    predicted: record.predictedWarn
  }));
  const blockRecords = included.map((record) => ({
    ...record,
    predicted: record.predictedBlock
  }));

  const report = {
    generatedAt: new Date().toISOString(),
    summary: {
      includedRecords: included.length,
      skippedRecords
    },
    warnThreshold: {
      threshold: 40,
      metrics: buildMetrics(warnRecords),
      bySource: summarizeBy(warnRecords, "source"),
      byProvider: summarizeBy(warnRecords, "provider")
    },
    blockThreshold: {
      threshold: 70,
      metrics: buildMetrics(blockRecords),
      bySource: summarizeBy(blockRecords, "source"),
      byProvider: summarizeBy(blockRecords, "provider")
    }
  };

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(JSON_REPORT_PATH, JSON.stringify(report, null, 2));
  await writeFile(MD_REPORT_PATH, toMarkdown(report));

  console.log(
    JSON.stringify(
      {
        ok: true,
        evaluatedRecords: included.length,
        skippedRecords,
        jsonReport: JSON_REPORT_PATH,
        markdownReport: MD_REPORT_PATH
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
