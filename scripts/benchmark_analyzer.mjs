import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const BENCHMARK_PATH = path.join(ROOT, "data", "benchmarks", "scamnomom-benchmark.json");
const OUTPUT_DIR = path.join(ROOT, "data", "processed");
const JSON_REPORT_PATH = path.join(OUTPUT_DIR, "benchmark-report.json");
const MD_REPORT_PATH = path.join(OUTPUT_DIR, "benchmark-report.md");

function safeDivide(a, b) {
  return b ? a / b : 0;
}

function round(value) {
  return Number(value.toFixed(4));
}

function buildMetrics(records) {
  let tp = 0;
  let tn = 0;
  let fp = 0;
  let fn = 0;

  for (const record of records) {
    if (record.label === "phishing" && record.predicted === "phishing") {
      tp += 1;
    } else if (record.label === "safe" && record.predicted === "safe") {
      tn += 1;
    } else if (record.label === "safe" && record.predicted === "phishing") {
      fp += 1;
    } else if (record.label === "phishing" && record.predicted === "safe") {
      fn += 1;
    }
  }

  const total = records.length;
  const precision = safeDivide(tp, tp + fp);
  const recall = safeDivide(tp, tp + fn);

  return {
    total,
    tp,
    tn,
    fp,
    fn,
    accuracy: round(safeDivide(tp + tn, total)),
    precision: round(precision),
    recall: round(recall),
    f1: round(safeDivide(2 * precision * recall, precision + recall)),
    falsePositiveRate: round(safeDivide(fp, fp + tn)),
    falseNegativeRate: round(safeDivide(fn, fn + tp))
  };
}

function summarizeBy(records, key) {
  const groups = new Map();
  for (const record of records) {
    const value = record[key] || "unknown";
    const list = groups.get(value) || [];
    list.push(record);
    groups.set(value, list);
  }

  return Object.fromEntries([...groups.entries()].map(([value, list]) => [value, buildMetrics(list)]));
}

function toMarkdown(report) {
  return `# ScamNoMom Benchmark Report

Generated at: ${report.generatedAt}

## Summary

- Total cases: ${report.summary.total}
- Page/email cases: ${report.summary.pageCases}
- Text cases: ${report.summary.textCases}

## Warn Threshold

\`\`\`json
${JSON.stringify(report.warnThreshold.metrics, null, 2)}
\`\`\`

## Block Threshold

\`\`\`json
${JSON.stringify(report.blockThreshold.metrics, null, 2)}
\`\`\`

## By Kind

\`\`\`json
${JSON.stringify(report.warnThreshold.byKind, null, 2)}
\`\`\`

## By Attack Type

\`\`\`json
${JSON.stringify(report.warnThreshold.byAttackType, null, 2)}
\`\`\`
`;
}

async function loadCases() {
  const raw = await readFile(BENCHMARK_PATH, "utf8");
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed : [];
}

function predictedLabel(score, threshold) {
  return score >= threshold ? "phishing" : "safe";
}

async function main() {
  const [{ analyzeFeatures }, { analyzeText }, cases] = await Promise.all([
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/pipeline/analyze.js")).href),
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/pipeline/text-analyzer.js")).href),
    loadCases()
  ]);

  const records = [];

  for (const entry of cases) {
    const analysis =
      entry.kind === "text" ? await analyzeText(entry.input) : await analyzeFeatures(entry.features);

    records.push({
      id: entry.id,
      kind: entry.kind,
      label: entry.label,
      score: analysis.score,
      action: analysis.recommendedAction,
      attackType: analysis.attackType
    });
  }

  const warnRecords = records.map((record) => ({ ...record, predicted: predictedLabel(record.score, 40) }));
  const blockRecords = records.map((record) => ({ ...record, predicted: predictedLabel(record.score, 70) }));

  const report = {
    generatedAt: new Date().toISOString(),
    summary: {
      total: records.length,
      pageCases: records.filter((record) => record.kind === "page").length,
      textCases: records.filter((record) => record.kind === "text").length
    },
    warnThreshold: {
      threshold: 40,
      metrics: buildMetrics(warnRecords),
      byKind: summarizeBy(warnRecords, "kind"),
      byAttackType: summarizeBy(warnRecords, "attackType")
    },
    blockThreshold: {
      threshold: 70,
      metrics: buildMetrics(blockRecords),
      byKind: summarizeBy(blockRecords, "kind"),
      byAttackType: summarizeBy(blockRecords, "attackType")
    },
    cases: records
  };

  if (process.env.BENCHMARK_STRICT === "1" && report.warnThreshold.metrics.recall < 0.8) {
    throw new Error(`Warn-threshold recall too low: ${report.warnThreshold.metrics.recall}`);
  }

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(JSON_REPORT_PATH, JSON.stringify(report, null, 2));
  await writeFile(MD_REPORT_PATH, toMarkdown(report));

  console.log(JSON.stringify({ ok: true, jsonReport: JSON_REPORT_PATH, markdownReport: MD_REPORT_PATH }, null, 2));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
