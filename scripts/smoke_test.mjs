import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const BENCHMARK_PATH = path.join(ROOT, "data", "benchmarks", "scamnomom-benchmark.json");
const OUTPUT_DIR = path.join(ROOT, "data", "processed");
const OUTPUT_PATH = path.join(OUTPUT_DIR, "smoke-test-report.json");

async function loadCases() {
  const raw = await readFile(BENCHMARK_PATH, "utf8");
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed : [];
}

async function main() {
  const [{ analyzeFeatures }, { analyzeText }, cases] = await Promise.all([
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/pipeline/analyze.js")).href),
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/pipeline/text-analyzer.js")).href),
    loadCases()
  ]);

  const results = [];

  for (const entry of cases) {
    const analysis =
      entry.kind === "text" ? await analyzeText(entry.input) : await analyzeFeatures(entry.features);

    const passAction = entry.expectedAction ? analysis.recommendedAction === entry.expectedAction : true;
    const passMin = typeof entry.minScore === "number" ? analysis.score >= entry.minScore : true;
    const passMax = typeof entry.maxScore === "number" ? analysis.score <= entry.maxScore : true;
    const passed = passAction && passMin && passMax;

    results.push({
      id: entry.id,
      kind: entry.kind,
      label: entry.label,
      passed,
      expectedAction: entry.expectedAction,
      actualAction: analysis.recommendedAction,
      score: analysis.score,
      attackType: analysis.attackType
    });
  }

  const summary = {
    total: results.length,
    passed: results.filter((result) => result.passed).length,
    failed: results.filter((result) => !result.passed).length
  };

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(
    OUTPUT_PATH,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        summary,
        results
      },
      null,
      2
    )
  );

  console.log(JSON.stringify({ ok: summary.failed === 0, output: OUTPUT_PATH, summary }, null, 2));

  if (summary.failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
