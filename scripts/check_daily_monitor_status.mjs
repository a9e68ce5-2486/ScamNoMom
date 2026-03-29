import { readFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const SUMMARY_PATH = path.join(ROOT, "data/processed/daily-monitor-summary.json");

async function main() {
  const raw = await readFile(SUMMARY_PATH, "utf8");
  const summary = JSON.parse(raw);
  const status = String(summary?.status || "unknown").toLowerCase();
  const anomalies = Array.isArray(summary?.anomalies) ? summary.anomalies.length : 0;

  console.log(
    JSON.stringify(
      {
        ok: status === "ok",
        status,
        anomalies,
        generatedAt: summary?.generatedAt,
        summaryPath: SUMMARY_PATH
      },
      null,
      2
    )
  );

  if (status !== "ok") {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
