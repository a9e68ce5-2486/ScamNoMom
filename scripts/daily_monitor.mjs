import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";

const ROOT = process.cwd();
const RAW_EXTERNAL_DIR = path.join(ROOT, "data/raw/external");
const PROCESSED_DIR = path.join(ROOT, "data/processed");

const FEED_STATUS_PATH = path.join(RAW_EXTERNAL_DIR, "feed-status.json");
const EXTERNAL_TEST_REPORT_PATH = path.join(PROCESSED_DIR, "external-feeds-test-report.json");
const SUMMARY_JSON_PATH = path.join(PROCESSED_DIR, "daily-monitor-summary.json");
const SUMMARY_MD_PATH = path.join(PROCESSED_DIR, "daily-monitor-summary.md");
const HISTORY_PATH = path.join(PROCESSED_DIR, "daily-monitor-history.json");

const DEFAULT_MIN_FEED_SUCCESS_RATE = 0.75;
const DEFAULT_MAX_WARN_DELTA = 0.18;
const DEFAULT_MIN_ANALYZED = 60;
const DEFAULT_HISTORY_DAYS = 120;

function safeDivide(numerator, denominator) {
  return denominator ? numerator / denominator : 0;
}

function round(value) {
  return Number(value.toFixed(4));
}

function parseArgs() {
  const args = process.argv.slice(2);
  return {
    skipFetch: args.includes("--skip-fetch")
  };
}

function parseNumber(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, parsed));
}

function monitorConfig() {
  return {
    minFeedSuccessRate: parseNumber(process.env.MONITOR_MIN_FEED_SUCCESS_RATE, DEFAULT_MIN_FEED_SUCCESS_RATE, 0, 1),
    maxWarnRateDelta: parseNumber(process.env.MONITOR_MAX_WARN_RATE_DELTA, DEFAULT_MAX_WARN_DELTA, 0.01, 1),
    minAnalyzed: Math.floor(parseNumber(process.env.MONITOR_MIN_ANALYZED, DEFAULT_MIN_ANALYZED, 10, 10000)),
    historyDays: Math.floor(parseNumber(process.env.MONITOR_HISTORY_DAYS, DEFAULT_HISTORY_DAYS, 7, 365)),
    webhookUrl: String(process.env.MONITOR_WEBHOOK_URL || "").trim()
  };
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: ROOT,
      stdio: "inherit",
      shell: false,
      ...options
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} ${args.join(" ")} failed with exit code ${code}`));
    });
  });
}

async function readJson(filePath, fallbackValue) {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch {
    return fallbackValue;
  }
}

function average(items) {
  if (!items.length) {
    return 0;
  }
  return items.reduce((sum, item) => sum + item, 0) / items.length;
}

function summarizeTrend(history, currentEntry) {
  const previous = history.length > 0 ? history[history.length - 1] : null;
  const recent = history.slice(-7);
  const recentWarnAvg = average(recent.map((entry) => entry.warnOrAboveRate || 0));
  const recentHighAvg = average(recent.map((entry) => entry.highOrBlockedRate || 0));

  return {
    previous: previous
      ? {
          warnOrAboveRate: previous.warnOrAboveRate,
          highOrBlockedRate: previous.highOrBlockedRate,
          analyzed: previous.analyzed
        }
      : null,
    deltaFromPrevious: previous
      ? {
          warnOrAboveRate: round(currentEntry.warnOrAboveRate - previous.warnOrAboveRate),
          highOrBlockedRate: round(currentEntry.highOrBlockedRate - previous.highOrBlockedRate),
          analyzed: currentEntry.analyzed - previous.analyzed
        }
      : null,
    movingAverage7d: {
      warnOrAboveRate: round(recentWarnAvg),
      highOrBlockedRate: round(recentHighAvg)
    },
    deltaFrom7dAvg: {
      warnOrAboveRate: round(currentEntry.warnOrAboveRate - recentWarnAvg),
      highOrBlockedRate: round(currentEntry.highOrBlockedRate - recentHighAvg)
    }
  };
}

function buildMarkdown(summary) {
  const anomalyLines = summary.anomalies.length
    ? summary.anomalies.map((item) => `- [${item.severity.toUpperCase()}] ${item.message}`).join("\n")
    : "- No anomaly detected.";

  return `# Daily Monitor Summary

Generated at: ${summary.generatedAt}
Overall status: **${summary.status.toUpperCase()}**

## Feed Health

\`\`\`json
${JSON.stringify(summary.feed, null, 2)}
\`\`\`

## External Model Test

\`\`\`json
${JSON.stringify(summary.modelTest, null, 2)}
\`\`\`

## Trend

\`\`\`json
${JSON.stringify(summary.trend, null, 2)}
\`\`\`

## Anomalies

${anomalyLines}
`;
}

async function sendWebhookNotification(webhookUrl, summary) {
  if (!webhookUrl) {
    return { sent: false };
  }

  const anomalyText = summary.anomalies.length
    ? summary.anomalies.map((item) => `[${item.severity}] ${item.message}`).join(" | ")
    : "no anomalies";
  const message = [
    `ScamNoMom daily monitor: ${summary.status.toUpperCase()}`,
    `feed success rate=${summary.feed.successRate}, failed sources=${summary.feed.failedSources.join(", ") || "none"}`,
    `model warnOrAbove=${summary.modelTest.warnOrAboveRate}, highOrBlocked=${summary.modelTest.highOrBlockedRate}`,
    `trend delta(7d warn)=${summary.trend.deltaFrom7dAvg.warnOrAboveRate}`,
    `anomalies=${anomalyText}`
  ].join("\n");

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ text: message })
    });
    if (!response.ok) {
      return {
        sent: false,
        error: `webhook HTTP ${response.status}`
      };
    }
    return { sent: true };
  } catch (error) {
    return {
      sent: false,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

async function main() {
  const args = parseArgs();
  const config = monitorConfig();
  const anomalies = [];
  const steps = [];

  await mkdir(PROCESSED_DIR, { recursive: true });

  if (!args.skipFetch) {
    try {
      await runCommand(process.execPath, [path.join(ROOT, "scripts/fetch_feeds.mjs")]);
      steps.push({ step: "fetch_feeds", ok: true });
    } catch (error) {
      steps.push({ step: "fetch_feeds", ok: false, error: error instanceof Error ? error.message : String(error) });
      anomalies.push({
        severity: "critical",
        message: `Feed fetch step failed: ${error instanceof Error ? error.message : String(error)}`
      });
    }
  }

  try {
    await runCommand(process.execPath, [path.join(ROOT, "scripts/prepare_dataset.mjs")]);
    steps.push({ step: "prepare_dataset", ok: true });
  } catch (error) {
    steps.push({ step: "prepare_dataset", ok: false, error: error instanceof Error ? error.message : String(error) });
    anomalies.push({
      severity: "critical",
      message: `Prepare dataset step failed: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  try {
    await runCommand("npm", ["run", "build"], { cwd: path.join(ROOT, "apps/api") });
    steps.push({ step: "api_build", ok: true });
  } catch (error) {
    steps.push({ step: "api_build", ok: false, error: error instanceof Error ? error.message : String(error) });
    anomalies.push({
      severity: "critical",
      message: `API build failed: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  try {
    await runCommand(process.execPath, [path.join(ROOT, "scripts/test_external_feeds.mjs")]);
    steps.push({ step: "test_external_feeds", ok: true });
  } catch (error) {
    steps.push({ step: "test_external_feeds", ok: false, error: error instanceof Error ? error.message : String(error) });
    anomalies.push({
      severity: "critical",
      message: `External feed model test failed: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  const feedStatus = await readJson(FEED_STATUS_PATH, {
    successes: [],
    errors: []
  });
  const externalTest = await readJson(EXTERNAL_TEST_REPORT_PATH, {
    summary: {
      analyzed: 0,
      failed: 0,
      warnOrAboveRate: 0,
      highOrBlockedRate: 0
    }
  });
  const history = await readJson(HISTORY_PATH, []);

  const totalSources = (feedStatus.successes?.length || 0) + (feedStatus.errors?.length || 0);
  const feedSuccessRate = round(safeDivide(feedStatus.successes?.length || 0, totalSources));
  const feed = {
    successRate: feedSuccessRate,
    successfulSources: (feedStatus.successes || []).map((entry) => entry.source),
    failedSources: (feedStatus.errors || []).map((entry) => entry.source),
    totalSources
  };

  const modelTest = {
    analyzed: Number(externalTest.summary?.analyzed || 0),
    failed: Number(externalTest.summary?.failed || 0),
    warnOrAboveRate: Number(externalTest.summary?.warnOrAboveRate || 0),
    highOrBlockedRate: Number(externalTest.summary?.highOrBlockedRate || 0)
  };

  if (feed.totalSources > 0 && feed.successRate < config.minFeedSuccessRate) {
    anomalies.push({
      severity: "warning",
      message: `Feed success rate ${feed.successRate} is below threshold ${config.minFeedSuccessRate}.`
    });
  }
  if (feed.failedSources.length > 0) {
    anomalies.push({
      severity: "warning",
      message: `Feed sources failed: ${feed.failedSources.join(", ")}`
    });
  }
  if (modelTest.analyzed < config.minAnalyzed) {
    anomalies.push({
      severity: "warning",
      message: `External model test analyzed only ${modelTest.analyzed} samples (threshold ${config.minAnalyzed}).`
    });
  }

  const currentEntry = {
    date: new Date().toISOString(),
    feedSuccessRate: feed.successRate,
    analyzed: modelTest.analyzed,
    warnOrAboveRate: modelTest.warnOrAboveRate,
    highOrBlockedRate: modelTest.highOrBlockedRate
  };
  const trend = summarizeTrend(Array.isArray(history) ? history : [], currentEntry);
  if (Math.abs(trend.deltaFrom7dAvg.warnOrAboveRate) > config.maxWarnRateDelta) {
    anomalies.push({
      severity: "warning",
      message: `Warn-or-above rate changed sharply vs 7d average (${trend.deltaFrom7dAvg.warnOrAboveRate}).`
    });
  }

  const nextHistory = [...(Array.isArray(history) ? history : []), currentEntry].slice(-config.historyDays);
  await writeFile(HISTORY_PATH, JSON.stringify(nextHistory, null, 2));

  const hasCritical = anomalies.some((item) => item.severity === "critical");
  const status = hasCritical ? "critical" : anomalies.length > 0 ? "warning" : "ok";
  const summary = {
    generatedAt: new Date().toISOString(),
    status,
    config,
    steps,
    feed,
    modelTest,
    trend,
    anomalies
  };

  await writeFile(SUMMARY_JSON_PATH, JSON.stringify(summary, null, 2));
  await writeFile(SUMMARY_MD_PATH, buildMarkdown(summary));

  const webhook = await sendWebhookNotification(config.webhookUrl, summary);

  console.log(
    JSON.stringify(
      {
        ok: status !== "critical",
        status,
        summaryJson: SUMMARY_JSON_PATH,
        summaryMarkdown: SUMMARY_MD_PATH,
        historyPath: HISTORY_PATH,
        webhook
      },
      null,
      2
    )
  );

  if (status === "critical") {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
