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
const DEFAULT_LINE_NOTIFY_URL = "https://notify-api.line.me/api/notify";

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
  const rawChannel = String(process.env.MONITOR_NOTIFY_CHANNEL || "auto").trim().toLowerCase();
  return {
    minFeedSuccessRate: parseNumber(process.env.MONITOR_MIN_FEED_SUCCESS_RATE, DEFAULT_MIN_FEED_SUCCESS_RATE, 0, 1),
    maxWarnRateDelta: parseNumber(process.env.MONITOR_MAX_WARN_RATE_DELTA, DEFAULT_MAX_WARN_DELTA, 0.01, 1),
    minAnalyzed: Math.floor(parseNumber(process.env.MONITOR_MIN_ANALYZED, DEFAULT_MIN_ANALYZED, 10, 10000)),
    historyDays: Math.floor(parseNumber(process.env.MONITOR_HISTORY_DAYS, DEFAULT_HISTORY_DAYS, 7, 365)),
    webhookUrl: String(process.env.MONITOR_WEBHOOK_URL || "").trim(),
    notifyChannel:
      rawChannel === "slack" || rawChannel === "discord" || rawChannel === "line_notify" || rawChannel === "generic"
        ? rawChannel
        : "auto",
    lineNotifyToken: String(process.env.MONITOR_LINE_NOTIFY_TOKEN || "").trim(),
    lineNotifyUrl: String(process.env.MONITOR_LINE_NOTIFY_URL || DEFAULT_LINE_NOTIFY_URL).trim()
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

function trendArrow(delta) {
  if (delta >= 0.02) {
    return "🔺";
  }
  if (delta <= -0.02) {
    return "🔻";
  }
  return "⏺";
}

function statusEmoji(status) {
  if (status === "critical") {
    return "🚨";
  }
  if (status === "warning") {
    return "⚠️";
  }
  return "✅";
}

function formatPercent(value) {
  return `${(Number(value || 0) * 100).toFixed(1)}%`;
}

function topAnomalies(anomalies, limit = 3) {
  const severityWeight = {
    critical: 2,
    warning: 1
  };
  return [...anomalies]
    .sort((a, b) => (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0))
    .slice(0, limit);
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
  const topIssues = topAnomalies(summary.anomalies, 3);
  const failSources = summary.feed.failedSources.length > 0 ? summary.feed.failedSources.join(", ") : "none";
  const warnTrend = summary.trend?.deltaFrom7dAvg?.warnOrAboveRate || 0;
  const highTrend = summary.trend?.deltaFrom7dAvg?.highOrBlockedRate || 0;
  const warnTrendLine = `${trendArrow(warnTrend)} warn-or-above vs 7d: ${formatPercent(warnTrend)}`;
  const highTrendLine = `${trendArrow(highTrend)} high-or-blocked vs 7d: ${formatPercent(highTrend)}`;
  const header = `${statusEmoji(summary.status)} ScamNoMom daily monitor: ${summary.status.toUpperCase()}`;
  const issueLines = topIssues.length > 0 ? topIssues.map((item) => `• [${item.severity}] ${item.message}`) : ["• no anomalies"];

  const message = [
    header,
    `Feed success: ${formatPercent(summary.feed.successRate)} | failed source: ${failSources}`,
    `Model warn-or-above: ${formatPercent(summary.modelTest.warnOrAboveRate)} | high-or-blocked: ${formatPercent(summary.modelTest.highOrBlockedRate)}`,
    warnTrendLine,
    highTrendLine,
    "Top anomalies:",
    ...issueLines
  ].join("\n");

  const effectiveChannel =
    webhookUrl && webhookUrl.includes("hooks.slack.com")
      ? "slack"
      : webhookUrl && webhookUrl.includes("discord.com/api/webhooks")
        ? "discord"
        : "generic";

  try {
    if (effectiveChannel === "slack") {
      const payload = {
        text: message,
        blocks: [
          {
            type: "header",
            text: {
              type: "plain_text",
              text: `${statusEmoji(summary.status)} ScamNoMom Daily Monitor`
            }
          },
          {
            type: "section",
            fields: [
              { type: "mrkdwn", text: `*Status*\n${summary.status.toUpperCase()}` },
              { type: "mrkdwn", text: `*Feed success*\n${formatPercent(summary.feed.successRate)}` },
              { type: "mrkdwn", text: `*Warn-or-above*\n${formatPercent(summary.modelTest.warnOrAboveRate)}` },
              { type: "mrkdwn", text: `*High-or-blocked*\n${formatPercent(summary.modelTest.highOrBlockedRate)}` }
            ]
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: `*Failed sources:* ${failSources}\n*Trend:* ${warnTrendLine} | ${highTrendLine}`
            }
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: `*Top anomalies*\n${issueLines.join("\n")}`
            }
          }
        ]
      };
      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      if (!response.ok) {
        return { sent: false, channel: "slack", error: `webhook HTTP ${response.status}` };
      }
      return { sent: true, channel: "slack" };
    }

    if (effectiveChannel === "discord") {
      const color = summary.status === "critical" ? 15158332 : summary.status === "warning" ? 16753920 : 5763719;
      const payload = {
        content: `${statusEmoji(summary.status)} ScamNoMom daily monitor`,
        embeds: [
          {
            title: `Status: ${summary.status.toUpperCase()}`,
            color,
            fields: [
              { name: "Feed success", value: formatPercent(summary.feed.successRate), inline: true },
              { name: "Failed sources", value: failSources, inline: true },
              { name: "Warn-or-above", value: formatPercent(summary.modelTest.warnOrAboveRate), inline: true },
              { name: "High-or-blocked", value: formatPercent(summary.modelTest.highOrBlockedRate), inline: true },
              { name: "Trend", value: `${warnTrendLine}\n${highTrendLine}`, inline: false },
              { name: "Top anomalies", value: issueLines.join("\n"), inline: false }
            ]
          }
        ]
      };
      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      if (!response.ok) {
        return { sent: false, channel: "discord", error: `webhook HTTP ${response.status}` };
      }
      return { sent: true, channel: "discord" };
    }

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
        channel: "generic",
        error: `webhook HTTP ${response.status}`
      };
    }
    return { sent: true, channel: "generic" };
  } catch (error) {
    return {
      sent: false,
      channel: effectiveChannel,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

async function sendLineNotify(config, summary) {
  if (!config.lineNotifyToken) {
    return { sent: false, channel: "line_notify", error: "MONITOR_LINE_NOTIFY_TOKEN is empty" };
  }

  const topIssues = topAnomalies(summary.anomalies, 3);
  const failSources = summary.feed.failedSources.length > 0 ? summary.feed.failedSources.join(", ") : "none";
  const warnTrend = summary.trend?.deltaFrom7dAvg?.warnOrAboveRate || 0;
  const highTrend = summary.trend?.deltaFrom7dAvg?.highOrBlockedRate || 0;
  const issueLines = topIssues.length > 0 ? topIssues.map((item) => `• [${item.severity}] ${item.message}`) : ["• no anomalies"];
  const message = [
    `${statusEmoji(summary.status)} ScamNoMom daily monitor ${summary.status.toUpperCase()}`,
    `Feed success: ${formatPercent(summary.feed.successRate)}`,
    `Failed source: ${failSources}`,
    `Warn-or-above: ${formatPercent(summary.modelTest.warnOrAboveRate)}`,
    `High-or-blocked: ${formatPercent(summary.modelTest.highOrBlockedRate)}`,
    `${trendArrow(warnTrend)} warn vs 7d: ${formatPercent(warnTrend)}`,
    `${trendArrow(highTrend)} high vs 7d: ${formatPercent(highTrend)}`,
    "Top anomalies:",
    ...issueLines
  ].join("\n");

  try {
    const response = await fetch(config.lineNotifyUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.lineNotifyToken}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        message
      })
    });
    if (!response.ok) {
      return { sent: false, channel: "line_notify", error: `line notify HTTP ${response.status}` };
    }
    return { sent: true, channel: "line_notify" };
  } catch (error) {
    return {
      sent: false,
      channel: "line_notify",
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

async function sendNotification(config, summary) {
  if (config.notifyChannel === "line_notify") {
    return sendLineNotify(config, summary);
  }

  if (!config.webhookUrl) {
    return { sent: false, channel: config.notifyChannel === "auto" ? "generic" : config.notifyChannel };
  }

  if (config.notifyChannel === "slack" || config.notifyChannel === "discord" || config.notifyChannel === "generic") {
    return sendWebhookNotification(config.webhookUrl, summary);
  }

  return sendWebhookNotification(config.webhookUrl, summary);
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

  const webhook = await sendNotification(config, summary);

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
