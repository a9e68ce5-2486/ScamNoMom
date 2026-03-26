import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const TRAINING_SAMPLES_PATH = path.join(ROOT, "data/processed/training-samples.json");
const CANDIDATES_PATH = path.join(ROOT, "data/processed/tw_scam_pattern_candidates.json");
const KEYWORDS_PATH = path.join(ROOT, "data/tw_scam_keywords.json");
const BRANDS_PATH = path.join(ROOT, "data/tw_brand_domains.json");
const OUTPUT_DIR = path.join(ROOT, "data/processed");
const OUTPUT_PATH = path.join(OUTPUT_DIR, "tw_dashboard.html");

async function readJson(filePath, fallback) {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function countBy(items, selector) {
  const counts = new Map();
  for (const item of items) {
    const key = selector(item);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([label, count]) => ({ label, count }));
}

function topRows(rows, emptyLabel) {
  if (!rows.length) {
    return `<tr><td colspan="3" class="empty">${emptyLabel}</td></tr>`;
  }

  return rows
    .map(
      (row, index) => `
        <tr>
          <td>${index + 1}</td>
          <td>${escapeHtml(row.label ?? row.value ?? "")}</td>
          <td>${escapeHtml(row.count ?? "")}</td>
        </tr>`
    )
    .join("");
}

function candidateRows(rows, emptyLabel) {
  if (!rows.length) {
    return `<tr><td colspan="5" class="empty">${emptyLabel}</td></tr>`;
  }

  return rows
    .map(
      (row, index) => `
        <tr>
          <td>${index + 1}</td>
          <td>${escapeHtml(row.value)}</td>
          <td>${escapeHtml(row.predictedCategory ?? "unknown")}</td>
          <td>${typeof row.confidence === "number" ? `${Math.round(row.confidence * 100)}%` : "--"}</td>
          <td>${escapeHtml(row.example ?? "")}</td>
        </tr>`
    )
    .join("");
}

async function main() {
  const [samples, candidates, keywords, brands] = await Promise.all([
    readJson(TRAINING_SAMPLES_PATH, []),
    readJson(CANDIDATES_PATH, {
      generatedAt: new Date().toISOString(),
      inputSamples: 0,
      candidateKeywords: [],
      candidatePhrases: [],
      hotBrands: []
    }),
    readJson(KEYWORDS_PATH, {}),
    readJson(BRANDS_PATH, [])
  ]);

  const phishingSamples = samples.filter((sample) => sample.label === "phishing");
  const safeSamples = samples.filter((sample) => sample.label === "safe");
  const sourceCounts = countBy(samples, (sample) => sample.sourceType ?? "unknown");
  const attackCounts = countBy(phishingSamples, (sample) => sample.signals?.attackType ?? "unknown");
  const highConfidenceKeywords = (candidates.candidateKeywords ?? [])
    .filter((item) => Number(item.confidence ?? 0) >= 0.7)
    .slice(0, 10);
  const highConfidencePhrases = (candidates.candidatePhrases ?? [])
    .filter((item) => Number(item.confidence ?? 0) >= 0.7)
    .slice(0, 10);
  const latestKeywords = (candidates.candidateKeywords ?? []).slice(0, 10);
  const latestPhrases = (candidates.candidatePhrases ?? []).slice(0, 10);

  const html = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>ScamNoMom Taiwan Dashboard</title>
    <style>
      :root {
        --bg: #f4efe7;
        --panel: rgba(255,255,255,0.78);
        --ink: #1c1712;
        --muted: #665c50;
        --line: rgba(88,65,39,0.14);
        --accent: #c8683a;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: Georgia, "Times New Roman", serif;
        color: var(--ink);
        background:
          radial-gradient(circle at top right, rgba(205,162,116,0.35), transparent 35%),
          linear-gradient(180deg, #fbf7ef 0%, var(--bg) 100%);
      }
      main {
        max-width: 1200px;
        margin: 0 auto;
        padding: 28px;
        display: grid;
        gap: 18px;
      }
      .hero, .panel {
        border: 1px solid var(--line);
        border-radius: 22px;
        background: var(--panel);
        padding: 18px;
      }
      .hero h1 { margin: 6px 0; font-size: 34px; }
      .eyebrow {
        font-size: 12px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--muted);
      }
      .summary {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
      }
      .stat {
        border: 1px solid var(--line);
        border-radius: 18px;
        padding: 14px;
        background: rgba(255,255,255,0.55);
      }
      .stat-label {
        font-size: 11px;
        text-transform: uppercase;
        color: var(--muted);
        letter-spacing: 0.08em;
      }
      .stat-value {
        margin-top: 6px;
        font-size: 32px;
        font-weight: 700;
      }
      .grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 18px;
      }
      h2 {
        margin: 0 0 12px;
        font-size: 18px;
      }
      table {
        width: 100%;
        border-collapse: collapse;
      }
      th, td {
        text-align: left;
        padding: 10px 8px;
        border-bottom: 1px solid var(--line);
        vertical-align: top;
        font-size: 14px;
      }
      th {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--muted);
      }
      .empty {
        color: var(--muted);
        font-style: italic;
      }
      .meta {
        color: var(--muted);
        font-size: 13px;
      }
      .wide {
        grid-column: 1 / -1;
      }
      .pill {
        display: inline-block;
        margin-right: 8px;
        margin-bottom: 8px;
        padding: 8px 10px;
        border-radius: 999px;
        background: rgba(200,104,58,0.1);
        border: 1px solid rgba(200,104,58,0.18);
        font-size: 13px;
      }
      @media (max-width: 900px) {
        .summary, .grid { grid-template-columns: 1fr; }
      }
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <div class="eyebrow">ScamNoMom Intelligence</div>
        <h1>Taiwan Scam Trend Dashboard</h1>
        <div class="meta">Generated ${escapeHtml(new Date().toLocaleString())}</div>
      </section>

      <section class="summary">
        <div class="stat">
          <div class="stat-label">Total Samples</div>
          <div class="stat-value">${samples.length}</div>
        </div>
        <div class="stat">
          <div class="stat-label">Phishing Samples</div>
          <div class="stat-value">${phishingSamples.length}</div>
        </div>
        <div class="stat">
          <div class="stat-label">Safe Samples</div>
          <div class="stat-value">${safeSamples.length}</div>
        </div>
        <div class="stat">
          <div class="stat-label">Tracked TW Brands</div>
          <div class="stat-value">${brands.length}</div>
        </div>
      </section>

      <section class="grid">
        <section class="panel">
          <h2>Sample Sources</h2>
          <table>
            <thead><tr><th>#</th><th>Source</th><th>Count</th></tr></thead>
            <tbody>${topRows(sourceCounts, "No samples yet")}</tbody>
          </table>
        </section>
        <section class="panel">
          <h2>Attack Types</h2>
          <table>
            <thead><tr><th>#</th><th>Type</th><th>Count</th></tr></thead>
            <tbody>${topRows(attackCounts, "No phishing attack types yet")}</tbody>
          </table>
        </section>
        <section class="panel">
          <h2>Hot Brands</h2>
          <table>
            <thead><tr><th>#</th><th>Brand</th><th>Mentions</th></tr></thead>
            <tbody>${topRows(candidates.hotBrands ?? [], "No hot brands yet")}</tbody>
          </table>
        </section>
        <section class="panel">
          <h2>Keyword Coverage</h2>
          <div>
            ${Object.entries(keywords)
              .map(([category, items]) => `<span class="pill">${escapeHtml(category)}: ${Array.isArray(items) ? items.length : 0}</span>`)
              .join("")}
          </div>
          <div class="meta" style="margin-top:12px;">Candidate snapshot generated: ${escapeHtml(candidates.generatedAt ?? "n/a")}</div>
        </section>
        <section class="panel">
          <h2>High-Confidence Keywords</h2>
          <table>
            <thead><tr><th>#</th><th>Keyword</th><th>Category</th><th>Confidence</th><th>Example</th></tr></thead>
            <tbody>${candidateRows(highConfidenceKeywords, "No high-confidence keywords yet")}</tbody>
          </table>
        </section>
        <section class="panel">
          <h2>High-Confidence Phrases</h2>
          <table>
            <thead><tr><th>#</th><th>Phrase</th><th>Category</th><th>Confidence</th><th>Example</th></tr></thead>
            <tbody>${candidateRows(highConfidencePhrases, "No high-confidence phrases yet")}</tbody>
          </table>
        </section>
        <section class="panel">
          <h2>Latest Candidate Keywords</h2>
          <table>
            <thead><tr><th>#</th><th>Keyword</th><th>Category</th><th>Confidence</th><th>Example</th></tr></thead>
            <tbody>${candidateRows(latestKeywords, "No candidate keywords yet")}</tbody>
          </table>
        </section>
        <section class="panel">
          <h2>Latest Candidate Phrases</h2>
          <table>
            <thead><tr><th>#</th><th>Phrase</th><th>Category</th><th>Confidence</th><th>Example</th></tr></thead>
            <tbody>${candidateRows(latestPhrases, "No candidate phrases yet")}</tbody>
          </table>
        </section>
        <section class="panel wide">
          <h2>Candidate Keywords</h2>
          <table>
            <thead><tr><th>#</th><th>Keyword</th><th>Predicted Category</th><th>Confidence</th><th>Example</th></tr></thead>
            <tbody>${candidateRows(candidates.candidateKeywords ?? [], "No candidate keywords yet")}</tbody>
          </table>
        </section>
        <section class="panel wide">
          <h2>Candidate Phrases</h2>
          <table>
            <thead><tr><th>#</th><th>Phrase</th><th>Predicted Category</th><th>Confidence</th><th>Example</th></tr></thead>
            <tbody>${candidateRows(candidates.candidatePhrases ?? [], "No candidate phrases yet")}</tbody>
          </table>
        </section>
      </section>
    </main>
  </body>
</html>`;

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(OUTPUT_PATH, html);

  console.log(
    JSON.stringify(
      {
        ok: true,
        outputPath: OUTPUT_PATH,
        totalSamples: samples.length,
        phishingSamples: phishingSamples.length
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
