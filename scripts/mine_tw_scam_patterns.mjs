import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const TRAINING_SAMPLES_PATH = path.join(ROOT, "data/processed/training-samples.json");
const KEYWORDS_PATH = path.join(ROOT, "data/tw_scam_keywords.json");
const BRANDS_PATH = path.join(ROOT, "data/tw_brand_domains.json");
const OUTPUT_DIR = path.join(ROOT, "data/processed");
const OUTPUT_PATH = path.join(OUTPUT_DIR, "tw_scam_pattern_candidates.json");
const CATEGORY_NAMES = ["credential", "urgency", "payment", "logistics", "prize"];

function extractChineseTokens(text) {
  const matches = String(text || "").match(/[\u4e00-\u9fff]{2,8}/g);
  return matches ?? [];
}

function topEntries(counter, limit = 30, minCount = 2) {
  return [...counter.entries()]
    .filter(([, count]) => count >= minCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([value, count]) => ({ value, count }));
}

function inferCategory(value, example, keywordConfig) {
  const text = `${value} ${example}`;
  const scores = new Map(CATEGORY_NAMES.map((name) => [name, 0]));

  for (const category of CATEGORY_NAMES) {
    for (const keyword of keywordConfig[category] ?? []) {
      if (text.includes(keyword) || keyword.includes(value)) {
        scores.set(category, (scores.get(category) ?? 0) + 2);
      }
    }
  }

  if (/登入|驗證|帳號|帳戶|密碼|身分/.test(text)) {
    scores.set("credential", (scores.get("credential") ?? 0) + 3);
  }

  if (/立即|緊急|停用|停權|逾期|失敗|限時/.test(text)) {
    scores.set("urgency", (scores.get("urgency") ?? 0) + 3);
  }

  if (/付款|繳費|轉帳|匯款|分期|扣款|退款|信用卡/.test(text)) {
    scores.set("payment", (scores.get("payment") ?? 0) + 3);
  }

  if (/物流|包裹|配送|宅配|取貨|超商|黑貓|新竹物流/.test(text)) {
    scores.set("logistics", (scores.get("logistics") ?? 0) + 3);
  }

  if (/中獎|領獎|抽獎|獎金|贈品/.test(text)) {
    scores.set("prize", (scores.get("prize") ?? 0) + 3);
  }

  const ranked = [...scores.entries()].sort((a, b) => b[1] - a[1]);
  const [bestCategory, bestScore] = ranked[0];
  const secondScore = ranked[1]?.[1] ?? 0;

  return {
    predictedCategory: bestScore > 0 ? bestCategory : "unknown",
    confidence: bestScore > 0 ? Math.min(1, 0.45 + (bestScore - secondScore) * 0.1) : 0
  };
}

async function readJson(filePath) {
  const raw = await readFile(filePath, "utf8");
  return JSON.parse(raw);
}

function buildKnownKeywordSet(keywordConfig) {
  return new Set(Object.values(keywordConfig).flat().map((item) => String(item).trim()));
}

function buildBrandAliasSet(brandConfig) {
  return new Set(
    brandConfig.flatMap((entry) => [entry.brand, ...(entry.aliases || [])]).map((item) => String(item).trim().toLowerCase())
  );
}

function collectSampleText(sample) {
  return [
    sample.content?.title ?? "",
    sample.content?.visibleText ?? "",
    sample.content?.subject ?? "",
    sample.content?.sender ?? "",
    sample.content?.bodyText ?? ""
  ].join(" ");
}

function detectMentionedBrands(text, brandConfig) {
  const lower = text.toLowerCase();
  return brandConfig
    .filter((entry) => [entry.brand, ...(entry.aliases || [])].some((alias) => lower.includes(String(alias).toLowerCase())))
    .map((entry) => entry.brand);
}

async function main() {
  const [samples, keywordConfig, brandConfig] = await Promise.all([
    readJson(TRAINING_SAMPLES_PATH).catch(() => []),
    readJson(KEYWORDS_PATH),
    readJson(BRANDS_PATH)
  ]);

  const knownKeywords = buildKnownKeywordSet(keywordConfig);
  const brandAliasSet = buildBrandAliasSet(brandConfig);
  const phishingSamples = Array.isArray(samples) ? samples.filter((sample) => sample.label === "phishing") : [];

  const tokenCounts = new Map();
  const bigramCounts = new Map();
  const brandCounts = new Map();
  const phraseExamples = new Map();

  for (const sample of phishingSamples) {
    const text = collectSampleText(sample);
    const tokens = extractChineseTokens(text);
    const brands = detectMentionedBrands(text, brandConfig);

    for (const brand of brands) {
      brandCounts.set(brand, (brandCounts.get(brand) ?? 0) + 1);
    }

    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (!knownKeywords.has(token) && !brandAliasSet.has(token.toLowerCase())) {
        tokenCounts.set(token, (tokenCounts.get(token) ?? 0) + 1);
        if (!phraseExamples.has(token)) {
          phraseExamples.set(token, text.slice(0, 220));
        }
      }

      if (i < tokens.length - 1) {
        const bigram = `${tokens[i]} ${tokens[i + 1]}`;
        if (!knownKeywords.has(tokens[i]) || !knownKeywords.has(tokens[i + 1])) {
          bigramCounts.set(bigram, (bigramCounts.get(bigram) ?? 0) + 1);
          if (!phraseExamples.has(bigram)) {
            phraseExamples.set(bigram, text.slice(0, 220));
          }
        }
      }
    }
  }

  const result = {
    generatedAt: new Date().toISOString(),
    inputSamples: phishingSamples.length,
    candidateKeywords: topEntries(tokenCounts, 40, 2).map((entry) => {
      const example = phraseExamples.get(entry.value) ?? "";
      return {
        ...entry,
        ...inferCategory(entry.value, example, keywordConfig),
        example
      };
    }),
    candidatePhrases: topEntries(bigramCounts, 30, 2).map((entry) => {
      const example = phraseExamples.get(entry.value) ?? "";
      return {
        ...entry,
        ...inferCategory(entry.value, example, keywordConfig),
        example
      };
    }),
    hotBrands: topEntries(brandCounts, 20, 1),
    recommendation:
      "Review predictedCategory and confidence for candidateKeywords and candidatePhrases, then promote approved items into data/tw_scam_keywords.json."
  };

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(OUTPUT_PATH, JSON.stringify(result, null, 2));

  console.log(
    JSON.stringify(
      {
        ok: true,
        inputSamples: phishingSamples.length,
        outputPath: OUTPUT_PATH,
        candidateKeywords: result.candidateKeywords.length,
        candidatePhrases: result.candidatePhrases.length
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
