import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const KEYWORDS_PATH = path.join(ROOT, "data/tw_scam_keywords.json");
const APPROVALS_PATH = path.join(ROOT, "data/processed/tw_scam_pattern_approvals.json");

const CATEGORY_NAMES = ["credential", "urgency", "payment", "logistics", "prize"];

async function readJson(filePath) {
  const raw = await readFile(filePath, "utf8");
  return JSON.parse(raw);
}

function normalizeItems(items) {
  return Array.from(
    new Set(
      (Array.isArray(items) ? items : [])
        .map((item) => String(item || "").trim())
        .filter(Boolean)
    )
  );
}

async function main() {
  const [keywords, approvals] = await Promise.all([readJson(KEYWORDS_PATH), readJson(APPROVALS_PATH)]);
  const result = structuredClone(keywords);
  const summary = {};

  for (const category of CATEGORY_NAMES) {
    const approvedKeywords = normalizeItems(approvals.approvedKeywords?.[category]);
    const approvedPhrases = normalizeItems(approvals.approvedPhrases?.[category]);
    const incoming = [...approvedKeywords, ...approvedPhrases];
    const current = normalizeItems(result[category]);
    const merged = normalizeItems([...current, ...incoming]);

    result[category] = merged;
    summary[category] = {
      added: merged.length - current.length,
      total: merged.length
    };
  }

  await writeFile(KEYWORDS_PATH, JSON.stringify(result, null, 2));

  console.log(
    JSON.stringify(
      {
        ok: true,
        updatedFile: KEYWORDS_PATH,
        summary
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
