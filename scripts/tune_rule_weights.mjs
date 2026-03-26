import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const FEEDBACK_PATH = path.join(ROOT, "apps/api/data/feedback.json");
const OUTPUT_DIR = path.join(ROOT, "data/processed");
const OUTPUT_PATH = path.join(OUTPUT_DIR, "rule-weight-suggestions.json");

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function round(value) {
  return Number(value.toFixed(2));
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

function signalToNumber(value) {
  if (typeof value === "boolean") {
    return value ? 1 : 0;
  }

  if (typeof value === "number") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.length;
  }

  return 0;
}

function toWeightKey(signalName) {
  const mapping = {
    hasPasswordFields: "passwordFields",
    externalSubmitCount: "externalSubmit",
    mismatchedTextCount: "mismatchedText",
    suspiciousTldCount: "suspiciousLinkTldBase",
    hiddenElementCount: "hiddenElements",
    iframeCount: "iframeHeavy",
    hostnameUsesSuspiciousTld: "suspiciousHostnameTld",
    brandOnCredentialPage: "brandOnCredentialPage",
    mismatchedBrands: "mismatchedBrand",
    mismatchedBrandLinks: "mismatchedBrandLinks",
    hasTaiwanBrandActionPattern: "taiwanBrandActionPattern",
    hasTraditionalScamLanguage: "traditionalScamLanguage",
    emailContext: "emailContext",
    emailHasManyLinks: "emailManyLinks",
    emailLinkMismatch: "emailLinkMismatch",
    emailHighTrustSenderStyle: "emailHighTrustSenderStyle",
    emailUrgencyLanguage: "emailUrgencyLanguage",
    emailTraditionalScamLanguage: "emailTraditionalScamLanguage",
    emailSenderReplyToMismatch: "emailSenderReplyToMismatch",
    emailBrandDomainMismatch: "emailBrandDomainMismatch",
    emailUsesFreemailForBrandClaim: "emailFreemailBrandClaim"
  };

  return mapping[signalName] || null;
}

async function main() {
  const [{ DEFAULT_RULE_WEIGHTS }, { extractRuleSignals }, feedbackRecords] = await Promise.all([
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/config/rule-weights.js")).href),
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/pipeline/rule-signals.js")).href),
    readFeedbackRecords()
  ]);

  const phishingRecords = feedbackRecords.filter((record) => record?.label === "phishing" && record?.features);
  const safeRecords = feedbackRecords.filter((record) => record?.label === "safe" && record?.features);

  const signalNames = Object.keys(extractRuleSignals({
    url: "https://example.com",
    hostname: "example.com",
    source: "web",
    title: "",
    visibleText: "",
    forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
    links: { total: 0, mismatchedTextCount: 0, suspiciousTldCount: 0, hostnames: [] },
    dom: { hiddenElementCount: 0, iframeCount: 0 },
    brandSignals: []
  }));

  const suggestions = {};

  for (const signalName of signalNames) {
    const weightKey = toWeightKey(signalName);
    if (!weightKey) {
      continue;
    }

    const phishingAvg = phishingRecords.length
      ? phishingRecords.reduce((sum, record) => sum + signalToNumber(extractRuleSignals(record.features)[signalName]), 0) / phishingRecords.length
      : 0;
    const safeAvg = safeRecords.length
      ? safeRecords.reduce((sum, record) => sum + signalToNumber(extractRuleSignals(record.features)[signalName]), 0) / safeRecords.length
      : 0;

    const delta = phishingAvg - safeAvg;
    const baseWeight = DEFAULT_RULE_WEIGHTS[weightKey];

    let suggestedWeight = baseWeight;
    if (delta >= 0.5) {
      suggestedWeight = clamp(Math.round(baseWeight * 1.15), 0, 40);
    } else if (delta <= -0.25) {
      suggestedWeight = clamp(Math.round(baseWeight * 0.85), 0, 40);
    }

    suggestions[weightKey] = {
      signal: signalName,
      currentWeight: baseWeight,
      suggestedWeight,
      phishingAverage: round(phishingAvg),
      safeAverage: round(safeAvg),
      delta: round(delta),
      recommendation:
        suggestedWeight > baseWeight
          ? "increase"
          : suggestedWeight < baseWeight
            ? "decrease"
            : "keep"
    };
  }

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(
    OUTPUT_PATH,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        feedbackCounts: {
          phishing: phishingRecords.length,
          safe: safeRecords.length
        },
        suggestions
      },
      null,
      2
    )
  );

  console.log(
    JSON.stringify(
      {
        ok: true,
        phishingFeedback: phishingRecords.length,
        safeFeedback: safeRecords.length,
        outputPath: OUTPUT_PATH
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
