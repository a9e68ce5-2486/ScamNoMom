import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const FIXTURE_PATH = path.join(ROOT, "data/benchmarks/threat-intel-policy-fixtures.json");

function makeProviderResult(input) {
  return {
    provider: String(input.provider || "unknown"),
    checked: input.checked !== false,
    scoreDelta: Number(input.scoreDelta || 0),
    confidence: Number(input.confidence || 0),
    reasons: Array.isArray(input.reasons) ? input.reasons : []
  };
}

async function loadFixtureCases() {
  const raw = await readFile(FIXTURE_PATH, "utf8");
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed : [];
}

async function runTests() {
  const [{ applyThreatIntelPolicy }, { getThreatIntelConfig }, fixtureCases] = await Promise.all([
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/pipeline/external-threat-intel.js")).href),
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/config/threat-intel.js")).href),
    loadFixtureCases()
  ]);

  const config = getThreatIntelConfig();

  for (const testCase of fixtureCases) {
    const providers = Array.isArray(testCase.providers) ? testCase.providers.map(makeProviderResult) : [];
    const result = applyThreatIntelPolicy(providers, config);

    if (typeof testCase.expected?.finalScoreDelta === "number") {
      assert.equal(result.finalScoreDelta, testCase.expected.finalScoreDelta, `${testCase.id}: finalScoreDelta`);
    }
    if (typeof testCase.expected?.penaltyApplied === "boolean") {
      assert.equal(result.penaltyApplied, testCase.expected.penaltyApplied, `${testCase.id}: penaltyApplied`);
    }
    if (typeof testCase.expected?.capApplied === "boolean") {
      assert.equal(result.capApplied, testCase.expected.capApplied, `${testCase.id}: capApplied`);
    }
    if (typeof testCase.expected?.positiveProviderCount === "number") {
      assert.equal(result.positiveProviderCount, testCase.expected.positiveProviderCount, `${testCase.id}: positiveProviderCount`);
    }
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        fixtureCount: fixtureCases.length
      },
      null,
      2
    )
  );
}

runTests();
