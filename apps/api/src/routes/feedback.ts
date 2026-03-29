import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { Router } from "express";
import { z } from "zod";

const analysisSchema = z.object({
  source: z.enum(["web", "email", "text"]),
  riskLevel: z.enum(["low", "medium", "high"]),
  score: z.number().min(0).max(100),
  reasons: z.array(z.string()),
  confidence: z.number().min(0).max(1),
  attackType: z.enum([
    "credential_harvest",
    "brand_impersonation",
    "malware_delivery",
    "payment_fraud",
    "investment_scam",
    "customer_service_scam",
    "government_impersonation",
    "romance_scam",
    "phone_scam",
    "unknown"
  ]),
  recommendedAction: z.enum(["allow", "warn", "escalate", "block"]),
  needsAgent: z.boolean(),
  analyzedAt: z.string(),
  provider: z.enum(["openai", "ollama", "fallback"]),
  agent: z
    .object({
      executed: z.boolean(),
      score: z.number().min(0).max(100),
      confidence: z.number().min(0).max(1),
      reasons: z.array(z.string()),
      attackType: z
        .enum([
          "credential_harvest",
          "brand_impersonation",
          "malware_delivery",
          "payment_fraud",
          "investment_scam",
          "customer_service_scam",
          "government_impersonation",
          "romance_scam",
          "phone_scam",
          "unknown"
        ])
        .optional(),
      redirectFindings: z
        .array(
          z.object({
            originalUrl: z.string(),
            finalUrl: z.string(),
            hopCount: z.number().int().min(0)
          })
        )
        .optional(),
      threatIntel: z
        .object({
          checkedHostnames: z.array(z.string()),
          blacklistMatches: z.array(z.string()),
          riskyIpHosts: z.array(z.string()),
          dnsFindings: z.array(
            z.object({
              hostname: z.string(),
              aRecordCount: z.number().int().min(0),
              nsRecordCount: z.number().int().min(0),
              mxRecordCount: z.number().int().min(0),
              hasSpfRecord: z.boolean(),
              lookupError: z.string().optional()
            })
          ),
          external: z
            .object({
              enabled: z.boolean(),
              rdap: z
                .object({
                  hostname: z.string(),
                  registrationDate: z.string().optional(),
                  lastChangedDate: z.string().optional(),
                  registrar: z.string().optional(),
                  domainAgeDays: z.number().int().min(0).optional()
                })
                .optional(),
              blacklist: z
                .object({
                  checked: z.boolean(),
                  listed: z.boolean(),
                  provider: z.string().optional(),
                  reason: z.string().optional()
                })
                .optional(),
              providers: z
                .array(
                  z.object({
                    provider: z.string(),
                    checked: z.boolean(),
                    scoreDelta: z.number(),
                    confidence: z.number().min(0).max(1),
                    reasons: z.array(z.string())
                  })
                )
                .optional(),
              policy: z
                .object({
                  providerCount: z.number().int().min(0),
                  positiveProviderCount: z.number().int().min(0),
                  rawScoreDelta: z.number().min(0),
                  adjustedScoreDelta: z.number().min(0),
                  finalScoreDelta: z.number().min(0),
                  confidence: z.number().min(0).max(1),
                  capApplied: z.boolean(),
                  penaltyApplied: z.boolean()
                })
                .optional()
            })
            .optional(),
          emailAuth: z
            .object({
              domain: z.string(),
              mxRecordCount: z.number().int().min(0),
              hasSpfRecord: z.boolean(),
              hasDmarcRecord: z.boolean(),
              dmarcPolicy: z.enum(["none", "quarantine", "reject"]).optional(),
              discoverableDkimSelectors: z.array(z.string()),
              checkedDkimSelectors: z.array(z.string())
            })
            .optional()
        })
        .optional()
    })
    .optional(),
  evidence: z.object({
    ruleScore: z.number(),
    llmScore: z.number(),
    mlScore: z.number().optional(),
    urlRiskScore: z.number().optional(),
    routerDecision: z.enum(["allow", "warn", "escalate", "block"]),
    agentScore: z.number().optional(),
    initialRouterDecision: z.enum(["allow", "warn", "escalate", "block"]).optional(),
    enrichment: z
      .object({
        liveDomUsed: z.boolean(),
        skippedReason: z.string().optional(),
        cacheHit: z.boolean().optional()
      })
      .optional(),
    modelContributions: z
      .object({
        rule: z.number(),
        llm: z.number(),
        urlRisk: z.number(),
        ml: z.number()
      })
      .optional(),
    modelVersion: z.string().optional()
  })
});

const featuresSchema = z.object({
  url: z.string().url(),
  hostname: z.string(),
  source: z.enum(["web", "email"]),
  title: z.string().optional(),
  visibleText: z.string().optional(),
  forms: z.object({
    total: z.number().int().min(0),
    passwordFields: z.number().int().min(0),
    externalSubmitCount: z.number().int().min(0)
  }),
  links: z.object({
    total: z.number().int().min(0),
    mismatchedTextCount: z.number().int().min(0),
    suspiciousTldCount: z.number().int().min(0),
    hostnames: z.array(z.string()).optional(),
    urls: z.array(z.string().url()).optional()
  }),
  dom: z.object({
    hiddenElementCount: z.number().int().min(0),
    iframeCount: z.number().int().min(0)
  }),
  brandSignals: z.array(z.string()),
  urlSignals: z
    .object({
      dotCount: z.number().int().min(0).max(30).optional(),
      hyphenCount: z.number().int().min(0).max(30).optional(),
      digitCount: z.number().int().min(0).max(40).optional(),
      length: z.number().int().min(0).max(2048).optional(),
      hasIpHost: z.boolean().optional(),
      hasAtSymbol: z.boolean().optional(),
      hasPunycode: z.boolean().optional(),
      hasHexEncoding: z.boolean().optional(),
      hasSuspiciousPathKeyword: z.boolean().optional(),
      hasSuspiciousQueryKeyword: z.boolean().optional(),
      hasLongHostname: z.boolean().optional(),
      hasManySubdomains: z.boolean().optional(),
      isShortenerHost: z.boolean().optional()
    })
    .optional(),
  enrichment: z
    .object({
      attempted: z.boolean(),
      success: z.boolean(),
      method: z.enum(["none", "live_dom"]),
      cacheHit: z.boolean(),
      latencyMs: z.number().int().min(0).optional(),
      error: z.string().optional()
    })
    .optional(),
  email: z
    .object({
      provider: z.enum(["gmail", "outlook", "yahoo", "proton", "generic"]),
      subject: z.string().optional(),
      sender: z.string().optional(),
      replyTo: z.string().optional(),
      bodyText: z.string().optional(),
      linkCount: z.number().int().min(0)
    })
    .optional()
});

const learningEventSchema = z.object({
  type: z.enum(["ignore_once", "trusted_host"]),
  createdAt: z.string(),
  reason: z.string().max(200).optional(),
  analysis: analysisSchema.optional(),
  features: featuresSchema.optional()
});

const feedbackSchema = z.object({
  label: z.enum(["safe", "phishing"]),
  notes: z.string().max(500).optional(),
  analysis: analysisSchema,
  features: featuresSchema,
  context: z
    .object({
      feedbackEvents: z.array(learningEventSchema).max(120).optional()
    })
    .optional()
});

const DATA_DIR = path.resolve(process.cwd(), "data");
const FEEDBACK_FILE = path.join(DATA_DIR, "feedback.json");
const FEEDBACK_EVENTS_FILE = path.join(DATA_DIR, "feedback-events.json");

async function ensureStore() {
  await mkdir(DATA_DIR, { recursive: true });
}

async function readFeedbackRecords() {
  await ensureStore();

  try {
    const raw = await readFile(FEEDBACK_FILE, "utf8");
    return JSON.parse(raw) as unknown[];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }

    throw error;
  }
}

async function writeFeedbackRecords(records: unknown[]) {
  await ensureStore();
  await writeFile(FEEDBACK_FILE, JSON.stringify(records, null, 2));
}

async function readFeedbackEventRecords() {
  await ensureStore();
  try {
    const raw = await readFile(FEEDBACK_EVENTS_FILE, "utf8");
    return JSON.parse(raw) as unknown[];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

async function writeFeedbackEventRecords(records: unknown[]) {
  await ensureStore();
  await writeFile(FEEDBACK_EVENTS_FILE, JSON.stringify(records, null, 2));
}

export const feedbackRouter = Router();

interface FeedbackRecordPayload extends z.infer<typeof feedbackSchema> {
  id: string;
  createdAt: string;
  feedbackSignals?: {
    ignoreOnce: boolean;
    trustedHost: boolean;
    likelyFalsePositive: boolean;
    likelyMissedPhish: boolean;
  };
}

feedbackRouter.post("/", async (req, res) => {
  const parsed = feedbackSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: "Invalid feedback payload",
      details: parsed.error.flatten()
    });
  }

  const records = await readFeedbackRecords();
  const record: FeedbackRecordPayload = {
    id: `fb_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    createdAt: new Date().toISOString(),
    ...parsed.data
  };

  if (record.analysis?.source === "web" || record.analysis?.source === "email") {
    const feedbackSignals = {
      ignoreOnce: record.label === "safe" && record.analysis?.recommendedAction !== "allow",
      trustedHost: record.label === "safe" && record.analysis?.recommendedAction === "warn",
      likelyFalsePositive: record.label === "safe" && Number(record.analysis?.score || 0) >= 55,
      likelyMissedPhish: record.label === "phishing" && Number(record.analysis?.score || 0) <= 45
    };
    record.feedbackSignals = feedbackSignals;
  }

  records.push(record);
  await writeFeedbackRecords(records);

  const contextEvents = parsed.data.context?.feedbackEvents || [];
  if (contextEvents.length > 0) {
    const eventRecords = await readFeedbackEventRecords();
    const now = Date.now();
    const maxAgeMs = 30 * 24 * 60 * 60 * 1000;
    const filtered = eventRecords.filter((item) => {
      const candidate = item as { createdAt?: string } | null;
      const ts = Date.parse(String(candidate?.createdAt || ""));
      return Number.isFinite(ts) && now - ts <= maxAgeMs;
    });
    const appended = contextEvents.map((event) => ({
      id: `fbe_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      linkedFeedbackId: record.id,
      ...event
    }));
    await writeFeedbackEventRecords([...filtered, ...appended].slice(-1200));
  }

  return res.json({
    ok: true,
    recordId: record.id,
    totalRecords: records.length
  });
});

feedbackRouter.get("/stats", async (_req, res) => {
  const records = (await readFeedbackRecords()) as Array<{ label?: string }>;
  const phishing = records.filter((record) => record.label === "phishing").length;
  const safe = records.filter((record) => record.label === "safe").length;

  return res.json({
    ok: true,
    totalRecords: records.length,
    labels: {
      phishing,
      safe
    }
  });
});
