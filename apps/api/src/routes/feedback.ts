import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { Router } from "express";
import { z } from "zod";

const analysisSchema = z.object({
  source: z.enum(["web", "email"]),
  riskLevel: z.enum(["low", "medium", "high"]),
  score: z.number().min(0).max(100),
  reasons: z.array(z.string()),
  confidence: z.number().min(0).max(1),
  attackType: z.enum([
    "credential_harvest",
    "brand_impersonation",
    "malware_delivery",
    "payment_fraud",
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
          "unknown"
        ])
        .optional()
    })
    .optional(),
  evidence: z.object({
    ruleScore: z.number(),
    llmScore: z.number(),
    routerDecision: z.enum(["allow", "warn", "escalate", "block"]),
    agentScore: z.number().optional(),
    initialRouterDecision: z.enum(["allow", "warn", "escalate", "block"]).optional()
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

const feedbackSchema = z.object({
  label: z.enum(["safe", "phishing"]),
  notes: z.string().max(500).optional(),
  analysis: analysisSchema,
  features: featuresSchema
});

const DATA_DIR = path.resolve(process.cwd(), "data");
const FEEDBACK_FILE = path.join(DATA_DIR, "feedback.json");

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

export const feedbackRouter = Router();

feedbackRouter.post("/", async (req, res) => {
  const parsed = feedbackSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: "Invalid feedback payload",
      details: parsed.error.flatten()
    });
  }

  const records = await readFeedbackRecords();
  const record = {
    id: `fb_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    createdAt: new Date().toISOString(),
    ...parsed.data
  };

  records.push(record);
  await writeFeedbackRecords(records);

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
