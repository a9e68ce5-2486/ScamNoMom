import { Router } from "express";
import { z } from "zod";
import { analyzeFeatures } from "../pipeline/analyze.js";
import { analyzeText } from "../pipeline/text-analyzer.js";

const pageFeaturesSchema = z.object({
  url: z.string().url(),
  hostname: z.string().min(1),
  source: z.enum(["web", "email"]),
  title: z.string().max(300).optional(),
  visibleText: z.string().max(8000).optional(),
  forms: z.object({
    total: z.number().int().min(0),
    passwordFields: z.number().int().min(0),
    externalSubmitCount: z.number().int().min(0)
  }),
  links: z.object({
    total: z.number().int().min(0),
    mismatchedTextCount: z.number().int().min(0),
    suspiciousTldCount: z.number().int().min(0),
    hostnames: z.array(z.string().min(1).max(255)).max(40),
    urls: z.array(z.string().url()).max(40)
  }),
  dom: z.object({
    hiddenElementCount: z.number().int().min(0),
    iframeCount: z.number().int().min(0)
  }),
  brandSignals: z.array(z.string().min(1).max(120)).max(40),
  email: z
    .object({
      provider: z.enum(["gmail", "outlook", "yahoo", "proton", "generic"]),
      subject: z.string().max(400).optional(),
      sender: z.string().max(320).optional(),
      replyTo: z.string().max(320).optional(),
      bodyText: z.string().max(8000).optional(),
      linkCount: z.number().int().min(0)
    })
    .optional()
});

export const analyzeRouter = Router();
const MAX_LINK_HOSTNAMES = 40;
const MAX_LINK_URLS = 40;

analyzeRouter.post("/", async (req, res) => {
  const parsed = pageFeaturesSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: "Invalid request payload",
      details: parsed.error.flatten()
    });
  }

  if (parsed.data.links.hostnames.length > MAX_LINK_HOSTNAMES || parsed.data.links.urls.length > MAX_LINK_URLS) {
    return res.status(400).json({
      error: "Too many link entries in payload",
      limits: {
        maxHostnames: MAX_LINK_HOSTNAMES,
        maxUrls: MAX_LINK_URLS
      }
    });
  }

  const result = await analyzeFeatures(parsed.data);
  return res.json(result);
});

const textAnalysisSchema = z.object({
  source: z.literal("text"),
  channel: z.enum(["sms", "line", "messenger", "telegram", "phone_transcript", "manual_report", "other"]),
  text: z.string().min(1).max(8000),
  title: z.string().max(300).optional(),
  claimedBrand: z.string().max(200).optional(),
  metadata: z
    .object({
      sender: z.string().max(200).optional(),
      contact: z.string().max(200).optional()
    })
    .optional()
});

analyzeRouter.post("/text", async (req, res) => {
  const parsed = textAnalysisSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: "Invalid text analysis payload",
      details: parsed.error.flatten()
    });
  }

  const result = await analyzeText(parsed.data);
  return res.json(result);
});
