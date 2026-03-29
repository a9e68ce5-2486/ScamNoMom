import "dotenv/config";
import cors from "cors";
import express from "express";
import { analyzeRouter } from "./routes/analyze.js";
import { feedbackRouter } from "./routes/feedback.js";

const app = express();
const port = Number(process.env.PORT ?? 8787);

app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "scamnomom-api",
    message: "ScamNoMom API is running.",
    endpoints: {
      health: "GET /health",
      analyze: "POST /analyze",
      analyzeText: "POST /analyze/text",
      feedback: "POST /feedback",
      feedbackStats: "GET /feedback/stats"
    }
  });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "scamnomom-api" });
});

app.use("/analyze", analyzeRouter);
app.use("/feedback", feedbackRouter);

app.use((_req, res) => {
  res.status(404).json({
    ok: false,
    error: "Route not found"
  });
});

app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const message = error instanceof Error ? error.message : "Unexpected server error";
  res.status(500).json({
    ok: false,
    error: message
  });
});

app.listen(port, () => {
  console.log(`ScamNoMom API listening on http://localhost:${port}`);
});
