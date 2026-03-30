#!/usr/bin/env python3
"""
label_with_llm.py
─────────────────
Read raw records from data/raw/tw/*.jsonl (and optionally data/raw/external/),
send each one to OpenAI for structured labeling, then route:

  confidence >= CONFIDENCE_THRESHOLD  →  data/labeled/auto_labeled.jsonl
  confidence <  CONFIDENCE_THRESHOLD  →  data/review_queue/pending.jsonl

Output schema (per record):
{
  "id":           "<stable id>",
  "source":       "<source_key>",
  "url":          "<origin url>",
  "title":        "<title>",
  "text":         "<body text>",
  "label":        "scam" | "safe" | "unclear",
  "attackType":   "<attack_type or null>",
  "channel":      "sms" | "line" | "email" | "web" | "other",
  "language":     "zh-TW" | "en" | "mixed",
  "confidence":   0.0–1.0,
  "labelSource":  "llm_auto" | "llm_reviewed" | "human",
  "llmModel":     "<model name>",
  "labeledAt":    "<ISO timestamp>",
  "rawLlmOutput": { ... }   # kept for auditing / re-labeling
}

Active-learning routing:
  The confidence threshold starts at 0.80.
  Records that land in review_queue are the most valuable training signal —
  they should be human-reviewed and fed back as "human" labeledSource.

Usage:
  python3 scripts/pipeline/label_with_llm.py
  python3 scripts/pipeline/label_with_llm.py --source 165_hotline --limit 50
  python3 scripts/pipeline/label_with_llm.py --relabel-low-confidence
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from openai import OpenAI

# ── Config ────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_TW_DIR      = REPO_ROOT / "data" / "raw" / "tw"
RAW_EXT_DIR     = REPO_ROOT / "data" / "raw" / "external"
LABELED_DIR     = REPO_ROOT / "data" / "labeled"
REVIEW_DIR      = REPO_ROOT / "data" / "review_queue"

LABELED_DIR.mkdir(parents=True, exist_ok=True)
REVIEW_DIR.mkdir(parents=True, exist_ok=True)

AUTO_LABELED_PATH   = LABELED_DIR / "auto_labeled.jsonl"
REVIEW_QUEUE_PATH   = REVIEW_DIR  / "pending.jsonl"
PROGRESS_PATH       = LABELED_DIR / ".progress.json"  # tracks already-labeled IDs

CONFIDENCE_THRESHOLD = 0.80   # below this → review queue
DEFAULT_MODEL        = "gpt-4o-mini"  # cheap, fast, good at structured output
BATCH_DELAY_SEC      = 0.5    # politeness delay between API calls

ATTACK_TYPES = [
    "credential_harvest",
    "brand_impersonation",
    "malware_delivery",
    "payment_fraud",
    "investment_scam",
    "customer_service_scam",
    "government_impersonation",
    "romance_scam",
    "phone_scam",
    "unknown",
]

LABEL_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "scam_label",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "label": {
                    "type": "string",
                    "enum": ["scam", "safe", "unclear"]
                },
                "attackType": {
                    "type": "string",
                    "enum": ATTACK_TYPES
                },
                "channel": {
                    "type": "string",
                    "enum": ["sms", "line", "email", "web", "phone", "other"]
                },
                "language": {
                    "type": "string",
                    "enum": ["zh-TW", "en", "mixed"]
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0
                },
                "reasoning": {
                    "type": "string"
                }
            },
            "required": ["label", "attackType", "channel", "language", "confidence", "reasoning"]
        }
    }
}

SYSTEM_PROMPT = """\
You are an expert scam and phishing analyst specializing in Taiwan cybercrime.
Your task is to label text samples as scam, safe, or unclear.

Label definitions:
- "scam":   the text is a scam message, phishing attempt, or describes a known scam pattern.
            This includes: fake logistics notices, investment fraud, fake customer service,
            government impersonation, romance scams, credential harvesting.
- "safe":   the text is a legitimate notification, news article, or advisory warning
            ABOUT scams (e.g., a government article explaining how a scam works is "safe" —
            it describes scam patterns but is itself not a scam message).
- "unclear": insufficient information or genuinely ambiguous.

Attack type: select the most specific type even if label is "safe" (e.g. an article about
fake logistics notices → attackType = "payment_fraud").

Channel: best guess for how this would be delivered to a victim (sms, line, email, web, phone).
For news/advisory articles use "web".

Be conservative with confidence:
- 0.95+ only when the content is unambiguously one category
- 0.80–0.94 when fairly confident but some ambiguity exists
- Below 0.80 when genuinely uncertain

Focus on Traditional Chinese scam patterns common in Taiwan:
假客服解除分期、假物流、投資詐騙、感情詐騙、假政府通知、釣魚網站、OTP詐騙
"""


# ── Progress tracking ─────────────────────────────────────────────────────────

def load_progress() -> set[str]:
    if not PROGRESS_PATH.exists():
        return set()
    try:
        data = json.loads(PROGRESS_PATH.read_text(encoding="utf-8"))
        return set(data.get("labeled_ids", []))
    except Exception:
        return set()


def save_progress(labeled_ids: set[str]) -> None:
    PROGRESS_PATH.write_text(
        json.dumps({"labeled_ids": sorted(labeled_ids), "updatedAt": _now()},
                   ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Raw record reader ─────────────────────────────────────────────────────────

def iter_raw_records(sources: list[str] | None = None) -> Iterator[dict]:
    dirs = [RAW_TW_DIR, RAW_EXT_DIR]
    for raw_dir in dirs:
        if not raw_dir.exists():
            continue
        for path in sorted(raw_dir.glob("*.jsonl")):
            source_key = path.stem
            if sources and source_key not in sources:
                continue
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except Exception:
                        pass


# ── LLM labeling ─────────────────────────────────────────────────────────────

def label_record(client: OpenAI, record: dict, model: str) -> dict:
    """Call OpenAI and return a labeled record dict."""
    text_excerpt = record.get("text", "")[:3000]
    title = record.get("title", "")

    user_message = f"Title: {title}\n\nContent:\n{text_excerpt}"

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
        response_format=LABEL_SCHEMA,
        temperature=0.1,
    )

    raw = response.choices[0].message.content
    parsed = json.loads(raw)

    return {
        "id":           record["id"],
        "source":       record.get("source", "unknown"),
        "url":          record.get("url", ""),
        "title":        title,
        "text":         record.get("text", ""),
        "label":        parsed["label"],
        "attackType":   parsed["attackType"],
        "channel":      parsed["channel"],
        "language":     parsed["language"],
        "confidence":   round(float(parsed["confidence"]), 4),
        "labelSource":  "llm_auto",
        "llmModel":     model,
        "labeledAt":    _now(),
        "rawLlmOutput": parsed,
    }


# ── Main runner ───────────────────────────────────────────────────────────────

def run(
    sources: list[str] | None = None,
    limit: int | None = None,
    model: str = DEFAULT_MODEL,
    confidence_threshold: float = CONFIDENCE_THRESHOLD,
    relabel_low_confidence: bool = False,
) -> dict:
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        print("ERROR: OPENAI_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    client = OpenAI(api_key=api_key)
    labeled_ids = load_progress()

    # If relabeling low-confidence records, remove them from the "done" set
    if relabel_low_confidence:
        low_conf_ids = _load_low_confidence_ids(confidence_threshold)
        labeled_ids -= low_conf_ids
        print(f"  Re-labeling {len(low_conf_ids)} low-confidence records…")

    stats = {
        "auto_labeled": 0,
        "review_queue": 0,
        "skipped":      0,
        "errors":       0,
    }

    processed = 0

    with (
        open(AUTO_LABELED_PATH, "a", encoding="utf-8") as auto_f,
        open(REVIEW_QUEUE_PATH, "a", encoding="utf-8") as review_f,
    ):
        for record in iter_raw_records(sources):
            if limit is not None and processed >= limit:
                break

            rec_id = record.get("id", "")
            if rec_id in labeled_ids:
                stats["skipped"] += 1
                continue

            try:
                labeled = label_record(client, record, model)
            except Exception as exc:
                print(f"  [ERROR] {rec_id}: {exc}", file=sys.stderr)
                stats["errors"] += 1
                continue

            conf = labeled["confidence"]
            line = json.dumps(labeled, ensure_ascii=False) + "\n"

            if conf >= confidence_threshold:
                auto_f.write(line)
                stats["auto_labeled"] += 1
                marker = "✓"
            else:
                review_f.write(line)
                stats["review_queue"] += 1
                marker = "?"

            labeled_ids.add(rec_id)
            processed += 1

            label_str  = labeled["label"].upper()
            attack_str = labeled["attackType"]
            print(f"  [{marker}] {rec_id[:30]:<30} {label_str:<7} conf={conf:.2f}  [{attack_str}]")

            # Save progress every 20 records so we can resume on crash
            if processed % 20 == 0:
                save_progress(labeled_ids)

            time.sleep(BATCH_DELAY_SEC)

    save_progress(labeled_ids)
    return stats


def _load_low_confidence_ids(threshold: float) -> set[str]:
    ids: set[str] = set()
    for path in [AUTO_LABELED_PATH, REVIEW_QUEUE_PATH]:
        if not path.exists():
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                    if rec.get("confidence", 1.0) < threshold:
                        ids.add(rec["id"])
                except Exception:
                    pass
    return ids


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Label raw scam samples with LLM")
    parser.add_argument("--sources", nargs="*", help="Source keys to process (default: all)")
    parser.add_argument("--limit",   type=int,  help="Max records to label per run")
    parser.add_argument("--model",   default=DEFAULT_MODEL, help=f"OpenAI model (default: {DEFAULT_MODEL})")
    parser.add_argument("--threshold", type=float, default=CONFIDENCE_THRESHOLD,
                        help=f"Confidence threshold for auto vs review (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("--relabel-low-confidence", action="store_true",
                        help="Re-label records below the confidence threshold")
    args = parser.parse_args()

    print("=== label_with_llm.py ===")
    print(f"  model:     {args.model}")
    print(f"  threshold: {args.threshold}")

    stats = run(
        sources=args.sources,
        limit=args.limit,
        model=args.model,
        confidence_threshold=args.threshold,
        relabel_low_confidence=args.relabel_low_confidence,
    )

    print("\n=== Summary ===")
    print(json.dumps(stats, indent=2))
