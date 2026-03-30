#!/usr/bin/env python3
"""
label_with_llm.py
─────────────────
Read raw records from data/raw/tw/*.jsonl (and optionally data/raw/external/),
send each one to an LLM for structured labeling, then route:

  confidence >= CONFIDENCE_THRESHOLD  →  data/labeled/auto_labeled.jsonl
  confidence <  CONFIDENCE_THRESHOLD  →  data/review_queue/pending.jsonl

Supported backends (auto-detected, or set via --backend):
  ollama   — local Ollama server (default if no OpenAI key; free)
  openai   — OpenAI API (requires OPENAI_API_KEY in env or apps/api/.env)

Usage:
  python3 scripts/pipeline/label_with_llm.py
  python3 scripts/pipeline/label_with_llm.py --backend ollama --limit 50
  python3 scripts/pipeline/label_with_llm.py --relabel-low-confidence
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT       = Path(__file__).resolve().parents[2]
RAW_TW_DIR      = REPO_ROOT / "data" / "raw" / "tw"
RAW_EXT_DIR     = REPO_ROOT / "data" / "raw" / "external"
LABELED_DIR     = REPO_ROOT / "data" / "labeled"
REVIEW_DIR      = REPO_ROOT / "data" / "review_queue"

LABELED_DIR.mkdir(parents=True, exist_ok=True)
REVIEW_DIR.mkdir(parents=True, exist_ok=True)

AUTO_LABELED_PATH  = LABELED_DIR / "auto_labeled.jsonl"
REVIEW_QUEUE_PATH  = REVIEW_DIR  / "pending.jsonl"
PROGRESS_PATH      = LABELED_DIR / ".progress.json"

# ── Config ────────────────────────────────────────────────────────────────────

CONFIDENCE_THRESHOLD    = 0.80
DEFAULT_OPENAI_MODEL    = "gpt-4o-mini"
DEFAULT_OLLAMA_MODEL    = "qwen3:8b"
DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
BATCH_DELAY_SEC         = 0.8   # slightly longer for Ollama (local CPU/GPU)

ATTACK_TYPES = [
    "credential_harvest", "brand_impersonation", "malware_delivery",
    "payment_fraud", "investment_scam", "customer_service_scam",
    "government_impersonation", "romance_scam", "phone_scam", "unknown",
]

SYSTEM_PROMPT = """\
You are an expert scam and phishing analyst specializing in Taiwan cybercrime.
Your task is to label text samples as scam, safe, or unclear.

Label definitions:
- "scam":   the text IS a scam message, phishing attempt, or describes a known scam
            pattern in a way that could deceive a victim. Includes: fake logistics
            notices, investment fraud, fake customer service, government impersonation,
            romance scams, credential harvesting.
- "safe":   legitimate content — news articles, government advisories, or warnings
            ABOUT scams (e.g. a news article explaining how a scam works is "safe").
- "unclear": insufficient information or genuinely ambiguous.

attackType: pick the most specific type even when label="safe".
channel: how this would reach a victim — sms / line / email / web / phone / other.
         For news/advisory articles use "web".
confidence: 0.95+ only when unambiguous; 0.80–0.94 when fairly certain; <0.80 uncertain.

Taiwanese scam patterns to recognise:
假客服解除分期、假物流、投資詐騙、感情詐騙、假政府通知、釣魚網站、OTP詐騙

IMPORTANT: respond ONLY with valid JSON, no extra text, no markdown fences.
JSON schema:
{
  "label":      "scam" | "safe" | "unclear",
  "attackType": "credential_harvest|brand_impersonation|malware_delivery|payment_fraud|investment_scam|customer_service_scam|government_impersonation|romance_scam|phone_scam|unknown",
  "channel":    "sms|line|email|web|phone|other",
  "language":   "zh-TW|en|mixed",
  "confidence": 0.0-1.0,
  "reasoning":  "one sentence"
}
"""

OPENAI_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "scam_label",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "label":      {"type": "string", "enum": ["scam", "safe", "unclear"]},
                "attackType": {"type": "string", "enum": ATTACK_TYPES},
                "channel":    {"type": "string", "enum": ["sms", "line", "email", "web", "phone", "other"]},
                "language":   {"type": "string", "enum": ["zh-TW", "en", "mixed"]},
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "reasoning":  {"type": "string"},
            },
            "required": ["label", "attackType", "channel", "language", "confidence", "reasoning"],
        },
    },
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_env_key(key_name: str) -> str:
    """Read a key from os.environ or fall back to apps/api/.env."""
    val = os.environ.get(key_name, "").strip()
    if val:
        return val
    env_path = REPO_ROOT / "apps" / "api" / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            m = re.match(rf"^{key_name}=(.+)", line.strip())
            if m:
                return m.group(1).strip().strip('"').strip("'")
    return ""


def _extract_json(raw: str) -> dict:
    """Extract first JSON object from a string (handles Ollama extra text)."""
    raw = raw.strip()
    # Strip <think>...</think> blocks that Qwen3 emits
    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
    start = raw.find("{")
    end   = raw.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON object found in: {raw[:200]}")
    return json.loads(raw[start:end + 1])


def _normalize(parsed: dict, model_name: str, record: dict) -> dict:
    label       = parsed.get("label", "unclear")
    attack_type = parsed.get("attackType", "unknown")
    channel     = parsed.get("channel", "other")
    language    = parsed.get("language", "zh-TW")
    confidence  = float(parsed.get("confidence", 0.5))

    if label not in ("scam", "safe", "unclear"):
        label = "unclear"
    if attack_type not in ATTACK_TYPES:
        attack_type = "unknown"
    if channel not in ("sms", "line", "email", "web", "phone", "other"):
        channel = "other"
    confidence = max(0.0, min(1.0, confidence))

    return {
        "id":           record["id"],
        "source":       record.get("source", "unknown"),
        "url":          record.get("url", ""),
        "title":        record.get("title", ""),
        "text":         record.get("text", ""),
        "label":        label,
        "attackType":   attack_type,
        "channel":      channel,
        "language":     language,
        "confidence":   round(confidence, 4),
        "labelSource":  "llm_auto",
        "llmModel":     model_name,
        "labeledAt":    _now(),
        "rawLlmOutput": parsed,
    }


# ── OpenAI backend ────────────────────────────────────────────────────────────

def _label_openai(record: dict, model: str, client) -> dict:
    text = record.get("text", "")[:3000]
    title = record.get("title", "")
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": f"Title: {title}\n\nContent:\n{text}"},
        ],
        response_format=OPENAI_RESPONSE_FORMAT,
        temperature=0.1,
    )
    parsed = json.loads(response.choices[0].message.content)
    return _normalize(parsed, model, record)


# ── Ollama backend ────────────────────────────────────────────────────────────

def _label_ollama(record: dict, model: str, base_url: str) -> dict:
    import urllib.request
    text  = record.get("text", "")[:3000]
    title = record.get("title", "")
    prompt = f"Title: {title}\n\nContent:\n{text}"

    payload = json.dumps({
        "model":  model,
        "stream": False,
        "format": "json",
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "options": {"temperature": 0.1},
    }).encode()

    req = urllib.request.Request(
        f"{base_url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())

    raw_text = data.get("response", "")
    parsed   = _extract_json(raw_text)
    return _normalize(parsed, model, record)


# ── Progress tracking ─────────────────────────────────────────────────────────

def load_progress() -> set[str]:
    if not PROGRESS_PATH.exists():
        return set()
    try:
        return set(json.loads(PROGRESS_PATH.read_text(encoding="utf-8")).get("labeled_ids", []))
    except Exception:
        return set()


def save_progress(labeled_ids: set[str]) -> None:
    PROGRESS_PATH.write_text(
        json.dumps({"labeled_ids": sorted(labeled_ids), "updatedAt": _now()},
                   ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


# ── Raw record reader ─────────────────────────────────────────────────────────

def iter_raw_records(sources: list[str] | None = None) -> Iterator[dict]:
    for raw_dir in [RAW_TW_DIR, RAW_EXT_DIR]:
        if not raw_dir.exists():
            continue
        for path in sorted(raw_dir.glob("*.jsonl")):
            if sources and path.stem not in sources:
                continue
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except Exception:
                            pass


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


# ── Main runner ───────────────────────────────────────────────────────────────

def resolve_backend(backend: str | None) -> tuple[str, dict]:
    """
    Returns (backend_name, config_dict).
    Auto-detect: prefer OpenAI if key exists, else Ollama.
    """
    if backend is None:
        openai_key = _read_env_key("OPENAI_API_KEY")
        backend = "openai" if openai_key else "ollama"

    if backend == "openai":
        key = _read_env_key("OPENAI_API_KEY")
        if not key:
            print("ERROR: OPENAI_API_KEY not set. Use --backend ollama or add key to apps/api/.env.",
                  file=sys.stderr)
            sys.exit(1)
        model = _read_env_key("OPENAI_MODEL") or DEFAULT_OPENAI_MODEL
        return "openai", {"api_key": key, "model": model}

    if backend == "ollama":
        base_url = _read_env_key("OLLAMA_BASE_URL") or DEFAULT_OLLAMA_BASE_URL
        model    = _read_env_key("OLLAMA_MODEL")    or DEFAULT_OLLAMA_MODEL
        # Quick connectivity check
        import urllib.request
        try:
            urllib.request.urlopen(f"{base_url}/api/tags", timeout=5)
        except Exception as exc:
            print(f"ERROR: Cannot reach Ollama at {base_url}: {exc}", file=sys.stderr)
            print("Make sure Ollama is running:  ollama serve", file=sys.stderr)
            sys.exit(1)
        return "ollama", {"base_url": base_url, "model": model}

    print(f"ERROR: Unknown backend '{backend}'. Use 'openai' or 'ollama'.", file=sys.stderr)
    sys.exit(1)


def run(
    sources: list[str] | None = None,
    limit: int | None = None,
    backend: str | None = None,
    confidence_threshold: float = CONFIDENCE_THRESHOLD,
    relabel_low_confidence: bool = False,
) -> dict:
    backend_name, cfg = resolve_backend(backend)

    # Build labeler function
    if backend_name == "openai":
        from openai import OpenAI
        client = OpenAI(api_key=cfg["api_key"])
        model  = cfg["model"]
        def label_fn(record: dict) -> dict:
            return _label_openai(record, model, client)
    else:
        base_url = cfg["base_url"]
        model    = cfg["model"]
        def label_fn(record: dict) -> dict:
            return _label_ollama(record, model, base_url)

    print(f"  backend : {backend_name}")
    print(f"  model   : {model}")
    print(f"  threshold: {confidence_threshold}")

    labeled_ids = load_progress()
    if relabel_low_confidence:
        low_conf_ids = _load_low_confidence_ids(confidence_threshold)
        labeled_ids -= low_conf_ids
        print(f"  re-labeling {len(low_conf_ids)} low-confidence records")

    stats = {"auto_labeled": 0, "review_queue": 0, "skipped": 0, "errors": 0}
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
                labeled = label_fn(record)
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

            print(f"  [{marker}] {rec_id[:28]:<28} "
                  f"{labeled['label'].upper():<7} "
                  f"conf={conf:.2f}  [{labeled['attackType']}]")

            if processed % 20 == 0:
                save_progress(labeled_ids)

            time.sleep(BATCH_DELAY_SEC)

    save_progress(labeled_ids)
    return stats


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Label raw scam samples with LLM")
    parser.add_argument("--sources",   nargs="*", help="Source keys to process (default: all)")
    parser.add_argument("--limit",     type=int,  help="Max records to label per run")
    parser.add_argument("--backend",   choices=["openai", "ollama"],
                        help="LLM backend (default: auto — openai if key set, else ollama)")
    parser.add_argument("--threshold", type=float, default=CONFIDENCE_THRESHOLD,
                        help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")
    parser.add_argument("--relabel-low-confidence", action="store_true",
                        help="Re-label records below the confidence threshold")
    args = parser.parse_args()

    print("=== label_with_llm.py ===")
    stats = run(
        sources=args.sources,
        limit=args.limit,
        backend=args.backend,
        confidence_threshold=args.threshold,
        relabel_low_confidence=args.relabel_low_confidence,
    )
    print("\n=== Summary ===")
    print(json.dumps(stats, indent=2))
