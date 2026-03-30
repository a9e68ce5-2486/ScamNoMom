#!/usr/bin/env python3
"""
review_queue.py
───────────────
Interactive CLI for human review of low-confidence LLM labels.

Reads from:  data/review_queue/pending.jsonl
Writes to:   data/labeled/human_reviewed.jsonl
             data/review_queue/pending.jsonl  (removes reviewed items)

Usage:
  python3 scripts/pipeline/review_queue.py           # review all pending
  python3 scripts/pipeline/review_queue.py --limit 20  # review first 20

Controls (during review):
  s  → scam
  l  → safe (legit)
  u  → unclear / skip
  q  → quit (progress saved)
  ?  → show full text

Label shortcuts also accept full words: scam / safe / legit / unclear / skip / quit
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT          = Path(__file__).resolve().parents[2]
REVIEW_QUEUE_PATH  = REPO_ROOT / "data" / "review_queue" / "pending.jsonl"
HUMAN_REVIEWED_PATH = REPO_ROOT / "data" / "labeled" / "human_reviewed.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_pending() -> list[dict]:
    if not REVIEW_QUEUE_PATH.exists():
        return []
    records = []
    with open(REVIEW_QUEUE_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except Exception:
                    pass
    return records


def save_pending(records: list[dict]) -> None:
    REVIEW_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REVIEW_QUEUE_PATH, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def append_human_reviewed(record: dict) -> None:
    HUMAN_REVIEWED_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(HUMAN_REVIEWED_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


ATTACK_TYPE_CHOICES = [
    "credential_harvest", "brand_impersonation", "malware_delivery",
    "payment_fraud", "investment_scam", "customer_service_scam",
    "government_impersonation", "romance_scam", "phone_scam", "unknown",
]

CHANNEL_CHOICES = ["sms", "line", "email", "web", "phone", "other"]


def prompt_attack_type(current: str) -> str:
    print(f"\n  Attack type options:")
    for i, at in enumerate(ATTACK_TYPE_CHOICES, 1):
        marker = " ← current" if at == current else ""
        print(f"    {i:2}. {at}{marker}")
    while True:
        raw = input("  Select [number or enter to keep current]: ").strip()
        if not raw:
            return current
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(ATTACK_TYPE_CHOICES):
                return ATTACK_TYPE_CHOICES[idx]
        except ValueError:
            if raw in ATTACK_TYPE_CHOICES:
                return raw
        print("  Invalid. Try again.")


def prompt_channel(current: str) -> str:
    opts = ", ".join(f"{i+1}={c}" for i, c in enumerate(CHANNEL_CHOICES))
    while True:
        raw = input(f"  Channel [{opts}] (enter to keep '{current}'): ").strip()
        if not raw:
            return current
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(CHANNEL_CHOICES):
                return CHANNEL_CHOICES[idx]
        except ValueError:
            if raw in CHANNEL_CHOICES:
                return raw
        print("  Invalid.")


def review_record(record: dict, index: int, total: int) -> str | None:
    """
    Interactively review one record.
    Returns the chosen label ("scam" | "safe" | "unclear") or None if quit.
    """
    print("\n" + "─" * 70)
    print(f"  [{index}/{total}]  Source: {record.get('source')}  "
          f"  LLM label: {record.get('label','?').upper()}  "
          f"  conf={record.get('confidence','?'):.2f}"
          f"  [{record.get('attackType','?')}]")
    print(f"  URL: {record.get('url','')[:80]}")
    print(f"  Title: {record.get('title','')[:100]}")
    print()

    text = record.get("text", "")
    preview = text[:400].replace("\n", " ")
    print(f"  Preview: {preview}")
    if len(text) > 400:
        print("  … (type ? to see full text)")
    print()

    while True:
        raw = input("  Label [s=scam / l=safe / u=unclear / q=quit / ?=full text]: ").strip().lower()
        if raw in ("q", "quit"):
            return None
        if raw == "?":
            print("\n" + "=" * 70)
            print(text)
            print("=" * 70 + "\n")
            continue
        if raw in ("s", "scam"):
            return "scam"
        if raw in ("l", "safe", "legit"):
            return "safe"
        if raw in ("u", "unclear", "skip"):
            return "unclear"
        print("  Invalid input. Use s / l / u / q / ?")


def run(limit: int | None = None) -> dict:
    pending = load_pending()
    if not pending:
        print("No records in review queue. Run label_with_llm.py first.")
        return {"reviewed": 0, "remaining": 0}

    total = len(pending)
    target = min(total, limit) if limit else total
    print(f"Review queue: {total} pending records. Reviewing up to {target}.")
    print("Press Ctrl-C or type 'q' to stop at any time — progress is saved.\n")

    reviewed_ids: set[str] = set()
    stats = {"scam": 0, "safe": 0, "unclear": 0}

    try:
        for i, record in enumerate(pending[:target], 1):
            label = review_record(record, i, target)

            if label is None:
                print("\nQuitting — progress saved.")
                break

            # Allow correction of attackType and channel
            attack_type = record.get("attackType", "unknown")
            channel     = record.get("channel", "other")

            if label in ("scam", "safe"):
                correct = input("  Correct attackType/channel? [y/N]: ").strip().lower()
                if correct == "y":
                    attack_type = prompt_attack_type(attack_type)
                    channel     = prompt_channel(channel)

            human_record = {
                **record,
                "label":       label,
                "attackType":  attack_type,
                "channel":     channel,
                "labelSource": "human",
                "labeledAt":   _now(),
                # Keep original LLM output for audit trail
                "originalLlmLabel":      record.get("label"),
                "originalLlmConfidence": record.get("confidence"),
            }
            human_record["confidence"] = 1.0  # Human label = max confidence

            append_human_reviewed(human_record)
            reviewed_ids.add(record["id"])
            stats[label] += 1

    except KeyboardInterrupt:
        print("\n\nInterrupted — saving progress.")

    # Remove reviewed records from pending queue
    remaining = [r for r in pending if r["id"] not in reviewed_ids]
    save_pending(remaining)

    print(f"\n=== Review complete ===")
    print(f"  Reviewed: {len(reviewed_ids)}  (scam={stats['scam']}, safe={stats['safe']}, unclear={stats['unclear']})")
    print(f"  Remaining in queue: {len(remaining)}")
    print(f"  Written to: {HUMAN_REVIEWED_PATH}")

    return {
        "reviewed":  len(reviewed_ids),
        "remaining": len(remaining),
        "stats":     stats,
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Human review CLI for low-confidence labels")
    parser.add_argument("--limit", type=int, help="Max records to review in this session")
    args = parser.parse_args()
    run(limit=args.limit)
