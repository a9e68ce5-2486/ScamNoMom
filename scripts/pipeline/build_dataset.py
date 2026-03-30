#!/usr/bin/env python3
"""
build_dataset.py
────────────────
Merge all labeled sources (auto-labeled + human-reviewed) into a clean,
deduplicated, stratified dataset ready for model training.

Input:
  data/labeled/auto_labeled.jsonl
  data/labeled/human_reviewed.jsonl   (output of review_queue.py)

Output:
  data/processed/dataset/
    train.jsonl        (80%)
    val.jsonl          (10%)
    test.jsonl         (10%)
    stats.json         (label / source / attack_type distribution)

Rules:
  - Human-reviewed records always override auto-labeled ones with the same id
  - Records with label="unclear" are excluded from train/val, kept in test only
  - Minimum text length: 20 chars
  - Deduplication: by id, then by text hash (near-duplicate removal)
  - Stratified split: preserves scam/safe ratio in each split

Usage:
  python3 scripts/pipeline/build_dataset.py
  python3 scripts/pipeline/build_dataset.py --no-unclear
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT   = Path(__file__).resolve().parents[2]
LABELED_DIR = REPO_ROOT / "data" / "labeled"
OUTPUT_DIR  = REPO_ROOT / "data" / "processed" / "dataset"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

AUTO_LABELED_PATH    = LABELED_DIR / "auto_labeled.jsonl"
HUMAN_REVIEWED_PATH  = LABELED_DIR / "human_reviewed.jsonl"

TRAIN_RATIO = 0.80
VAL_RATIO   = 0.10
# TEST_RATIO  = 1 - TRAIN_RATIO - VAL_RATIO  = 0.10

RANDOM_SEED = 42


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text_hash(text: str) -> str:
    normalized = " ".join(text.lower().split())
    return hashlib.sha1(normalized.encode()).hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                pass
    return records


def save_jsonl(records: list[dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ── Merge & deduplicate ───────────────────────────────────────────────────────

def merge_sources() -> list[dict]:
    auto     = load_jsonl(AUTO_LABELED_PATH)
    human    = load_jsonl(HUMAN_REVIEWED_PATH)

    # Human labels always win — build override map first
    human_by_id = {r["id"]: r for r in human}

    merged: dict[str, dict] = {}
    for rec in auto:
        rec_id = rec.get("id", "")
        if rec_id:
            merged[rec_id] = rec

    # Human overrides
    for rec_id, rec in human_by_id.items():
        merged[rec_id] = rec

    return list(merged.values())


def clean_and_dedup(records: list[dict], min_text_len: int = 20) -> list[dict]:
    seen_text_hashes: set[str] = set()
    clean: list[dict] = []

    for rec in records:
        text = rec.get("text", "").strip()
        if len(text) < min_text_len:
            continue

        th = _text_hash(text)
        if th in seen_text_hashes:
            continue
        seen_text_hashes.add(th)

        clean.append(rec)

    return clean


# ── Stratified split ──────────────────────────────────────────────────────────

def stratified_split(
    records: list[dict],
    include_unclear_in_test: bool = True,
) -> tuple[list[dict], list[dict], list[dict]]:
    rng = random.Random(RANDOM_SEED)

    # Separate by label
    by_label: dict[str, list[dict]] = defaultdict(list)
    for rec in records:
        by_label[rec.get("label", "unclear")].append(rec)

    train, val, test = [], [], []

    for label, recs in by_label.items():
        if label == "unclear":
            if include_unclear_in_test:
                test.extend(recs)
            continue

        rng.shuffle(recs)
        n = len(recs)
        n_train = int(n * TRAIN_RATIO)
        n_val   = int(n * VAL_RATIO)

        train.extend(recs[:n_train])
        val.extend(recs[n_train : n_train + n_val])
        test.extend(recs[n_train + n_val :])

    rng.shuffle(train)
    rng.shuffle(val)
    rng.shuffle(test)

    return train, val, test


# ── Stats ─────────────────────────────────────────────────────────────────────

def compute_stats(train: list, val: list, test: list) -> dict:
    def split_stats(records: list) -> dict:
        labels      = Counter(r.get("label")      for r in records)
        attack_types = Counter(r.get("attackType") for r in records)
        sources     = Counter(r.get("source")      for r in records)
        channels    = Counter(r.get("channel")     for r in records)
        label_srcs  = Counter(r.get("labelSource") for r in records)
        return {
            "count":       len(records),
            "labels":      dict(labels),
            "attackTypes": dict(attack_types),
            "sources":     dict(sources),
            "channels":    dict(channels),
            "labelSources": dict(label_srcs),
        }

    return {
        "generatedAt": _now(),
        "total": len(train) + len(val) + len(test),
        "train": split_stats(train),
        "val":   split_stats(val),
        "test":  split_stats(test),
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def run(include_unclear_in_test: bool = True) -> dict:
    print("Merging labeled sources…")
    merged = merge_sources()
    print(f"  Raw merged: {len(merged)} records")

    cleaned = clean_and_dedup(merged)
    print(f"  After dedup/clean: {len(cleaned)} records")

    if not cleaned:
        print("  No records to split. Run fetch_tw_sources.py + label_with_llm.py first.")
        return {"total": 0}

    train, val, test = stratified_split(cleaned, include_unclear_in_test)
    print(f"  Split → train: {len(train)}, val: {len(val)}, test: {len(test)}")

    save_jsonl(train, OUTPUT_DIR / "train.jsonl")
    save_jsonl(val,   OUTPUT_DIR / "val.jsonl")
    save_jsonl(test,  OUTPUT_DIR / "test.jsonl")

    stats = compute_stats(train, val, test)
    (OUTPUT_DIR / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"\nDataset written to {OUTPUT_DIR}/")
    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build train/val/test dataset from labeled data")
    parser.add_argument("--no-unclear", action="store_true",
                        help="Exclude 'unclear' records entirely (default: include in test only)")
    args = parser.parse_args()

    stats = run(include_unclear_in_test=not args.no_unclear)

    print("\n=== Stats ===")
    print(json.dumps(stats, indent=2, ensure_ascii=False))
