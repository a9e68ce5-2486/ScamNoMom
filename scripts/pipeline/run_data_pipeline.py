#!/usr/bin/env python3
"""
run_data_pipeline.py
────────────────────
One-command entry point for the full data collection → labeling → dataset pipeline.

Steps:
  1. fetch    — scrape Taiwan scam sources  (fetch_tw_sources.py)
  2. label    — LLM auto-label new records  (label_with_llm.py)
  3. build    — merge + split dataset       (build_dataset.py)

Usage:
  python3 scripts/pipeline/run_data_pipeline.py                # full pipeline
  python3 scripts/pipeline/run_data_pipeline.py --skip-fetch   # skip scraping (reuse cached raw)
  python3 scripts/pipeline/run_data_pipeline.py --skip-label   # skip LLM (reuse cached labels)
  python3 scripts/pipeline/run_data_pipeline.py --label-limit 100  # label at most 100 new records
  python3 scripts/pipeline/run_data_pipeline.py --max-pages 10     # deeper scrape

Environment variables required for step 2:
  OPENAI_API_KEY

Notes:
  - Each step is idempotent — safe to re-run; already-processed records are skipped.
  - If OPENAI_API_KEY is missing, step 2 is skipped with a warning and the pipeline
    continues to step 3 (build from whatever is already labeled).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Allow importing sibling modules from the same package directory
sys.path.insert(0, str(Path(__file__).parent))

import build_dataset
import fetch_tw_sources
import label_with_llm


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _header(title: str) -> None:
    width = 60
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def run(
    skip_fetch:  bool = False,
    skip_label:  bool = False,
    max_pages:   int  = 5,
    label_limit: int | None = None,
    sources:     list[str] | None = None,
    label_model: str = label_with_llm.DEFAULT_MODEL,
    confidence_threshold: float = label_with_llm.CONFIDENCE_THRESHOLD,
) -> dict:
    started_at = _now()
    pipeline_stats: dict = {"startedAt": started_at, "steps": {}}

    # ── Step 1: Fetch ─────────────────────────────────────────────────────────
    if skip_fetch:
        print("\n[Step 1/3] fetch_tw_sources — SKIPPED (--skip-fetch)")
        pipeline_stats["steps"]["fetch"] = "skipped"
    else:
        _header("Step 1/3 — Fetching Taiwan scam sources")
        t0 = time.time()
        fetch_stats = fetch_tw_sources.run(sources=sources, max_pages=max_pages)
        elapsed = round(time.time() - t0, 1)
        pipeline_stats["steps"]["fetch"] = {**fetch_stats, "elapsed_sec": elapsed}
        print(f"\n  Done in {elapsed}s")

    # ── Step 2: Label ─────────────────────────────────────────────────────────
    if skip_label:
        print("\n[Step 2/3] label_with_llm — SKIPPED (--skip-label)")
        pipeline_stats["steps"]["label"] = "skipped"
    elif not os.environ.get("OPENAI_API_KEY"):
        print("\n[Step 2/3] label_with_llm — SKIPPED (OPENAI_API_KEY not set)")
        print("  Set OPENAI_API_KEY to enable automatic LLM labeling.")
        pipeline_stats["steps"]["label"] = "skipped_no_api_key"
    else:
        _header("Step 2/3 — LLM auto-labeling")
        t0 = time.time()
        label_stats = label_with_llm.run(
            sources=sources,
            limit=label_limit,
            model=label_model,
            confidence_threshold=confidence_threshold,
        )
        elapsed = round(time.time() - t0, 1)
        pipeline_stats["steps"]["label"] = {**label_stats, "elapsed_sec": elapsed}

        if label_stats.get("review_queue", 0) > 0:
            print(f"\n  {label_stats['review_queue']} records need human review.")
            print("  Run:  python3 scripts/pipeline/review_queue.py")

        print(f"\n  Done in {elapsed}s")

    # ── Step 3: Build dataset ─────────────────────────────────────────────────
    _header("Step 3/3 — Building train/val/test dataset")
    t0 = time.time()
    dataset_stats = build_dataset.run()
    elapsed = round(time.time() - t0, 1)
    pipeline_stats["steps"]["build"] = {**dataset_stats, "elapsed_sec": elapsed}
    print(f"\n  Done in {elapsed}s")

    # ── Summary ───────────────────────────────────────────────────────────────
    pipeline_stats["finishedAt"] = _now()
    total = dataset_stats.get("total", 0)
    train_count = dataset_stats.get("train", {}).get("count", 0)
    val_count   = dataset_stats.get("val",   {}).get("count", 0)
    test_count  = dataset_stats.get("test",  {}).get("count", 0)

    print("\n" + "=" * 60)
    print("  Pipeline complete")
    print(f"  Dataset total:  {total} records")
    print(f"  Train / Val / Test:  {train_count} / {val_count} / {test_count}")

    if total < 500:
        print(f"\n  NOTE: {total} records is below the 500-record threshold.")
        print("  Keep running the pipeline daily to accumulate more data.")
        print("  Train a fastText model when you reach ~500 records.")

    print("=" * 60)
    return pipeline_stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Full data collection → labeling → dataset pipeline")
    parser.add_argument("--skip-fetch",  action="store_true", help="Skip web scraping step")
    parser.add_argument("--skip-label",  action="store_true", help="Skip LLM labeling step")
    parser.add_argument("--max-pages",   type=int, default=5,  help="Max pages per source to scrape")
    parser.add_argument("--label-limit", type=int,             help="Max new records to label per run")
    parser.add_argument("--sources",     nargs="*",            help="Source keys to process (default: all)")
    parser.add_argument("--model",       default=label_with_llm.DEFAULT_MODEL,
                                         help=f"OpenAI model for labeling (default: {label_with_llm.DEFAULT_MODEL})")
    parser.add_argument("--threshold",   type=float, default=label_with_llm.CONFIDENCE_THRESHOLD,
                                         help=f"Confidence threshold (default: {label_with_llm.CONFIDENCE_THRESHOLD})")
    args = parser.parse_args()

    stats = run(
        skip_fetch=args.skip_fetch,
        skip_label=args.skip_label,
        max_pages=args.max_pages,
        label_limit=args.label_limit,
        sources=args.sources,
        label_model=args.model,
        confidence_threshold=args.threshold,
    )

    print("\n=== Full pipeline stats ===")
    print(json.dumps(stats, indent=2, ensure_ascii=False))
