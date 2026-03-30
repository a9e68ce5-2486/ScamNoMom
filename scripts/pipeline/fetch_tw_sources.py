#!/usr/bin/env python3
"""
fetch_tw_sources.py
───────────────────
Crawl Taiwan-specific scam/phishing data sources and save raw samples to
data/raw/tw/<source_name>.jsonl

Sources:
  ithome    — iThome security news (詐騙 / 釣魚 / 社交工程 tags)
  ptt       — PTT Gossiping + MayDay boards, keyword search
  165       — 165 Anti-Scam Hotline SPA (requires Playwright)
  twcert    — TWCERT/CC security knowledge articles (Playwright)

Each output record:
{
  "id":         "<source>_<sha1>",
  "source":     "<source_key>",
  "url":        "<original url>",
  "title":      "<article title>",
  "text":       "<cleaned body text>",
  "fetchedAt":  "<ISO timestamp>"
}

Usage:
  python3 scripts/pipeline/fetch_tw_sources.py               # all sources
  python3 scripts/pipeline/fetch_tw_sources.py --sources ithome ptt
  python3 scripts/pipeline/fetch_tw_sources.py --max-pages 10
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import requests
from bs4 import BeautifulSoup

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT  = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "data" / "raw" / "tw"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── HTTP helpers ───────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "zh-TW,zh;q=0.9,en;q=0.8",
}

def _get(url: str, timeout: int = 15, retries: int = 3,
         session: requests.Session | None = None) -> requests.Response | None:
    s = session or requests.Session()
    for attempt in range(1, retries + 1):
        try:
            resp = s.get(url, timeout=timeout, headers=HEADERS)
            resp.raise_for_status()
            resp.encoding = resp.apparent_encoding or "utf-8"
            return resp
        except Exception as exc:
            if attempt == retries:
                print(f"    [WARN] {url}: {exc}", file=sys.stderr)
                return None
            time.sleep(2 ** attempt)
    return None


def _soup(url: str, session: requests.Session | None = None) -> BeautifulSoup | None:
    resp = _get(url, session=session)
    return BeautifulSoup(resp.text, "lxml") if resp else None


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _stable_id(source: str, text: str) -> str:
    return f"{source}_{hashlib.sha1(text.encode()).hexdigest()[:12]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Source: iThome ─────────────────────────────────────────────────────────────
# iThome is Taiwan's largest IT media. Their security/scam coverage is excellent
# and the pages render fully in plain HTML.

ITHOME_BASE = "https://www.ithome.com.tw"
ITHOME_SEARCH_KEYWORDS = ["詐騙", "釣魚", "社交工程", "網路詐騙", "假客服", "假物流"]


def _ithome_article_urls(keyword: str, max_pages: int) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    encoded = requests.utils.quote(keyword)
    for page in range(1, max_pages + 1):
        list_url = f"{ITHOME_BASE}/tags/{encoded}"
        if page > 1:
            list_url += f"?page={page}"
        soup = _soup(list_url)
        if soup is None:
            break
        found = False
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "/news/" in href:
                full = href if href.startswith("http") else ITHOME_BASE + href
                if full not in seen:
                    seen.add(full)
                    urls.append(full)
                    found = True
        if not found:
            break
        time.sleep(0.4)
    return urls


def _ithome_article_text(url: str) -> tuple[str, str]:
    soup = _soup(url)
    if soup is None:
        return "", ""
    title_tag = soup.select_one("h1")
    title = _clean(title_tag.get_text()) if title_tag else ""
    body_tag = soup.select_one("article, .node-body, #content-main, .article-content")
    body = _clean(body_tag.get_text(" ")) if body_tag else ""
    return title, body


def fetch_ithome(max_pages: int = 5) -> Iterator[dict]:
    print("  Fetching iThome scam/security news…")
    seen_ids: set[str] = set()
    for keyword in ITHOME_SEARCH_KEYWORDS:
        article_urls = _ithome_article_urls(keyword, max_pages)
        for url in article_urls:
            title, body = _ithome_article_text(url)
            text = f"{title} {body}".strip()
            if len(text) < 40:
                continue
            rec_id = _stable_id("ithome", text)
            if rec_id in seen_ids:
                continue
            seen_ids.add(rec_id)
            yield {
                "id":        rec_id,
                "source":    "ithome",
                "url":       url,
                "title":     title,
                "text":      text[:6000],
                "fetchedAt": _now(),
            }
            time.sleep(0.3)


# ── Source: PTT ────────────────────────────────────────────────────────────────
# PTT is Taiwan's largest BBS. Gossiping board posts about scams often contain
# real scam message quotes or descriptions of social engineering tactics.

PTT_BASE   = "https://www.ptt.cc"
PTT_BOARDS = ["Gossiping", "MayDay"]
PTT_KEYWORDS = ["詐騙", "釣魚訊息", "假客服", "假物流", "投資詐騙", "LINE詐騙"]


def _ptt_session() -> requests.Session:
    s = requests.Session()
    s.cookies.set("over18", "1", domain="www.ptt.cc")
    return s


def _ptt_article_urls(board: str, keyword: str, max_pages: int,
                       session: requests.Session) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    encoded = requests.utils.quote(keyword)
    for page in range(1, max_pages + 1):
        search_url = f"{PTT_BASE}/bbs/{board}/search?q={encoded}&page={page}"
        soup = _soup(search_url, session=session)
        if soup is None:
            break
        items = soup.select(".r-ent")
        if not items:
            break
        for item in items:
            a = item.select_one("a[href]")
            if a is None:
                continue
            full_url = PTT_BASE + a["href"]
            if full_url not in seen:
                seen.add(full_url)
                urls.append(full_url)
        time.sleep(0.4)
    return urls


def _ptt_article_text(url: str, session: requests.Session) -> tuple[str, str]:
    resp = _get(url, session=session)
    if resp is None:
        return "", ""
    soup = BeautifulSoup(resp.text, "lxml")
    # Remove metadata and push sections
    for tag in soup.select(".push, .article-metaline, .article-metaline-right, #action-bar-container"):
        tag.decompose()
    content = soup.select_one("#main-content")
    if content is None:
        return "", ""
    # Extract title from article meta
    title_meta = soup.select_one(".article-meta-value")
    title = _clean(title_meta.get_text()) if title_meta else ""
    body = _clean(content.get_text(" "))
    # Remove PTT signature boilerplate
    body = re.split(r"--\s*\n.*批踢踢實業坊", body)[0].strip()
    return title, body


def fetch_ptt(max_pages: int = 3) -> Iterator[dict]:
    print("  Fetching PTT scam-related posts…")
    session = _ptt_session()
    seen_ids: set[str] = set()

    for board in PTT_BOARDS:
        for keyword in PTT_KEYWORDS:
            article_urls = _ptt_article_urls(board, keyword, max_pages, session)
            for url in article_urls:
                title, body = _ptt_article_text(url, session)
                text = f"{title} {body}".strip()
                if len(text) < 50:
                    continue
                rec_id = _stable_id("ptt", text)
                if rec_id in seen_ids:
                    continue
                seen_ids.add(rec_id)
                yield {
                    "id":        rec_id,
                    "source":    "ptt",
                    "url":       url,
                    "title":     title,
                    "text":      text[:6000],
                    "fetchedAt": _now(),
                }
                time.sleep(0.3)


# ── Source: 165 Hotline (Playwright SPA) ──────────────────────────────────────
# 165.npa.gov.tw is an Angular SPA. The API endpoint returns 504 when called
# directly, so we use Playwright to let the browser load and execute the JS.

NPA_165_BASE       = "https://165.npa.gov.tw"
NPA_165_ARTICLE_RE = re.compile(r"/#/articles?/(\d+)")


def fetch_165_playwright(max_pages: int = 5) -> Iterator[dict]:
    print("  Fetching 165 anti-scam hotline via Playwright…")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("    [WARN] playwright not installed. Skipping 165 hotline.", file=sys.stderr)
        return

    seen_ids: set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_extra_http_headers({"Accept-Language": "zh-TW,zh;q=0.9"})

        for page_num in range(1, max_pages + 1):
            url = f"{NPA_165_BASE}/#/articles/{page_num}"
            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
                page.wait_for_timeout(2000)  # let Angular render
            except Exception as exc:
                print(f"    [WARN] playwright timeout on {url}: {exc}", file=sys.stderr)
                break

            soup = BeautifulSoup(page.content(), "lxml")
            # Typical Angular renders article cards with links
            article_links = [
                a["href"] for a in soup.select("a[href]")
                if "article" in a.get("href", "").lower() or NPA_165_ARTICLE_RE.search(a.get("href", ""))
            ]

            if not article_links:
                # No articles found — try extracting visible text from the page
                main = soup.select_one("main, app-root, #app")
                if main:
                    text = _clean(main.get_text(" "))
                    if len(text) > 80:
                        rec_id = _stable_id("165_hotline", text)
                        if rec_id not in seen_ids:
                            seen_ids.add(rec_id)
                            yield {
                                "id":        rec_id,
                                "source":    "165_hotline",
                                "url":       url,
                                "title":     f"165 hotline page {page_num}",
                                "text":      text[:6000],
                                "fetchedAt": _now(),
                            }
                continue

            for href in article_links:
                article_url = href if href.startswith("http") else NPA_165_BASE + href
                if article_url in seen_ids:
                    continue
                try:
                    page.goto(article_url, wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(1500)
                except Exception:
                    continue

                detail_soup = BeautifulSoup(page.content(), "lxml")
                title_tag = detail_soup.select_one("h1, h2, .article-title")
                title = _clean(title_tag.get_text()) if title_tag else ""
                body_tag = detail_soup.select_one("main, app-root, .article-body, #content")
                body = _clean(body_tag.get_text(" ")) if body_tag else ""
                text = f"{title} {body}".strip()
                if len(text) < 40:
                    continue
                rec_id = _stable_id("165_hotline", text)
                if rec_id in seen_ids:
                    continue
                seen_ids.add(rec_id)
                yield {
                    "id":        rec_id,
                    "source":    "165_hotline",
                    "url":       article_url,
                    "title":     title,
                    "text":      text[:6000],
                    "fetchedAt": _now(),
                }
                time.sleep(0.5)

        browser.close()


# ── Source: TWCERT knowledge articles (Playwright) ────────────────────────────

TWCERT_KNOWLEDGE_URL = "https://www.twcert.org.tw/tw/lp-14-1.html"
TWCERT_BASE          = "https://www.twcert.org.tw"


def fetch_twcert_playwright(max_pages: int = 3) -> Iterator[dict]:
    print("  Fetching TWCERT security knowledge via Playwright…")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("    [WARN] playwright not installed. Skipping TWCERT.", file=sys.stderr)
        return

    seen_ids: set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_extra_http_headers({"Accept-Language": "zh-TW,zh;q=0.9"})

        for page_num in range(1, max_pages + 1):
            list_url = (TWCERT_KNOWLEDGE_URL if page_num == 1
                        else f"https://www.twcert.org.tw/tw/lp-14-{page_num}.html")
            try:
                page.goto(list_url, wait_until="networkidle", timeout=20000)
                page.wait_for_timeout(1500)
            except Exception as exc:
                print(f"    [WARN] {list_url}: {exc}", file=sys.stderr)
                break

            soup = BeautifulSoup(page.content(), "lxml")
            links = [
                (TWCERT_BASE + a["href"] if not a["href"].startswith("http") else a["href"])
                for a in soup.select("a[href]")
                if "/tw/cp-" in a.get("href", "") and any(
                    c > "\u4e00" for c in a.get_text()
                )
            ]

            if not links:
                break

            for article_url in links:
                if article_url in seen_ids:
                    continue
                try:
                    page.goto(article_url, wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(1000)
                except Exception:
                    continue

                detail = BeautifulSoup(page.content(), "lxml")
                title_tag = detail.select_one("h1, h2, .title")
                title = _clean(title_tag.get_text()) if title_tag else ""
                body_tag = detail.select_one(".article-content, article, main")
                body = _clean(body_tag.get_text(" ")) if body_tag else ""
                text = f"{title} {body}".strip()
                if len(text) < 40:
                    continue
                rec_id = _stable_id("twcert", text)
                if rec_id in seen_ids:
                    continue
                seen_ids.add(rec_id)
                yield {
                    "id":        rec_id,
                    "source":    "twcert",
                    "url":       article_url,
                    "title":     title,
                    "text":      text[:6000],
                    "fetchedAt": _now(),
                }
                time.sleep(0.5)

        browser.close()


# ── Dedup & save ──────────────────────────────────────────────────────────────

def load_existing_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    ids: set[str] = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                ids.add(json.loads(line.strip())["id"])
            except Exception:
                pass
    return ids


def run(sources: list[str] | None = None, max_pages: int = 5) -> dict:
    all_sources: dict[str, object] = {
        "ithome":      lambda: fetch_ithome(max_pages),
        "ptt":         lambda: fetch_ptt(min(max_pages, 3)),
        "165_hotline": lambda: fetch_165_playwright(max_pages),
        "twcert":      lambda: fetch_twcert_playwright(min(max_pages, 3)),
    }
    targets = {k: v for k, v in all_sources.items()
               if sources is None or k in sources}

    stats: dict[str, dict] = {}

    for source_key, generator_fn in targets.items():
        out_path = OUTPUT_DIR / f"{source_key}.jsonl"
        existing_ids = load_existing_ids(out_path)
        new_count = skip_count = 0

        print(f"\n[{source_key}]")
        with open(out_path, "a", encoding="utf-8") as f:
            for record in generator_fn():
                if record["id"] in existing_ids:
                    skip_count += 1
                    continue
                existing_ids.add(record["id"])
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                new_count += 1
                print(f"    + {record['title'][:60]}")

        total = len(existing_ids)
        print(f"  → new: {new_count}, skipped (dup): {skip_count}, total: {total}")
        stats[source_key] = {"new": new_count, "skipped": skip_count, "total": total}

    return stats


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fetch Taiwan scam data sources")
    parser.add_argument("--sources",   nargs="*", help="Sources to fetch: ithome ptt 165_hotline twcert")
    parser.add_argument("--max-pages", type=int, default=5, help="Max pages per source (default: 5)")
    args = parser.parse_args()

    # Install Playwright browser on first run if needed
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            try:
                p.chromium.launch(headless=True).close()
            except Exception:
                print("Installing Playwright Chromium…")
                import subprocess
                subprocess.run(["playwright", "install", "chromium"], check=True)
    except ImportError:
        pass

    print("=== fetch_tw_sources.py ===")
    stats = run(sources=args.sources, max_pages=args.max_pages)
    print("\n=== Summary ===")
    print(json.dumps(stats, indent=2, ensure_ascii=False))
