# Data Pipeline

[繁體中文版本](./README.zh-TW.md)

This folder defines the training-data workflow for ScamNoMom.

## Layout

```text
data/
  raw/
    external/
    feedback/
  processed/
  schemas/
```

## Unified Sample Format

All training samples should be normalized into the schema described in:

- `data/schemas/training-sample.json`

Each sample should include:

- `sourceType`: `web`, `email`, or `url_feed`
- `label`: `safe` or `phishing`
- `content`: normalized text and metadata
- `signals`: structured features
- `provenance`: original dataset source

## Current Supported Inputs

### Auto-fetch feeds

Fetch the latest public feeds into `data/raw/external/`:

```bash
node scripts/fetch_feeds.mjs
```

Optional environment variables:

```bash
PHISHTANK_APP_KEY=your_app_key
PHISHTANK_USER_AGENT=scamnomom/your-name
OPENPHISH_FEED_URL=https://openphish.com/feed.txt
URLHAUS_FEED_URL=https://urlhaus.abuse.ch/downloads/csv_online/
PHISHING_ARMY_FEED_URL=https://phishing.army/download/phishing_army_blocklist_extended.txt
FEED_FETCH_RETRY_MAX=3
FEED_FETCH_TIMEOUT_MS=12000
FEED_FETCH_REQUIRE_ALL=false
```

### Extension feedback

Source file:

- `apps/api/data/feedback.json`

Transformation command:

```bash
node scripts/prepare_dataset.mjs
```

Output:

- `data/processed/training-samples.json`

### PhishTank

Place a downloaded PhishTank file in:

- `data/raw/external/phishtank.csv`
- or `data/raw/external/phishtank.json`

Supported fields:

- `url`
- `phish_url`
- `phish_id`
- `verification_time`
- `submission_time`

### OpenPhish

Place a downloaded OpenPhish file in:

- `data/raw/external/openphish.txt`
- or `data/raw/external/openphish.json`

Supported formats:

- plain text with one URL per line
- JSON array with `url`

## Build Combined Dataset

```bash
node scripts/fetch_feeds.mjs
node scripts/prepare_dataset.mjs
```

The script merges:

- extension feedback
- PhishTank URLs
- OpenPhish URLs
- URLhaus URLs
- Phishing Army URLs

into:

- `data/processed/training-samples.json`

## Planned External Sources

- Enron
- SpamAssassin

Add each source into `data/raw/external/` first, then extend `scripts/prepare_dataset.mjs`.

## Taiwan Brand Whitelist

Taiwan-facing brand and official domain mappings are stored in:

- `data/tw_brand_domains.json`

The backend rule engine uses the corresponding config to detect brand-domain mismatches for common Taiwan banking, e-commerce, payment, and logistics brands.

## Taiwan Scam Keywords

Common Taiwan scam and phishing phrases are stored in:

- `data/tw_scam_keywords.json`

The backend rule engine and fallback analyzer use the corresponding config categories for:

- credential prompts
- urgency language
- payment scams
- logistics scams
- prize scams

## Pattern Mining

You can mine emerging Taiwan scam phrases from the processed dataset:

```bash
node scripts/mine_tw_scam_patterns.mjs
```

Output:

- `data/processed/tw_scam_pattern_candidates.json`

This script produces:

- candidate new keywords
- candidate phrase pairs
- hot brand mentions

These candidates should be reviewed before being added to `data/tw_scam_keywords.json`.

## Promote Approved Keywords

1. Review:

- `data/processed/tw_scam_pattern_candidates.json`

2. Add approved items into:

- `data/processed/tw_scam_pattern_approvals.json`

3. Promote approved items into the live keyword set:

```bash
node scripts/promote_keywords.mjs
```

## Dashboard

Generate a local HTML dashboard for Taiwan scam trends:

```bash
node scripts/generate_tw_dashboard.mjs
```

Output:

- `data/processed/tw_dashboard.html`

The dashboard includes:

- sample counts
- source and attack-type breakdowns
- hot brand mentions
- high-confidence candidate keywords and phrases
- latest candidate keywords and phrases
- full candidate tables

## One-Command Pipeline

Run the full local intelligence pipeline:

```bash
node scripts/run_pipeline.mjs
```

This executes:

1. `fetch_feeds.mjs`
2. `prepare_dataset.mjs`
3. `mine_tw_scam_patterns.mjs`
4. `generate_tw_dashboard.mjs`

If you want to reuse already-downloaded feeds:

```bash
node scripts/run_pipeline.mjs --skip-fetch
```
