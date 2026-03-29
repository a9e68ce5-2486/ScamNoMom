# ScamNoMom

[繁體中文詳細版](./README.zh-TW.md)

ScamNoMom 是一個以瀏覽器端為核心的詐騙與釣魚偵測專案，重點放在：

- 可疑連結與導流網址
- 釣魚網站
- Webmail 釣魚郵件
- 台灣常見詐騙話術與品牌冒用

目前是可實際執行的 local-first MVP，主要組成包含：

- `Chrome Extension (MV3)`：特徵擷取、頁面警告、popup 與設定頁
- `Node.js + TypeScript API`：規則引擎、LLM 分析、Agent-ready second pass
- `OpenAI` 或 `Ollama/Qwen`：語意分析
- `Feedback + Dataset + Dashboard + Evaluation`：持續優化流程
- `Local + optional external threat intel`：DNS, feed, RDAP, and blacklist second pass
- `Email auth intelligence`：domain-level SPF / DKIM / DMARC signals for webmail analysis

快速入口：

- 中文說明文件：[README.zh-TW.md](./README.zh-TW.md)
- 安裝方式：[INSTALL.zh-TW.md](./INSTALL.zh-TW.md)
- 目前架構：[docs/current-architecture.zh-TW.md](./docs/current-architecture.zh-TW.md)

目前最重要的能力：

- 一般網站與 Webmail 的釣魚風險分析
- Gmail / Outlook / Yahoo / Proton Mail 支援
- 台灣品牌白名單與詐騙話術規則
- 中風險案例的 redirect / short-link / DNS / local feed second pass
- 純文字訊息與對話詐騙分析：`POST /analyze/text`
- 使用者回饋、資料整理、評估與規則權重調整
- 內建 smoke tests、benchmark dataset 與環境 doctor 檢查

目前仍待補強的重點：

- 真正外部 threat intel：WHOIS、domain age、blacklist、DNS
- 更完整的 email authenticity：SPF / DKIM / DMARC
- 更完整的測試與 benchmark dataset
- 更成熟的正式發佈與安裝體驗

---

## English Summary

[Full Traditional Chinese README](./README.zh-TW.md)

ScamNoMom is a hybrid phishing and scam detection project focused on:

- phishing websites
- webmail phishing messages
- Taiwan-specific scam language and brand impersonation

The current implementation is a local-first MVP built with:

- `Chrome Extension (MV3)` for feature extraction, popup UI, and in-page warnings
- `Node.js + TypeScript` backend for risk scoring
- `OpenAI` or `Ollama/Qwen` for semantic analysis
- `Rule engine + feedback loop + dataset pipeline` for continuous improvement

## What This Project Does

This project can currently analyze:

- general phishing websites
- Gmail
- Outlook Web
- Yahoo Mail
- Proton Mail

It detects risk using a hybrid pipeline:

1. Extract page or email features in the browser
2. Send normalized features to the local API
3. Score with deterministic rules
4. Score with an LLM or fallback heuristic analyzer
5. Combine scores and route a final decision
6. Show warning UI in the popup and on the page
7. Collect user feedback for later learning

## Methods Used

### 1. Rule-Based Detection

The backend rule engine checks for high-signal phishing indicators such as:

- password fields
- external form submissions
- mismatched link text and destination
- suspicious top-level domains
- hidden elements and iframe-heavy pages
- brand-domain mismatch
- Taiwan scam language

Rule logic lives in:

- [rule-engine.ts](./apps/api/src/pipeline/rule-engine.ts)

### 2. LLM-Based Semantic Analysis

The backend supports:

- `OpenAI Responses API`
- `Ollama` with local models such as `qwen3:8b`
- built-in heuristic fallback if no model is available

LLM analysis evaluates:

- impersonation
- credential harvesting intent
- urgency language
- payment-fraud patterns
- email-specific scam context

LLM logic lives in:

- [llm-analyzer.ts](./apps/api/src/pipeline/llm-analyzer.ts)

### 3. Taiwan-Specific Scam Adaptation

The project is explicitly adapted for Taiwan scam patterns using:

- Taiwan brand whitelist: [tw_brand_domains.json](./data/tw_brand_domains.json)
- Taiwan scam keyword sets: [tw_scam_keywords.json](./data/tw_scam_keywords.json)

This enables detection of:

- fake bank pages
- fake e-commerce notifications
- fake logistics messages
- installment-payment scams
- payment-link scams
- account verification scams written in Traditional Chinese

### 4. Browser-Side Feature Extraction

The extension extracts:

- page text
- forms
- links
- suspicious domains
- brand mentions
- webmail subject/sender/body signals

Feature extraction lives in:

- [content.js](./apps/extension/content.js)

### 5. Human-in-the-Loop Learning

The extension popup allows users to label samples as:

- `Mark Safe`
- `Mark Phishing`

These labels are saved to:

- `apps/api/data/feedback.json`

Feedback is then converted into a training-ready dataset and used to mine emerging scam phrases.

## Repository Structure

```text
.
├── apps
│   ├── api
│   │   ├── src
│   │   │   ├── config
│   │   │   ├── pipeline
│   │   │   ├── routes
│   │   │   └── types
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── extension
│       ├── manifest.json
│       ├── content.js
│       ├── popup.html
│       ├── popup.css
│       ├── popup.js
│       └── service-worker.js
├── data
│   ├── processed
│   ├── raw
│   ├── schemas
│   ├── tw_brand_domains.json
│   └── tw_scam_keywords.json
├── docs
└── scripts
```

## Current Features

### Extension

- popup risk dashboard
- in-page warning overlay
- manual rescan button
- development-only debug capture
- feedback buttons for learning

### Backend

- `/` service summary
- `/health`
- `POST /analyze`
- `POST /analyze/text`
- `POST /feedback`
- `GET /feedback/stats`

### Webmail Support

- Gmail
- Outlook Web
- Yahoo Mail
- Proton Mail

### Taiwan-Specific Intelligence

- official brand-domain mismatch checks
- brand mismatch checks on linked domains
- Traditional Chinese scam keyword categories
- candidate phrase mining for emerging scam language

## How ScamNoMom Differs From Similar Tools

Products in a nearby category usually fall into a few groups:

- browser security extensions focused on malicious-site blocking or reputation
- antivirus vendor browser protection products
- email security tools focused on enterprise mail filtering

Those tools are often strong at:

- known malicious URL blocking
- reputation and blacklist lookups
- large-scale threat-intelligence coverage

`ScamNoMom` is positioned differently.

Its main differences are:

- it uses a `Rule + LLM + Agent-ready` hybrid pipeline instead of only blacklist logic
- it supports both `web pages + webmail`
- it is adapted for Taiwan-specific scam language and brand impersonation
- it can run with local `Ollama/Qwen` for privacy-first deployments
- it includes feedback collection, dataset preparation, pattern mining, and dashboards

## ScamNoMom Advantages

### 1. Not Limited to Known Bad URLs

Many security extensions rely heavily on:

- known blacklists
- domain reputation
- fixed blocking rules

`ScamNoMom` also analyzes:

- rule-based page signals
- semantic content
- brand impersonation
- Taiwan scam language
- webmail context

This makes it more useful against new phishing variants that may not yet exist in public blocklists.

### 2. Better Fit for Taiwan Scam Patterns

This is one of the biggest differentiators.

The project already includes:

- Taiwan brand-domain whitelists
- Taiwan scam keyword categories
- impersonation checks for banking, e-commerce, payment, and logistics brands
- Traditional Chinese fraud language such as verification, installment-payment scams, payment prompts, and delivery notices

That makes it more locally relevant than many general-purpose tools built around English-first or global-only threat patterns.

### 3. Webmail-Aware Analysis

Many browser protection tools focus on:

- the URL
- the domain reputation
- whether the page itself is malicious

`ScamNoMom` also supports:

- Gmail
- Outlook Web
- Yahoo Mail
- Proton Mail

and can analyze sender, subject, message body, and embedded links together.

### 4. Local-First Deployment Option

When used with `Ollama`, the system can run locally. That gives you:

- stronger privacy control
- lower recurring API cost
- a better base for custom research and on-device deployments

### 5. Built to Learn Over Time

This project is not only a static detector. It already includes the foundations for continuous improvement:

- feedback collection
- dataset preparation
- emerging scam phrase mining
- dashboard reporting
- evaluation pipeline

That makes `ScamNoMom` closer to an extensible anti-scam platform than a fixed browser add-on.

## Target Users

`ScamNoMom` is especially suited for:

- everyday users who want extra protection against phishing websites and scam messages
- people who frequently use Gmail, Outlook, Yahoo Mail, or Proton Mail
- Taiwan users who often encounter scams involving banks, logistics, e-commerce, and payment services
- developers and researchers working on localized anti-scam tooling
- users who prefer privacy-first deployments with local LLMs

## Typical Use Cases

The current system is especially useful for:

- warning users directly on suspicious websites
- checking webmail messages for fake verification, fake logistics, and fake payment notices
- analyzing Traditional Chinese scam language such as installment-payment scams, account alerts, delivery notices, and prize scams
- collecting feedback to improve rules and datasets over time
- monitoring emerging scam phrases and brand impersonation trends with the local dashboard

## Why This Is Not Just Another Blacklist Extension

A blacklist-oriented extension is usually strongest when dealing with:

- known malicious URLs
- domains that have already been reported
- samples that already exist in public threat feeds

But real phishing campaigns often:

- rotate domains quickly
- use new short links
- rewrite text while keeping the same scam intent
- target local users with localized brands and language

`ScamNoMom` is designed to cover that gap.

It does not try to replace reputation or blacklist systems. Instead, it adds:

- new-variant detection
- semantic reasoning
- mail-content context
- Taiwan-localized scam detection
- a learning and evaluation workflow

## How To Run

### 1. Start the API

```bash
cd apps/api
npm install
npm run dev
```

Available endpoints:

- `GET http://localhost:8787/`
- `GET http://localhost:8787/health`
- `POST http://localhost:8787/analyze`
- `POST http://localhost:8787/feedback`
- `GET http://localhost:8787/feedback/stats`

### 2. Configure LLM Provider

Create `apps/api/.env` from:

- [`.env.example`](./apps/api/.env.example)

OpenAI mode:

```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=your_server_side_key
OPENAI_MODEL=gpt-5.2
```

Ollama mode:

```bash
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen3:8b
```

Auto fallback:

```bash
LLM_PROVIDER=auto
```

If no model is available, the backend falls back to the local heuristic analyzer.

### 3. Load the Chrome Extension

1. Open `chrome://extensions`
2. Enable Developer Mode
3. Click `Load unpacked`
4. Select:
   - `./apps/extension`

### 4. Test It

Try it on:

- general websites
- login or suspicious phishing pages
- Gmail / Outlook / Yahoo / Proton message pages

Open the popup to inspect:

- risk score
- action recommendation
- provider used
- attack type
- source type
- mail provider

## Learning and Dataset Workflow

### Feedback Collection

Users can label analyzed content from the popup. Feedback is stored locally and later normalized into a training format.

### Dataset Preparation

Prepare a unified dataset:

```bash
node scripts/prepare_dataset.mjs
```

Output:

- [training-samples.json](./data/processed/training-samples.json)

### Auto-Fetch Public Feeds

Fetch phishing URL feeds:

```bash
node scripts/fetch_feeds.mjs
```

Supported sources:

- PhishTank
- OpenPhish

### Mine Emerging Taiwan Scam Patterns

```bash
node scripts/mine_tw_scam_patterns.mjs
```

Output:

- [tw_scam_pattern_candidates.json](./data/processed/tw_scam_pattern_candidates.json)

This produces:

- candidate keywords
- candidate phrases
- predicted categories
- confidence estimates
- hot brand mentions

### Approve and Promote New Scam Keywords

Edit:

- [tw_scam_pattern_approvals.json](./data/processed/tw_scam_pattern_approvals.json)

Then run:

```bash
node scripts/promote_keywords.mjs
```

This safely merges approved items into:

- [tw_scam_keywords.json](./data/tw_scam_keywords.json)

### Generate Local Dashboard

```bash
node scripts/generate_tw_dashboard.mjs
```

Output:

- [tw_dashboard.html](./data/processed/tw_dashboard.html)

The dashboard includes:

- total sample counts
- phishing vs safe split
- source breakdown
- attack-type breakdown
- hot brands
- high-confidence candidate keywords
- latest candidate phrases

### One-Command Pipeline

Run the whole local intelligence workflow:

```bash
node scripts/run_pipeline.mjs
```

Or reuse already downloaded feeds:

```bash
node scripts/run_pipeline.mjs --skip-fetch
```

## Files You’ll Likely Edit Most

- [tw_scam_keywords.json](./data/tw_scam_keywords.json)
- [tw_brand_domains.json](./data/tw_brand_domains.json)
- [content.js](./apps/extension/content.js)
- [rule-engine.ts](./apps/api/src/pipeline/rule-engine.ts)
- [llm-analyzer.ts](./apps/api/src/pipeline/llm-analyzer.ts)

## What Has Been Built So Far

- hybrid phishing detection pipeline
- Chrome MV3 extension UI
- local API service
- OpenAI/Ollama/fallback support
- webmail analysis
- Taiwan-specific brand and scam adaptation
- user feedback learning loop
- phishing feed ingestion
- dataset preparation
- pattern mining
- approval-to-promotion keyword workflow
- local dashboard
- one-command intelligence pipeline

## Current Limitations

- webmail extraction is DOM-based, so selectors may need maintenance
- external threat-intel support is partial and configurable (RDAP / blacklist hooks), not a full sandboxed threat-intel agent
- no production database yet
- no full model fine-tuning workflow yet
- trend mining is candidate generation, not autonomous rule deployment

## Recommended Next Steps

1. Add more Taiwan legitimate-domain negative samples
2. Build a small admin/review UI for keyword approval
3. Add scheduled pipeline execution
4. Add agent tools for WHOIS, blacklist, redirect tracing, and sandbox simulation
5. Use accumulated feedback plus feeds for supervised tuning or policy optimization

For practical installation and daily automation, see:

- [INSTALL.md](./INSTALL.md)
