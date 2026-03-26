# ScamNoMom 目前系統架構

這份文件描述的是 `ScamNoMom` 目前在 repo 中已經實作完成、可以實際執行的架構，不是 proposal 願景版。

## 1. 整體架構

目前系統由三個主要部分組成：

1. `Chrome Extension (MV3)`
2. `Local API Backend`
3. `Local Intelligence Pipeline`

資料流如下：

```text
使用者開啟網站 / Webmail
  -> Extension content script 擷取特徵
  -> service worker 呼叫本地 API
  -> API 進行 Rule + LLM + Agent-ready 分析
  -> 回傳風險結果
  -> popup / 頁面 overlay 顯示結果
  -> 使用者可提交 feedback
  -> feedback 進入資料流程與後續評估
```

## 2. Repository 結構

```text
apps/
  api/
    src/
      config/
      pipeline/
      routes/
      types/
  extension/
    manifest.json
    content.js
    popup.html
    popup.css
    popup.js
    options.html
    options.css
    options.js
    service-worker.js
data/
  processed/
  raw/
  schemas/
docs/
scripts/
```

## 3. Extension 架構

### 3.1 content script

檔案：

- [content.js](../apps/extension/content.js)

職責：

- 擷取目前頁面特徵
- 支援一般網站與 webmail 頁面
- 偵測 Gmail / Outlook / Yahoo / Proton Mail 郵件內容
- 擷取：
  - URL
  - hostname
  - visible text
  - 表單資訊
  - 連結資訊
  - DOM 特徵
  - brand signals
  - email subject / sender / body / reply-to
- 將特徵傳給 service worker
- 根據分析結果顯示頁面右上角 warning overlay

### 3.2 service worker

檔案：

- [service-worker.js](../apps/extension/service-worker.js)

職責：

- 作為 extension 與 backend API 的中介
- 從 `chrome.storage.sync` 讀取使用者設定
- 呼叫：
  - `POST /analyze`
  - `POST /feedback`
- 將最新分析結果存到 `chrome.storage.local`
- 支援：
  - 手動 rescan
  - feedback 提交
  - popup 顯示最新分析狀態

### 3.3 popup UI

檔案：

- [popup.html](../apps/extension/popup.html)
- [popup.css](../apps/extension/popup.css)
- [popup.js](../apps/extension/popup.js)

功能：

- 顯示風險分數與風險等級
- 顯示 recommended action
- 顯示 rule score / llm score
- 顯示 source / mail provider / hostname
- 顯示 reasons
- 支援：
  - `Rescan Current Tab`
  - `Mark Safe`
  - `Mark Phishing`
  - 開啟 `Settings`

### 3.4 options page

檔案：

- [options.html](../apps/extension/options.html)
- [options.css](../apps/extension/options.css)
- [options.js](../apps/extension/options.js)

功能：

- 設定 API Base URL
- 開關頁面 warning overlay
- 開關 auto-rescan

## 4. Backend API 架構

### 4.1 API server

檔案：

- [server.ts](../apps/api/src/server.ts)

目前提供：

- `GET /`
- `GET /health`
- `POST /analyze`
- `POST /analyze/text`
- `POST /feedback`
- `GET /feedback/stats`

### 4.2 Analyze route

檔案：

- [analyze.ts](../apps/api/src/routes/analyze.ts)

功能：

- 驗證 extension 傳來的 feature payload
- 目前 schema 支援：
  - web
  - email
- 驗證通過後呼叫主分析流程

另外也支援：

- `POST /analyze/text`

可分析：

- sms
- line
- messenger
- telegram
- phone transcript
- manual report

### 4.3 Feedback route

檔案：

- [feedback.ts](../apps/api/src/routes/feedback.ts)

功能：

- 接收使用者標註
- 儲存：
  - label
  - analysis result
  - current features
- 目前寫入：
  - `apps/api/data/feedback.json`
- 提供簡單統計：
  - `GET /feedback/stats`

## 5. 分析 Pipeline

### 5.1 入口

檔案：

- [analyze.ts](../apps/api/src/pipeline/analyze.ts)

目前主流程：

```text
PageFeatures
  -> Rule Engine
  -> LLM Analyzer
  -> Weighted Score
  -> Router
     -> 若中風險則進 Agent Analyzer
  -> Final Score / Final Decision
```

### 5.2 Rule Engine

檔案：

- [rule-engine.ts](../apps/api/src/pipeline/rule-engine.ts)

負責：

- password field 偵測
- external form submit 偵測
- mismatched link text 偵測
- suspicious TLD 偵測
- hidden elements / iframe 特徵
- 品牌與當前網域不一致
- 品牌與連結網域不一致
- 台灣品牌 / 支付 / 物流場景規則
- 台灣詐騙關鍵詞規則
- email 相關規則

輸出：

- `ruleScore`
- `rule reasons`

### 5.3 LLM Analyzer

檔案：

- [llm-analyzer.ts](../apps/api/src/pipeline/llm-analyzer.ts)

支援 provider：

- `OpenAI`
- `Ollama`
- `fallback heuristic analyzer`

負責：

- 語意理解
- 冒用品牌判斷
- 帳密竊取意圖判斷
- 緊急語氣與詐騙話術判斷
- payment / logistics / prize 類型語意判斷

輸出：

- `riskLevel`
- `score`
- `reasons`
- `attackType`
- `confidence`
- `provider`

### 5.4 Router

檔案：

- [router.ts](../apps/api/src/pipeline/router.ts)

目前規則：

- `score >= 70` -> `block`
- `40 <= score < 70` -> `escalate`
- `score < 40` -> `allow`

### 5.5 Agent Analyzer

檔案：

- [agent-analyzer.ts](../apps/api/src/pipeline/agent-analyzer.ts)

這是目前已落地的第二階段深度分析骨架。  
當初步分數落在中風險區間時，系統會進一步檢查：

- 短網址 / redirect 風格連結
- hostname 結構風險
- 大量 off-domain links
- 品牌與頁面 / 連結雙重不一致
- URL path 是否像 login / verify / payment flow
- payment + urgency / credential 組合訊號
- email sender / reply-to 網域不一致
- email sender domain 與品牌不一致

目前這層已具備本地 second-pass threat-intel 能力，但還不是完整的外部 threat-intel agent。

目前已做：

- redirect / short-link 解析
- local phishing feed 命中比對
- DNS 訊號檢查
- sender domain 的 MX / SPF 基本觀察

## 6. 風險分數與決策

目前加權方式：

```text
Final Score = 0.4 * Rule Score + 0.6 * LLM Score
```

若進入 agent analyzer：

- 會產生新的 `agent score`
- 再重新決定最終 `riskLevel`
- 再產生最終 `recommendedAction`

目前輸出包含：

- `riskLevel`
- `score`
- `reasons`
- `confidence`
- `attackType`
- `recommendedAction`
- `provider`
- `agent`
- `evidence`

## 7. 台灣化架構

### 7.1 品牌官方網域資料

檔案：

- [tw-brand-domains.ts](../apps/api/src/config/tw-brand-domains.ts)
- [tw_brand_domains.json](../data/tw_brand_domains.json)

用途：

- 銀行品牌
- 電商品牌
- 支付品牌
- 物流 / 超商品牌

### 7.2 詐騙話術資料

檔案：

- [tw-scam-keywords.ts](../apps/api/src/config/tw-scam-keywords.ts)
- [tw_scam_keywords.json](../data/tw_scam_keywords.json)

目前分類：

- `credential`
- `urgency`
- `payment`
- `logistics`
- `prize`
- `investment`
- `customerService`
- `government`
- `qr`

## 8. 學習與資料流程

目前學習系統是以資料蒐集與分析為主，尚未進入自動重訓。

### 8.1 feedback 收集

- extension popup 收集標註
- backend 寫入 `feedback.json`

### 8.2 dataset pipeline

主要腳本：

- [fetch_feeds.mjs](../scripts/fetch_feeds.mjs)
- [prepare_dataset.mjs](../scripts/prepare_dataset.mjs)
- [mine_tw_scam_patterns.mjs](../scripts/mine_tw_scam_patterns.mjs)
- [promote_keywords.mjs](../scripts/promote_keywords.mjs)
- [generate_tw_dashboard.mjs](../scripts/generate_tw_dashboard.mjs)
- [evaluate_dataset.mjs](../scripts/evaluate_dataset.mjs)

功能：

- 抓 phishing feeds
- 整理 training samples
- 挖掘台灣新話術
- 人工審核後提升關鍵詞
- 產生 dashboard
- 評估目前模型與規則表現

## 9. 目前未完成但規劃中的部分

目前還沒有真正落地的部分包括：

- 外部 threat-intel agent
- WHOIS / DNS / blacklist 查詢
- redirect chain 展開
- SPF / DKIM / DMARC 檢查
- 自動 rule auto-tuning
- RL policy learning
- 完整單元測試 / e2e 測試

## 10. 總結

目前的 `ScamNoMom` 已經是一個可以運作的 hybrid phishing detection MVP，具備：

- Extension 前端
- 本地 API backend
- Rule + LLM + Agent-ready 分析
- 台灣在地化詐騙偵測
- feedback / dataset / dashboard / evaluation pipeline

如果從架構定位來看，現在它已經不是單純的 blacklist extension，而是一個可持續演進的本地反詐騙系統。
