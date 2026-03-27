# ScamNoMom

[English Version](./README.md)

ScamNoMom 是一個混合式的釣魚與詐騙偵測專案，重點支援：

- 釣魚網站
- Webmail 釣魚郵件
- 台灣常見詐騙話術與品牌冒用

目前實作是一個以本地執行為主的 MVP，主要由以下幾部分組成：

- `Chrome Extension (MV3)`：負責特徵擷取、popup UI、頁面內警告
- `Node.js + TypeScript` backend：負責風險評分與分析流程
- `OpenAI` 或 `Ollama/Qwen`：負責語意分析
- `Rule engine + feedback loop + dataset pipeline`：負責持續優化
- `Local + optional external threat intel`：負責 DNS、feed、RDAP、blacklist second pass

## 專案目前能做什麼

目前系統可以分析：

- 一般釣魚網站
- Gmail
- Outlook Web
- Yahoo Mail
- Proton Mail

整體偵測流程如下：

1. 在瀏覽器端擷取頁面或郵件特徵
2. 將標準化特徵送到本地 API
3. 先用規則引擎評分
4. 再用 LLM 或 fallback heuristic analyzer 評分
5. 合併分數並做最終決策
6. 在 popup 與頁面上顯示警告
7. 收集使用者回饋作為後續學習資料

## 使用的方法

### 1. 規則式偵測

Backend rule engine 會檢查高訊號風險特徵，例如：

- 密碼欄位
- 表單是否送往外部網域
- 連結文字與目的地是否不一致
- 可疑頂級網域
- 隱藏元素與大量 iframe
- 品牌與網域不一致
- 台灣常見詐騙話術

規則邏輯在：

- [rule-engine.ts](./apps/api/src/pipeline/rule-engine.ts)

### 2. LLM 語意分析

Backend 支援：

- `OpenAI Responses API`
- `Ollama` 本地模型，例如 `qwen3:8b`
- 若模型不可用則退回內建 heuristic analyzer

LLM 主要分析：

- 是否有冒用品牌
- 是否有竊取帳密意圖
- 是否使用緊急催促語氣
- 是否涉及付款詐騙
- 是否具備郵件場景特徵

邏輯在：

- [llm-analyzer.ts](./apps/api/src/pipeline/llm-analyzer.ts)

### 3. 台灣詐騙場景調整

專案已針對台灣常見詐騙型態做調整，包含：

- 台灣品牌官方網域白名單：[tw_brand_domains.json](./data/tw_brand_domains.json)
- 台灣詐騙關鍵詞詞庫：[tw_scam_keywords.json](./data/tw_scam_keywords.json)

因此能更好辨識：

- 假銀行頁面
- 假電商通知
- 假物流訊息
- 解除分期詐騙
- 假付款連結
- 繁中帳號驗證誘導

### 4. 瀏覽器端特徵擷取

Extension 會擷取：

- 頁面文字
- 表單
- 連結
- 可疑網域
- 品牌詞
- Webmail 的主旨、寄件者、本文

特徵擷取在：

- [content.js](./apps/extension/content.js)

### 5. Human-in-the-Loop Learning

Extension popup 支援：

- `Mark Safe`
- `Mark Phishing`

這些標註會存到：

- `apps/api/data/feedback.json`

之後可再轉成訓練資料，並拿來挖掘新型詐騙話術。

## 專案結構

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
│       ├── options.html
│       ├── options.css
│       ├── options.js
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

目前實作中的架構說明可參考：

- [docs/current-architecture.zh-TW.md](./docs/current-architecture.zh-TW.md)

## 目前功能

### Extension

- popup 風險儀表板
- 頁面內警告 overlay
- 手動重掃描
- 僅開發模式顯示的 debug capture
- 使用者回饋按鈕
- 內建設定頁

### Backend

- `/` 服務摘要
- `/health`
- `POST /analyze`
- `POST /feedback`
- `GET /feedback/stats`

### Webmail 支援

- Gmail
- Outlook Web
- Yahoo Mail
- Proton Mail

### 台灣化能力

- 品牌官方網域比對
- 頁面連結層級的品牌網域比對
- 繁體中文詐騙關鍵詞分類
- 新興詐騙話術候選挖掘

## 與目前市面同類工具的差異

目前市面上與本專案方向接近的產品，通常可分成幾類：

- 瀏覽器安全擴充套件：例如偏向惡意網站封鎖、黑名單、reputation 的產品
- 防毒或安全廠商的 browser protection：例如偏向已知惡意網址攔截
- 郵件安全服務：例如偏向企業郵件閘道、雲端郵件掃描

這類工具通常很強的地方是：

- 已知惡意網址資料庫
- 大型 threat intelligence feed
- 企業級封鎖與管理能力

但 `ScamNoMom` 的定位不完全一樣。它的差異在於：

- 採用 `Rule + LLM + Agent-ready` 的混合架構，不只靠黑名單
- 支援 `web + webmail`，不是只看一般網站
- 針對台灣常見詐騙情境做在地化調整
- 支援本地 `Ollama/Qwen`，可走 local-first 隱私路線
- 內建 feedback、dataset、pattern mining、dashboard，方便持續學習

## ScamNoMom 的優勢

### 1. 不只攔已知惡意網址

很多市面工具偏重：

- 已知黑名單
- reputation
- 固定規則

`ScamNoMom` 則會同時看：

- 規則特徵
- 語意內容
- 品牌冒用
- 台灣詐騙話術
- Webmail 郵件上下文

所以即使是新的釣魚頁、還沒進黑名單的變體，也有機會被抓到。

### 2. 對台灣場景更友善

這是 `ScamNoMom` 最大的差異之一。  
目前已內建：

- 台灣品牌官方網域白名單
- 台灣詐騙關鍵詞分類
- 常見銀行、電商、支付、物流品牌冒用偵測
- 繁體中文付款、補件、驗證、解除分期等詐騙語境

這比多數以英文或全球通用風險資料為主的工具，更適合台灣使用者。

### 3. 支援 webmail 內容分析

許多瀏覽器安全工具主要看的是：

- 網址
- 網域 reputation
- 網頁是否惡意

但 `ScamNoMom` 也支援：

- Gmail
- Outlook Web
- Yahoo Mail
- Proton Mail

可以直接針對郵件主旨、寄件者、本文、連結做綜合判斷。

### 4. 可在本地運行

如果你用 `Ollama`，整體分析可以走本地推理。這代表：

- 更好的隱私控制
- 更低的長期 API 成本
- 比較適合研究、客製化與地端部署

### 5. 可持續進化

這個專案不是單次判斷工具而已，還有完整的學習管線：

- feedback 收集
- dataset 整理
- 新興詐騙話術挖掘
- dashboard
- 後續可接 rule auto-tuning 與 RL policy

也就是說，`ScamNoMom` 更像一個可持續成長的反詐騙系統，而不是只有固定功能的 extension。

## 適合的使用者

`ScamNoMom` 特別適合以下幾類人：

- 想保護自己或家人避免遇到釣魚網站與詐騙訊息的一般使用者
- 經常使用 Gmail、Outlook、Yahoo Mail、Proton Mail 的使用者
- 常面對台灣銀行、物流、電商、支付詐騙訊息的台灣使用者
- 想做在地化 anti-scam 研究的開發者或研究者
- 想用本地 LLM 建立隱私優先防護工具的人

## 典型使用情境

`ScamNoMom` 目前最適合這些場景：

- 打開可疑網站時，直接在頁面上收到高風險警告
- 打開 Gmail / Outlook 郵件時，判斷是否是假驗證、假物流、假付款通知
- 收到繁體中文的「解除分期」、「補件」、「帳戶異常」、「中獎」等詐騙文案時，提供風險判斷
- 用 feedback 收集誤報與漏報，再持續優化規則與資料集
- 用本地 dashboard 觀察最近熱門詐騙話術與品牌冒用趨勢

## 為什麼不只是黑名單 Extension

如果只是黑名單型 extension，通常只能處理：

- 已知惡意網址
- 已經被舉報的網域
- 已進 threat feed 的樣本

但真實世界很多詐騙頁與釣魚訊息會：

- 很快換網域
- 用新短網址
- 改文案但保留相同詐騙意圖
- 專門針對台灣在地品牌與繁體中文使用者

`ScamNoMom` 想解的就是這個 gap。  
它不是要取代 reputation 或 blacklist，而是補足：

- 新變體偵測
- 語意理解
- 郵件內容上下文
- 台灣在地化詐騙模式
- 可持續學習與優化

## 如何執行

### 1. 啟動 API

```bash
cd apps/api
npm install
npm run dev
```

可用端點：

- `GET http://localhost:8787/`
- `GET http://localhost:8787/health`
- `POST http://localhost:8787/analyze`
- `POST http://localhost:8787/feedback`
- `GET http://localhost:8787/feedback/stats`

### 2. 設定 LLM Provider

從下列檔案建立 `apps/api/.env`：

- [`.env.example`](./apps/api/.env.example)

OpenAI 模式：

```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=your_server_side_key
OPENAI_MODEL=gpt-5.2
```

Ollama 模式：

```bash
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen3:8b
```

自動 fallback：

```bash
LLM_PROVIDER=auto
```

如果沒有可用模型，backend 會退回本地 heuristic analyzer。

### 3. 載入 Chrome Extension

1. 打開 `chrome://extensions`
2. 啟用 `Developer Mode`
3. 點選 `Load unpacked`
4. 選擇：
   - `./apps/extension`

### 4. 測試

可以測試：

- 一般網站
- 登入頁或疑似釣魚頁
- Gmail / Outlook / Yahoo / Proton 郵件頁面

打開 popup 可以看到：

- risk score
- recommended action
- 使用的 provider
- attack type
- source type
- mail provider

## 學習與資料流程

### Feedback 收集

使用者可以在 popup 內標記分析結果。這些標註會先存在本地，再轉成可用的訓練格式。

### Dataset 整理

資料整理與腳本說明請看：

- [data/README.zh-TW.md](./data/README.zh-TW.md)

### Evaluation

目前也可以直接對已標註的 feedback 做正式評估：

```bash
npm run evaluate
```

輸出：

- [evaluation-report.json](./data/processed/evaluation-report.json)
- [evaluation-report.md](./data/processed/evaluation-report.md)

### Rule Auto-Tuning

目前也支援根據已標註 feedback 產生規則權重調整建議：

```bash
npm run tune:rules
```

輸出：

- [rule-weight-suggestions.json](./data/processed/rule-weight-suggestions.json)
- [rule_weights.json](./data/rule_weights.json)

### 一鍵啟動與安裝

如果你要的是實際安裝與使用方式，請看：

- [INSTALL.zh-TW.md](./INSTALL.zh-TW.md)
