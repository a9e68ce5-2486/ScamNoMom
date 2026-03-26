# 資料流程

[English Version](./README.md)

這個資料夾定義了 ScamNoMom 的訓練資料流程。

## 目錄結構

```text
data/
  raw/
    external/
    feedback/
  processed/
  schemas/
```

## 統一樣本格式

所有訓練樣本都應整理成下列 schema：

- `data/schemas/training-sample.json`

每筆樣本應包含：

- `sourceType`：`web`、`email` 或 `url_feed`
- `label`：`safe` 或 `phishing`
- `content`：標準化文字與中繼資料
- `signals`：結構化特徵
- `provenance`：原始資料來源

## 目前支援的輸入來源

### 自動抓取 phishing feeds

將最新公開 feeds 抓到 `data/raw/external/`：

```bash
node scripts/fetch_feeds.mjs
```

可用環境變數：

```bash
PHISHTANK_APP_KEY=your_app_key
PHISHTANK_USER_AGENT=scamnomom/your-name
OPENPHISH_FEED_URL=https://openphish.com/feed.txt
```

### Extension feedback

來源檔案：

- `apps/api/data/feedback.json`

轉換指令：

```bash
node scripts/prepare_dataset.mjs
```

輸出：

- `data/processed/training-samples.json`

### PhishTank

把下載好的 PhishTank 檔案放到：

- `data/raw/external/phishtank.csv`
- 或 `data/raw/external/phishtank.json`

支援欄位：

- `url`
- `phish_url`
- `phish_id`
- `verification_time`
- `submission_time`

### OpenPhish

把下載好的 OpenPhish 檔案放到：

- `data/raw/external/openphish.txt`
- 或 `data/raw/external/openphish.json`

支援格式：

- 每行一個 URL 的純文字
- 含 `url` 欄位的 JSON array

## 建立整合資料集

```bash
node scripts/fetch_feeds.mjs
node scripts/prepare_dataset.mjs
```

這支腳本會整合：

- extension feedback
- PhishTank URLs
- OpenPhish URLs

輸出到：

- `data/processed/training-samples.json`

## 預計加入的外部資料來源

- Enron
- SpamAssassin

先把資料放到 `data/raw/external/`，再擴充 `scripts/prepare_dataset.mjs`。

## 台灣品牌白名單

針對台灣品牌與官方網域的對照資料放在：

- `data/tw_brand_domains.json`

Backend rule engine 會使用這份資料，檢查常見台灣銀行、電商、支付、物流品牌的品牌網域不一致情況。

## 台灣詐騙關鍵詞

台灣常見詐騙與 phishing 話術存放於：

- `data/tw_scam_keywords.json`

Backend rule engine 與 fallback analyzer 會依照這些分類使用：

- credential prompts
- urgency language
- payment scams
- logistics scams
- prize scams

## 話術挖掘

可從處理後的資料集中挖掘台灣新興詐騙話術：

```bash
node scripts/mine_tw_scam_patterns.mjs
```

輸出：

- `data/processed/tw_scam_pattern_candidates.json`

腳本會產生：

- 候選新關鍵詞
- 候選片語組合
- 熱門品牌提及

這些候選詞應先人工審核，再加入 `data/tw_scam_keywords.json`。

## 提升已核准關鍵詞

1. 先檢查：

- `data/processed/tw_scam_pattern_candidates.json`

2. 將核准項目加到：

- `data/processed/tw_scam_pattern_approvals.json`

3. 將核准項目提升到正式詞庫：

```bash
node scripts/promote_keywords.mjs
```

## Dashboard

產生台灣詐騙趨勢的本地 HTML dashboard：

```bash
node scripts/generate_tw_dashboard.mjs
```

輸出：

- `data/processed/tw_dashboard.html`

Dashboard 包含：

- 樣本數量
- source 與 attack-type 分布
- 熱門品牌提及
- 高信心候選關鍵詞與片語
- 最新候選關鍵詞與片語
- 完整候選表格

## 一鍵跑完整 pipeline

執行完整本地 intelligence pipeline：

```bash
node scripts/run_pipeline.mjs
```

執行順序：

1. `fetch_feeds.mjs`
2. `prepare_dataset.mjs`
3. `mine_tw_scam_patterns.mjs`
4. `generate_tw_dashboard.mjs`

如果你想重用已下載的 feeds：

```bash
node scripts/run_pipeline.mjs --skip-fetch
```

## Evaluation

如果你要評估目前模型與規則在已標註 feedback 上的表現，可以跑：

```bash
npm run evaluate
```

輸出：

- `data/processed/evaluation-report.json`
- `data/processed/evaluation-report.md`

這份評估目前以已標註的 extension feedback 為主，並提供：

- accuracy
- precision
- recall
- f1
- false positive rate
- false negative rate

## Rule Auto-Tuning

如果你要根據已標註 feedback 產生 rule weight 建議，可以跑：

```bash
npm run tune:rules
```

輸出：

- `data/processed/rule-weight-suggestions.json`

目前 backend 會讀取：

- `data/rule_weights.json`

也就是說，你可以先讓腳本產生建議，再人工審核後把新的權重寫回 `data/rule_weights.json`。
