# 安裝與啟動

[English Version](./INSTALL.md)

這份文件是給實際日常使用 ScamNoMom 的人使用，支援：

- macOS
- Linux
- Windows

## 環境需求

- Chrome 或其他 Chromium-based 瀏覽器
- Node.js 20+
- npm
- 選配：
  - Ollama，用於本地 LLM 推理
  - OpenAI API key，用於雲端分析

## 1. 快速開始

最快的本地啟動方式：

```bash
cd /path/to/ScamNoMom
npm run setup:ollama
npm run start
```

接著載入 extension：

- `/path/to/ScamNoMom/apps/extension`

這條路徑最適合一般本地使用者：

- 安裝依賴
- 建立 `apps/api/.env`
- 啟動本地 API
- 用 extension popup 與設定頁操作

## 2. Setup 指令

依照你想用的 provider 選一個：

```bash
npm run setup:ollama
npm run setup:openai
npm run setup:auto
```

這些指令會：

- 安裝 API 依賴
- 如果沒有 `.env` 就建立 `apps/api/.env`
- 設定 LLM provider
- 建立本地資料與 log 資料夾

如果依賴已經安裝好，只想刷新 `.env`：

```bash
node scripts/setup.mjs --provider auto --skip-install
```

## 3. Provider 設定

環境檔案：

- [`.env.example`](/Users/shenghung/MyGitHub/ScamNoMom/apps/api/.env.example)
- `apps/api/.env`

### Ollama

適合本地隱私優先的使用方式。

範例：

```bash
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen3:8b
```

先下載模型：

```bash
ollama pull qwen3:8b
```

### OpenAI

範例：

```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=your_server_side_key
OPENAI_MODEL=gpt-5.2
```

### Auto fallback

```bash
LLM_PROVIDER=auto
```

系統會依序嘗試：

1. OpenAI
2. Ollama
3. local heuristic fallback

## 4. 啟動本地系統

一般啟動：

```bash
npm run start
```

開發模式：

```bash
npm run start:dev
```

只啟動 API：

```bash
npm run api:start
npm run api:start:dev
```

檢查 API：

- `http://localhost:8787/`
- `http://localhost:8787/health`

## 5. 載入 Extension

1. 打開 `chrome://extensions`
2. 開啟 `Developer mode`
3. 點選 `Load unpacked`
4. 選擇 [apps/extension](/Users/shenghung/MyGitHub/ScamNoMom/apps/extension)

## 6. 不改程式碼也能設定 Extension

Extension 現在內建設定頁。

可用兩種方式打開：

1. 打開 popup 後按 `Settings`
2. 或到 Chrome 的 extension 詳細資訊頁，點 `Extension options`

可設定項目：

- `API Base URL`
- `Show on-page warning overlay`
- `Auto-rescan changing pages`

這樣一般使用者不需要改 `.js` 檔，也不必手動硬編 localhost。

## 7. Extension 目前能檢查什麼

目前支援：

- 釣魚網站
- 假登入頁
- 可疑付款或物流頁面
- Gmail
- Outlook Web
- Yahoo Mail
- Proton Mail

目前 UI 功能：

- popup 風險儀表板
- 頁面內 warning overlay
- 手動 rescan
- feedback 收集
- 台灣場景規則偵測

## 8. 每日 intelligence pipeline

執行完整本地資料流程：

```bash
npm run pipeline
```

若不想重新抓遠端 feed：

```bash
npm run pipeline:skip-fetch
```

手動分步執行：

```bash
node scripts/fetch_feeds.mjs
node scripts/prepare_dataset.mjs
node scripts/mine_tw_scam_patterns.mjs
node scripts/generate_tw_dashboard.mjs
```

Dashboard 輸出：

- [tw_dashboard.html](/Users/shenghung/MyGitHub/ScamNoMom/data/processed/tw_dashboard.html)

## 9. 安裝每日自動更新

安裝跨平台每日 pipeline 排程：

```bash
npm run schedule:install
```

支援平台：

- macOS：`launchd`
- Linux：`crontab`
- Windows：`schtasks`

Logs：

- `/path/to/ScamNoMom/logs/pipeline.stdout.log`
- `/path/to/ScamNoMom/logs/pipeline.stderr.log`

若不想每天重新抓 feed：

```bash
node scripts/install_daily_pipeline_schedule.mjs --hour 3 --minute 15 --skip-fetch
```

移除排程：

```bash
npm run schedule:uninstall
```

## 10. 安裝 API 自動啟動

如果你不想每次都手動打開 terminal 啟動 API，可以安裝 API 自動啟動：

```bash
npm run service:install
```

開發模式自動啟動：

```bash
npm run service:install:dev
```

移除：

```bash
npm run service:uninstall
```

Logs：

- `/path/to/ScamNoMom/logs/api.stdout.log`
- `/path/to/ScamNoMom/logs/api.stderr.log`

支援平台：

- macOS：登入後由 `launchd` 啟動
- Linux：開機後由 `crontab` 啟動
- Windows：登入後由 `schtasks` 啟動

## 11. 實際使用建議

如果你要日常實際使用，最穩定的方式是：

1. 本地安裝 Ollama 並下載 `qwen3:8b`
2. 執行 `npm run setup:ollama`
3. 執行 `npm run service:install`
4. 在 Chrome 載入 extension 一次
5. 打開 extension 的 `Settings` 頁，確認 API URL
6. 安裝 `npm run schedule:install` 讓資料每日更新

之後正常使用就是：

- 保持瀏覽器 extension 開啟
- 讓本地 API 在背景執行
- 需要時查看警告、feedback 與 dashboard

## 12. 準備給其他使用者的發佈包

如果你要把這個專案分享給其他人，可以用兩種打包方式：

建立 extension 發佈目錄：

```bash
npm run release:extension
```

輸出：

- `/path/to/ScamNoMom/dist/scamnomom-extension`

建立 portable 使用者 bundle：

```bash
npm run release:bundle
```

輸出：

- `/path/to/ScamNoMom/dist/scamnomom-portable`

portable bundle 內含：

- API source 與 scripts
- browser extension
- setup 與 startup launcher
- 安裝文件

建議分享流程：

1. 執行 `npm run release:bundle`
2. 壓縮 `dist/scamnomom-portable`
3. 把壓縮檔給使用者
4. 請對方先跑 `setup-ollama`，再跑 `start-scamnomom`
