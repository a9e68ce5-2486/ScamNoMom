# Install and Run

[繁體中文版本](./INSTALL.zh-TW.md)

This guide is for practical day-to-day use of ScamNoMom on:

- macOS
- Linux
- Windows

## Requirements

- Chrome or another Chromium-based browser
- Node.js 20+
- npm
- Optional:
  - Ollama for local LLM inference
  - OpenAI API key for cloud analysis

## 1. Quick Start

Fastest local setup:

```bash
cd /path/to/ScamNoMom
npm run setup:ollama
npm run start
```

Then load the extension from:

- `/path/to/ScamNoMom/apps/extension`

This is the simplest path for a normal local user:

- setup dependencies
- create `apps/api/.env`
- start the local API
- use the extension popup and settings page

## 2. Setup Commands

Choose the provider you want:

```bash
npm run setup:ollama
npm run setup:openai
npm run setup:auto
```

These commands will:

- install API dependencies
- create `apps/api/.env` if missing
- set the LLM provider
- create local data and log directories

If you already installed dependencies and only want to refresh `.env`:

```bash
node scripts/setup.mjs --provider auto --skip-install
```

## 3. Provider Configuration

Environment file:

- [`.env.example`](/Users/shenghung/MyGitHub/ScamNoMom/apps/api/.env.example)
- `apps/api/.env`

### Ollama

Recommended for private local use.

Example:

```bash
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen3:8b
```

Start Ollama and download a model:

```bash
ollama pull qwen3:8b
```

### OpenAI

Example:

```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=your_server_side_key
OPENAI_MODEL=gpt-5.2
```

### Auto fallback

```bash
LLM_PROVIDER=auto
```

This will try:

1. OpenAI
2. Ollama
3. local heuristic fallback

## 4. Start the Local System

Normal startup:

```bash
npm run start
```

Development mode:

```bash
npm run start:dev
```

Direct API-only startup:

```bash
npm run api:start
npm run api:start:dev
```

Check the API:

- `http://localhost:8787/`
- `http://localhost:8787/health`

## 5. Load the Extension

1. Open `chrome://extensions`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select [apps/extension](/Users/shenghung/MyGitHub/ScamNoMom/apps/extension)

## 6. Configure the Extension Without Editing Code

The extension now includes a built-in settings page.

Open it in either way:

1. Click the extension popup and press `Settings`
2. Or open the extension details page in Chrome and choose `Extension options`

Available settings:

- `API Base URL`
- `Show on-page warning overlay`
- `Auto-rescan changing pages`

This means normal users do not need to edit `.js` files or hardcode localhost values in the extension.

## 7. What the Extension Can Check

Current coverage includes:

- phishing websites
- fake login pages
- suspicious payment or logistics pages
- Gmail
- Outlook Web
- Yahoo Mail
- Proton Mail

Current UI features include:

- popup risk dashboard
- on-page warning overlay
- manual rescan
- feedback collection
- Taiwan-focused rule checks

## 8. Daily Intelligence Pipeline

Run the full local intelligence pipeline:

```bash
npm run pipeline
```

Skip remote feed download and reuse local files:

```bash
npm run pipeline:skip-fetch
```

Manual component commands:

```bash
node scripts/fetch_feeds.mjs
node scripts/prepare_dataset.mjs
node scripts/mine_tw_scam_patterns.mjs
node scripts/generate_tw_dashboard.mjs
```

Dashboard output:

- [tw_dashboard.html](/Users/shenghung/MyGitHub/ScamNoMom/data/processed/tw_dashboard.html)

## 9. Install Daily Auto-Update

Install the cross-platform daily pipeline scheduler:

```bash
npm run schedule:install
```

Supported platforms:

- macOS: `launchd`
- Linux: `crontab`
- Windows: `schtasks`

Logs:

- `/path/to/ScamNoMom/logs/pipeline.stdout.log`
- `/path/to/ScamNoMom/logs/pipeline.stderr.log`

Install without re-fetching feeds:

```bash
node scripts/install_daily_pipeline_schedule.mjs --hour 3 --minute 15 --skip-fetch
```

Uninstall:

```bash
npm run schedule:uninstall
```

## 10. Install API Auto-Start

If you do not want to open a terminal and start the API manually every time, install the API auto-start job:

```bash
npm run service:install
```

Development-mode auto-start:

```bash
npm run service:install:dev
```

Uninstall:

```bash
npm run service:uninstall
```

Logs:

- `/path/to/ScamNoMom/logs/api.stdout.log`
- `/path/to/ScamNoMom/logs/api.stderr.log`

Supported platforms:

- macOS: starts at login with `launchd`
- Linux: starts at reboot with `crontab`
- Windows: starts at user logon with `schtasks`

## 11. Practical Recommendation

For actual daily use, the simplest stable setup is:

1. Install Ollama locally and pull `qwen3:8b`
2. Run `npm run setup:ollama`
3. Run `npm run service:install`
4. Load the extension once in Chrome
5. Open the extension `Settings` page and confirm the API URL
6. Install `npm run schedule:install` for daily data refresh

After that, normal usage is just:

- keep the browser extension enabled
- let the local API run in the background
- review warnings, feedback, and dashboard when needed

## 12. Prepare a User Distribution Package

If you want to share this with other users, there are now two packaging commands:

Create an extension release folder:

```bash
npm run release:extension
```

Output:

- `/path/to/ScamNoMom/dist/scamnomom-extension`

Create a portable user bundle:

```bash
npm run release:bundle
```

Output:

- `/path/to/ScamNoMom/dist/scamnomom-portable`

The portable bundle includes:

- the API source and scripts
- the browser extension
- setup and startup launchers
- installation documents

Recommended sharing workflow:

1. Run `npm run release:bundle`
2. Compress `dist/scamnomom-portable`
3. Send that archive to the user
4. Ask them to run `setup-ollama` and then `start-scamnomom`

## Troubleshooting

### The popup says analysis failed

Check:

- API is running on `localhost:8787`
- `.env` is valid
- Ollama or OpenAI is reachable

### Webmail content is not captured correctly

Current mail support is DOM-based. Reload the extension, open a specific message page, and use `Rescan Current Tab`.

### Dashboard is empty

This is normal if you have not yet:

- collected feedback
- fetched phishing feeds
- prepared the dataset

Run:

```bash
node scripts/run_pipeline.mjs
```

### Daily job is not running

Check:

```bash
tail -n 50 /path/to/ScamNoMom/logs/pipeline.stderr.log
```

If you are on:

- macOS: `launchctl list | grep scamnomom`
- Linux: `crontab -l`
- Windows: `schtasks /Query /TN com.scamnomom.pipeline.daily`
