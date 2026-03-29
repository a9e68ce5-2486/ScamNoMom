function countSuspiciousTlds(links) {
  const suspicious = new Set(["zip", "click", "top", "gq", "work", "country"]);
  let count = 0;

  for (const link of links) {
    try {
      const hostname = new URL(link.href, location.href).hostname;
      const tld = hostname.split(".").pop()?.toLowerCase();
      if (tld && suspicious.has(tld)) {
        count += 1;
      }
    } catch {
      continue;
    }
  }

  return count;
}

const DEFAULT_SETTINGS = {
  apiBaseUrl: "http://localhost:8787",
  overlayEnabled: true,
  autoRescanEnabled: true,
  notificationMode: "standard"
};

function getSettings(callback) {
  chrome.storage.sync.get(["settings"], ({ settings }) => {
    callback({
      ...DEFAULT_SETTINGS,
      ...(settings || {})
    });
  });
}

function countMismatchedLinks(links) {
  let mismatches = 0;

  for (const link of links) {
    const text = (link.textContent || "").trim();
    if (!text) {
      continue;
    }

    try {
      const url = new URL(link.href, location.href);
      if (text.includes(".") && !text.includes(url.hostname)) {
        mismatches += 1;
      }
    } catch {
      continue;
    }
  }

  return mismatches;
}

function collectLinkHostnames(links) {
  const seen = new Set();
  const hostnames = [];

  for (const link of links) {
    try {
      const hostname = new URL(link.href, location.href).hostname.toLowerCase();
      if (!hostname || seen.has(hostname)) {
        continue;
      }

      seen.add(hostname);
      hostnames.push(hostname);

      if (hostnames.length >= 12) {
        break;
      }
    } catch {
      continue;
    }
  }

  return hostnames;
}

function collectLinkUrls(links) {
  const seen = new Set();
  const urls = [];

  for (const link of links) {
    try {
      const href = new URL(link.href, location.href).toString();
      if (!href || seen.has(href)) {
        continue;
      }

      seen.add(href);
      urls.push(href);

      if (urls.length >= 12) {
        break;
      }
    } catch {
      continue;
    }
  }

  return urls;
}

function extractBrandSignals(text) {
  const knownBrands = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "bank",
    "chase",
    "國泰",
    "玉山",
    "台新",
    "中信",
    "中國信託",
    "富邦",
    "永豐",
    "兆豐",
    "郵局",
    "蝦皮",
    "momo",
    "pchome",
    "露天",
    "博客來",
    "line",
    "街口",
    "全支付",
    "全盈+pay",
    "7-11",
    "統一超商",
    "全家",
    "黑貓",
    "新竹物流",
    "宅配通"
  ];
  const lower = text.toLowerCase();
  return knownBrands.filter((brand) => lower.includes(brand));
}

function textFromNode(node) {
  return (node?.textContent || "").replace(/\s+/g, " ").trim();
}

function extractGmailEmailContext() {
  const subject =
    textFromNode(document.querySelector("h2[data-thread-perm-id]")) ||
    textFromNode(document.querySelector("h2.hP")) ||
    textFromNode(document.querySelector("div[role='main'] h2"));

  const sender =
    textFromNode(document.querySelector("span[email]")) ||
    textFromNode(document.querySelector("h3 span[email]")) ||
    textFromNode(document.querySelector("span.gD"));

  const replyTo = document.querySelector("span[email]")?.getAttribute("email") || "";

  const body =
    textFromNode(document.querySelector("div.a3s.aiL")) ||
    textFromNode(document.querySelector("div[role='listitem'] div[dir='ltr']")) ||
    textFromNode(document.querySelector("div[role='main']"));

  return {
    provider: "gmail",
    subject,
    sender,
    replyTo,
    bodyText: body,
    linkCount: document.querySelectorAll("div.a3s.aiL a[href]").length || document.querySelectorAll("a[href]").length
  };
}

function extractOutlookEmailContext() {
  const subject =
    textFromNode(document.querySelector('[role="heading"]')) ||
    textFromNode(document.querySelector('[data-app-section="ReadingPane"] h1')) ||
    textFromNode(document.querySelector("h1"));

  const sender =
    textFromNode(document.querySelector('[aria-label*="From"]')) ||
    textFromNode(document.querySelector('[title*="@"]')) ||
    textFromNode(document.querySelector('[data-testid="message-header-sender"]'));

  const replyTo = document.querySelector('a[href^="mailto:"]')?.getAttribute("href")?.replace(/^mailto:/, "") || "";

  const body =
    textFromNode(document.querySelector('[aria-label="Message body"]')) ||
    textFromNode(document.querySelector('[data-app-section="MailReadCompose"]')) ||
    textFromNode(document.querySelector('[role="document"]'));

  return {
    provider: "outlook",
    subject,
    sender,
    replyTo,
    bodyText: body,
    linkCount:
      document.querySelectorAll('[aria-label="Message body"] a[href]').length ||
      document.querySelectorAll('[role="document"] a[href]').length ||
      document.querySelectorAll("a[href]").length
  };
}

function extractYahooEmailContext() {
  const subject =
    textFromNode(document.querySelector('[data-test-id="message-subject"]')) ||
    textFromNode(document.querySelector("h1")) ||
    textFromNode(document.querySelector('[role="main"] h2'));

  const sender =
    textFromNode(document.querySelector('[data-test-id="message-from"]')) ||
    textFromNode(document.querySelector('[data-test-id="from-field"]')) ||
    textFromNode(document.querySelector('[title*="@"]'));

  const replyTo = document.querySelector('a[href^="mailto:"]')?.getAttribute("href")?.replace(/^mailto:/, "") || "";

  const body =
    textFromNode(document.querySelector('[data-test-id="message-view-body"]')) ||
    textFromNode(document.querySelector('[data-test-id="message-content"]')) ||
    textFromNode(document.querySelector('[role="main"]'));

  return {
    provider: "yahoo",
    subject,
    sender,
    replyTo,
    bodyText: body,
    linkCount:
      document.querySelectorAll('[data-test-id="message-view-body"] a[href]').length ||
      document.querySelectorAll('[data-test-id="message-content"] a[href]').length ||
      document.querySelectorAll("a[href]").length
  };
}

function extractProtonEmailContext() {
  const subject =
    textFromNode(document.querySelector('[data-testid="message-header:subject"]')) ||
    textFromNode(document.querySelector("h1")) ||
    textFromNode(document.querySelector('[role="main"] h2'));

  const sender =
    textFromNode(document.querySelector('[data-testid="message-header:from"]')) ||
    textFromNode(document.querySelector('[data-testid="message-conversation:sendee-address"]')) ||
    textFromNode(document.querySelector('[title*="@"]'));

  const replyTo = document.querySelector('a[href^="mailto:"]')?.getAttribute("href")?.replace(/^mailto:/, "") || "";

  const body =
    textFromNode(document.querySelector('[data-testid="message-body"]')) ||
    textFromNode(document.querySelector('[data-testid="message-view-body"]')) ||
    textFromNode(document.querySelector('[role="document"]'));

  return {
    provider: "proton",
    subject,
    sender,
    replyTo,
    bodyText: body,
    linkCount:
      document.querySelectorAll('[data-testid="message-body"] a[href]').length ||
      document.querySelectorAll('[data-testid="message-view-body"] a[href]').length ||
      document.querySelectorAll("a[href]").length
  };
}

function detectEmailContext() {
  const host = location.hostname.toLowerCase();

  if (host.includes("mail.google.com")) {
    return extractGmailEmailContext();
  }

  if (host.includes("outlook.live.com") || host.includes("outlook.office.com") || host.includes("outlook.office365.com")) {
    return extractOutlookEmailContext();
  }

  if (host.includes("mail.yahoo.com")) {
    return extractYahooEmailContext();
  }

  if (host.includes("mail.proton.me") || host.includes("mail.protonmail.com")) {
    return extractProtonEmailContext();
  }

  return null;
}

function injectOverlayStyles() {
  if (document.getElementById("phishguard-overlay-style")) {
    return;
  }

  const style = document.createElement("style");
  style.id = "phishguard-overlay-style";
  style.textContent = `
    #phishguard-overlay {
      position: fixed;
      top: 16px;
      right: 16px;
      z-index: 2147483647;
      width: 360px;
      border-radius: 18px;
      color: #1d140d;
      background: rgba(255, 250, 242, 0.98);
      border: 1px solid rgba(86, 59, 30, 0.18);
      box-shadow: 0 18px 42px rgba(48, 30, 13, 0.24);
      backdrop-filter: blur(10px);
      overflow: hidden;
      font-family: Georgia, "Times New Roman", serif;
      transform: translateY(-10px);
      opacity: 0;
      animation: phishguard-slide-in 180ms ease forwards;
    }

    #phishguard-overlay[data-risk="low"] {
      background: linear-gradient(180deg, rgba(233, 247, 237, 0.98), rgba(249, 252, 248, 0.98));
    }

    #phishguard-overlay[data-risk="medium"] {
      background: linear-gradient(180deg, rgba(255, 239, 198, 0.98), rgba(255, 249, 236, 0.98));
    }

    #phishguard-overlay[data-risk="high"] {
      background: linear-gradient(180deg, rgba(255, 215, 205, 0.98), rgba(255, 246, 242, 0.98));
    }

    @keyframes phishguard-slide-in {
      to {
        transform: translateY(0);
        opacity: 1;
      }
    }

    #phishguard-overlay * {
      box-sizing: border-box;
    }

    .phishguard-header {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 14px 16px 10px;
    }

    .phishguard-title {
      font-size: 18px;
      font-weight: 700;
      margin: 4px 0 0;
    }

    .phishguard-kicker {
      font-size: 11px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #6e5b48;
    }

    .phishguard-close {
      border: 0;
      border-radius: 999px;
      width: 30px;
      height: 30px;
      cursor: pointer;
      background: rgba(255, 255, 255, 0.7);
      font-size: 18px;
      line-height: 1;
      color: #614c39;
    }

    .phishguard-body {
      padding: 0 16px 16px;
    }

    .phishguard-score-row {
      display: flex;
      justify-content: space-between;
      align-items: end;
      gap: 12px;
    }

    .phishguard-score-label,
    .phishguard-mini-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #6e5b48;
    }

    .phishguard-score {
      margin-top: 4px;
      font-size: 40px;
      font-weight: 700;
      line-height: 1;
    }

    .phishguard-action {
      padding: 10px 12px;
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.6);
      border: 1px solid rgba(68, 46, 22, 0.1);
      min-width: 108px;
    }

    .phishguard-meter {
      margin-top: 12px;
      height: 10px;
      border-radius: 999px;
      background: rgba(53, 34, 14, 0.1);
      overflow: hidden;
    }

    .phishguard-meter-fill {
      height: 100%;
      border-radius: 999px;
      background: linear-gradient(90deg, #698d69 0%, #d69730 55%, #cc5a43 100%);
    }

    .phishguard-facts {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-top: 12px;
    }

    .phishguard-fact {
      padding: 10px;
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.56);
    }

    .phishguard-fact-value {
      display: block;
      margin-top: 4px;
      font-size: 13px;
      font-weight: 700;
    }

    .phishguard-reasons {
      margin: 14px 0 0;
      padding-left: 18px;
    }

    .phishguard-reasons li {
      margin-bottom: 6px;
      font-size: 13px;
      line-height: 1.35;
    }

    .phishguard-footer {
      margin-top: 12px;
      font-size: 12px;
      color: #6e5b48;
    }
  `;

  document.documentElement.appendChild(style);
}

function formatTitleCase(text) {
  return String(text || "")
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function appendReasonList(container, reasons) {
  container.innerHTML = "";
  for (const reason of reasons) {
    const item = document.createElement("li");
    item.textContent = String(reason || "");
    container.appendChild(item);
  }
}

function normalizeNotificationMode(value) {
  const mode = String(value || "").toLowerCase();
  if (mode === "quiet" || mode === "standard" || mode === "sensitive") {
    return mode;
  }
  return "standard";
}

function shouldShowOverlay(result, settings) {
  if (!result || result?.suppression?.active) {
    return false;
  }

  const notificationMode = normalizeNotificationMode(settings?.notificationMode);
  if (result.analysisUnavailable) {
    return true;
  }

  const action = String(result.recommendedAction || "allow");
  const riskLevel = String(result.riskLevel || "low");
  const score = Number(result.score || 0);

  if (notificationMode === "quiet") {
    return action === "block" || riskLevel === "high" || score >= 80;
  }

  if (notificationMode === "sensitive") {
    return action !== "allow" || riskLevel !== "low" || score >= 28;
  }

  return Boolean(
    (action === "warn" || action === "block" || action === "escalate") &&
    (riskLevel === "medium" || riskLevel === "high")
  );
}

function buildOverlayActionHint(result) {
  const type = String(result?.attackType || "");
  if (type === "customer_service_scam" || type === "phone_scam") {
    return "不要操作 ATM 或提供驗證碼；先撥 165 反詐騙專線確認。";
  }
  if (type === "investment_scam") {
    return "不要加入投資群或匯款入金；先用官方管道核實。";
  }
  if (type === "government_impersonation") {
    return "政府通知請改用官方網站/App 查詢，不要直接點訊息連結。";
  }
  if (type === "payment_fraud") {
    return "暫停付款，改從官方 App 或客服電話自行查證。";
  }
  if (type === "credential_harvest" || type === "brand_impersonation") {
    return "不要輸入帳密；改手動輸入官方網址登入確認。";
  }
  return "若有疑慮請先停止操作，改走官方管道查證。";
}

function renderOverlay(result, settings) {
  const existing = document.getElementById("phishguard-overlay");
  if (existing) {
    existing.remove();
  }

  if (!shouldShowOverlay(result, settings)) {
    return;
  }

  injectOverlayStyles();

  const overlay = document.createElement("aside");
  overlay.id = "phishguard-overlay";
  overlay.setAttribute("data-risk", result.analysisUnavailable ? "medium" : result.riskLevel);

  const topReasons = (result.reasons || []).slice(0, 3);
  const confidence = Math.round((result.confidence || 0) * 100);
  const isEmail = result?.source === "email";
  const title = result.analysisUnavailable
    ? isEmail
      ? "Email analysis unavailable"
      : "Page analysis unavailable"
    : isEmail
      ? result.riskLevel === "high"
        ? "Potential phishing email"
        : "Suspicious email detected"
      : result.riskLevel === "high"
        ? "Potential phishing page"
        : "Proceed carefully";
  const kicker = result.analysisUnavailable
    ? "ScamNoMom needs review"
    : isEmail
      ? "ScamNoMom email warning"
      : "ScamNoMom live warning";
  const footer = result.analysisUnavailable
    ? "ScamNoMom could not reach the local analysis service. Open the extension popup before clicking links or submitting information."
    : isEmail
      ? "Review the sender, links, and request before replying or clicking."
      : "Open the extension popup for the full breakdown.";
  const hint = buildOverlayActionHint(result);

  overlay.innerHTML = `
    <div class="phishguard-header">
      <div>
        <div class="phishguard-kicker"></div>
        <div class="phishguard-title"></div>
      </div>
      <button class="phishguard-close" type="button" aria-label="Dismiss warning">×</button>
    </div>
    <div class="phishguard-body">
      <div class="phishguard-score-row">
        <div>
          <div class="phishguard-score-label">Risk score</div>
          <div class="phishguard-score"></div>
        </div>
        <div class="phishguard-action">
          <div class="phishguard-mini-label">Recommended</div>
          <div class="phishguard-fact-value phishguard-action-value"></div>
        </div>
      </div>
      <div class="phishguard-meter">
        <div class="phishguard-meter-fill"></div>
      </div>
      <div class="phishguard-facts">
        <div class="phishguard-fact">
          <div class="phishguard-mini-label">Attack Type</div>
          <span class="phishguard-fact-value phishguard-attack-type"></span>
        </div>
        <div class="phishguard-fact">
          <div class="phishguard-mini-label">Confidence</div>
          <span class="phishguard-fact-value phishguard-confidence"></span>
        </div>
        <div class="phishguard-fact">
          <div class="phishguard-mini-label">Engine</div>
          <span class="phishguard-fact-value phishguard-provider"></span>
        </div>
      </div>
      <ul class="phishguard-reasons"></ul>
      <div class="phishguard-footer"></div>
      <div class="phishguard-footer phishguard-hint"></div>
    </div>
  `;

  const kickerEl = overlay.querySelector(".phishguard-kicker");
  const titleEl = overlay.querySelector(".phishguard-title");
  const scoreEl = overlay.querySelector(".phishguard-score");
  const actionEl = overlay.querySelector(".phishguard-action-value");
  const meterFillEl = overlay.querySelector(".phishguard-meter-fill");
  const attackTypeEl = overlay.querySelector(".phishguard-attack-type");
  const confidenceEl = overlay.querySelector(".phishguard-confidence");
  const providerEl = overlay.querySelector(".phishguard-provider");
  const reasonsEl = overlay.querySelector(".phishguard-reasons");
  const footerEls = overlay.querySelectorAll(".phishguard-footer");

  if (kickerEl) {
    kickerEl.textContent = kicker;
  }
  if (titleEl) {
    titleEl.textContent = title;
  }
  if (scoreEl) {
    scoreEl.textContent = result.analysisUnavailable ? "--" : String(result.score ?? "--");
  }
  if (actionEl) {
    actionEl.textContent = result.analysisUnavailable ? "Review Manually" : formatTitleCase(result.recommendedAction);
  }
  if (meterFillEl) {
    meterFillEl.style.width = `${result.analysisUnavailable ? 45 : Math.max(0, Math.min(100, result.score || 0))}%`;
  }
  if (attackTypeEl) {
    attackTypeEl.textContent = result.analysisUnavailable ? "Unknown" : formatTitleCase(result.attackType);
  }
  if (confidenceEl) {
    confidenceEl.textContent = result.analysisUnavailable ? "--" : `${confidence}%`;
  }
  if (providerEl) {
    providerEl.textContent = formatTitleCase(result.provider);
  }
  if (reasonsEl) {
    appendReasonList(reasonsEl, topReasons);
  }
  if (footerEls[0]) {
    footerEls[0].textContent = footer;
  }
  if (footerEls[1]) {
    footerEls[1].textContent = hint;
  }

  overlay.querySelector(".phishguard-close")?.addEventListener("click", () => {
    overlay.remove();
  });

  document.documentElement.appendChild(overlay);
}

function collectFeatures() {
  const forms = Array.from(document.forms);
  const links = Array.from(document.querySelectorAll("a[href]"));
  const hiddenElements = document.querySelectorAll("[hidden], [style*='display:none'], [style*='visibility:hidden']");
  const pageText = (document.body?.innerText || "").slice(0, 5000);
  const emailContext = detectEmailContext();
  const combinedText = emailContext
    ? `${emailContext.subject || ""} ${emailContext.sender || ""} ${emailContext.bodyText || ""}`.slice(0, 5000)
    : pageText;

  const externalSubmitCount = forms.filter((form) => {
    const action = form.getAttribute("action");
    if (!action) {
      return false;
    }

    try {
      const actionUrl = new URL(action, location.href);
      return actionUrl.hostname !== location.hostname;
    } catch {
      return false;
    }
  }).length;

  return {
    url: location.href,
    hostname: location.hostname,
    source: emailContext ? "email" : "web",
    title: document.title,
    visibleText: combinedText,
    forms: {
      total: forms.length,
      passwordFields: document.querySelectorAll("input[type='password']").length,
      externalSubmitCount
    },
    links: {
      total: links.length,
      mismatchedTextCount: countMismatchedLinks(links),
      suspiciousTldCount: countSuspiciousTlds(links),
      hostnames: collectLinkHostnames(links),
      urls: collectLinkUrls(links)
    },
    dom: {
      hiddenElementCount: hiddenElements.length,
      iframeCount: document.querySelectorAll("iframe").length
    },
    brandSignals: extractBrandSignals(combinedText),
    email: emailContext
  };
}

function fingerprintFeatures(features) {
  const parts = [
    features.hostname || "",
    features.source || "",
    features.title || "",
    features.visibleText || "",
    String(features.forms?.total ?? 0),
    String(features.forms?.passwordFields ?? 0),
    String(features.forms?.externalSubmitCount ?? 0),
    String(features.links?.total ?? 0),
    String(features.links?.mismatchedTextCount ?? 0),
    String(features.links?.suspiciousTldCount ?? 0),
    (features.links?.hostnames || []).slice(0, 8).join("|"),
    (features.links?.urls || []).slice(0, 8).join("|"),
    (features.brandSignals || []).slice(0, 8).join("|"),
    features.email?.provider || "",
    features.email?.subject || "",
    features.email?.sender || "",
    features.email?.replyTo || "",
    features.email?.bodyText || "",
    String(features.email?.linkCount ?? 0)
  ];
  return parts.join("::");
}

let lastFeatureFingerprint = "";
let lastAnalyzeTs = 0;
const MIN_ANALYZE_INTERVAL_MS = 5000;

function analyzeCurrentPage(sendResponse) {
  const features = collectFeatures();
  const nextFingerprint = fingerprintFeatures(features);
  const now = Date.now();
  const withinCooldown = now - lastAnalyzeTs < MIN_ANALYZE_INTERVAL_MS;
  const samePayload = nextFingerprint === lastFeatureFingerprint;

  if (!sendResponse && samePayload) {
    return;
  }

  if (!sendResponse && withinCooldown) {
    return;
  }

  lastFeatureFingerprint = nextFingerprint;
  lastAnalyzeTs = now;

  getSettings((settings) => {
    chrome.runtime.sendMessage(
      {
        type: "PHISHGUARD_ANALYZE_PAGE",
        payload: features
      },
      (response) => {
        if (chrome.runtime.lastError) {
          sendResponse?.({ ok: false, error: chrome.runtime.lastError.message });
          return;
        }

        if (settings.overlayEnabled) {
          renderOverlay(response?.result, settings);
        } else {
          renderOverlay(null, settings);
        }

        sendResponse?.(response ?? { ok: false, error: "No analysis response." });
      }
    );
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "PHISHGUARD_RESCAN") {
    return false;
  }

  analyzeCurrentPage(sendResponse);
  return true;
});

analyzeCurrentPage();

let rescanDebounce;
let mutationCountSinceLastScan = 0;
const MIN_MUTATIONS_FOR_RESCAN = 3;
const observer = new MutationObserver(() => {
  mutationCountSinceLastScan += 1;
  clearTimeout(rescanDebounce);
  rescanDebounce = setTimeout(() => {
    getSettings((settings) => {
      if (!settings.autoRescanEnabled) {
        return;
      }

      if (mutationCountSinceLastScan < MIN_MUTATIONS_FOR_RESCAN) {
        return;
      }

      mutationCountSinceLastScan = 0;
      analyzeCurrentPage();
    });
  }, 1200);
});

if (document.body) {
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
} else {
  window.addEventListener("load", () => {
    if (!document.body) {
      return;
    }

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  });
}
