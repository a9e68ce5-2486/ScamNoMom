function formatTitleCase(text) {
  return String(text || "")
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function currentFeedbackContext() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["latestAnalysis", "latestFeatures"], ({ latestAnalysis, latestFeatures }) => {
      resolve({
        analysis: latestAnalysis || null,
        features: latestFeatures || null
      });
    });
  });
}

function sendLearningEvent(type, payload) {
  chrome.runtime.sendMessage(
    {
      type: "PHISHGUARD_RECORD_LEARNING_EVENT",
      payload: {
        type,
        ...payload
      }
    },
    () => {
      // Fire-and-forget: learning signal should not block UX actions.
    }
  );
}

function renderInterventionPanel(result) {
  const panel = document.getElementById("intervention-panel");
  const summary = document.getElementById("intervention-summary");
  const actions = document.getElementById("intervention-actions");

  if (!panel || !summary || !actions) {
    return;
  }

  const intervention = result?.intervention;
  if (!intervention || intervention.severity === "none") {
    panel.hidden = true;
    summary.textContent = "Potential OTP / transfer scam behavior detected.";
    actions.innerHTML = "";
    return;
  }

  panel.hidden = false;
  summary.textContent =
    intervention.severity === "high"
      ? "High-risk transaction flow: OTP/transfer coercion cues detected."
      : "Caution: suspicious transfer or verification cues detected.";

  actions.innerHTML = "";
  const mergedActions = [...(intervention.reasons || []), ...(intervention.suggestedActions || [])].slice(0, 5);
  for (const action of mergedActions) {
    const li = document.createElement("li");
    li.textContent = action;
    actions.appendChild(li);
  }
  if (mergedActions.length === 0) {
    const li = document.createElement("li");
    li.textContent = "Do not provide OTP or transfer funds before official verification.";
    actions.appendChild(li);
  }
}

function renderCalibrationHint(result) {
  const hint = document.getElementById("calibration-hint");
  if (!hint) {
    return;
  }
  const calibration = result?.calibration;
  if (!calibration?.applied) {
    hint.textContent = "User calibration: default";
    return;
  }
  const delta = Number(calibration.scoreDelta || 0);
  const deltaText = delta > 0 ? `+${delta.toFixed(1)}` : delta.toFixed(1);
  hint.textContent = `User calibration applied (${deltaText})`;
}

function resetInterventionPanel() {
  const panel = document.getElementById("intervention-panel");
  const summary = document.getElementById("intervention-summary");
  const actions = document.getElementById("intervention-actions");
  if (!panel || !summary || !actions) {
    return;
  }
  panel.hidden = true;
  summary.textContent = "Potential OTP / transfer scam behavior detected.";
  actions.innerHTML = "";
}

function renderConversationPanel(result) {
  const panel = document.getElementById("conversation-panel");
  const summary = document.getElementById("conversation-summary");
  if (!panel || !summary) {
    return;
  }
  if (result?.source !== "conversation") {
    panel.hidden = true;
    summary.textContent = "";
    return;
  }
  panel.hidden = false;
  const reason = Array.isArray(result.reasons) && result.reasons.length > 0 ? result.reasons[0] : "Conversation analysis completed.";
  summary.textContent = reason;
}

function analyzeConversationFromPrompt() {
  const raw = window.prompt("Paste conversation lines. Prefix each line with 'counterparty:' or 'user:'.");
  if (!raw) {
    return;
  }
  const turns = String(raw)
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const lower = line.toLowerCase();
      if (lower.startsWith("counterparty:")) {
        return { role: "counterparty", text: line.slice("counterparty:".length).trim() };
      }
      if (lower.startsWith("system:")) {
        return { role: "system", text: line.slice("system:".length).trim() };
      }
      return { role: "user", text: line.startsWith("user:") ? line.slice("user:".length).trim() : line };
    })
    .filter((turn) => turn.text.length > 0)
    .slice(0, 40);

  if (turns.length === 0) {
    updateRescanUi("idle", "No conversation content");
    return;
  }

  updateRescanUi("loading", "Analyzing conversation...");
  chrome.storage.sync.get(["settings"], ({ settings }) => {
    const apiBaseUrl = String(settings?.apiBaseUrl || "http://localhost:8787").replace(/\/+$/, "");
    const calibration = settings?.calibrationProfile || null;
    fetch(`${apiBaseUrl}/analyze/conversation`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        source: "conversation",
        channel: "manual_report",
        turns,
        calibration
      })
    })
      .then((res) => {
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        return res.json();
      })
      .then((result) => {
        chrome.storage.local.set({
          latestAnalysis: result,
          latestFeatures: {
            url: "about:conversation",
            hostname: "conversation",
            source: "web",
            title: "Conversation analysis",
            visibleText: turns.map((t) => `[${t.role}] ${t.text}`).join(" "),
            forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
            links: { total: 0, mismatchedTextCount: 0, suspiciousTldCount: 0, hostnames: [], urls: [] },
            dom: { hiddenElementCount: 0, iframeCount: 0 },
            brandSignals: []
          }
        });
        setStatus(result, null);
        updateRescanUi("idle", "Conversation analyzed");
      })
      .catch(() => {
        updateRescanUi("idle", "Conversation analyze failed");
      });
  });
}

function setStatus(result, features) {
  for (const action of intervention.suggestedActions || []) {
    const li = document.createElement("li");
    li.textContent = action;
    actions.appendChild(li);
  }
}

function getActionGuide(result, features) {
  if (!result) {
    return "暫無分析結果。";
  }

  if (result?.suppression?.active) {
    return result.suppression.type === "trusted_host"
      ? "此網站目前在暫時信任名單中；如有異常請到設定頁移除。"
      : "本網址已被忽略一次；如仍有疑慮請手動重掃描。";
  }

  const attackType = String(result.attackType || "unknown");
  const host = features?.hostname || "此網站";
  const isEmail = result.source === "email";

  if (attackType === "customer_service_scam" || attackType === "phone_scam") {
    return "疑似假客服/來電詐騙：不要去 ATM 操作、不要提供 OTP，先撥 165 反詐騙專線。";
  }

  if (attackType === "investment_scam") {
    return "疑似投資詐騙：不要加投資群、不要入金，改用金管會揭露平台與官方券商管道查證。";
  }

  if (attackType === "government_impersonation") {
    return "疑似政府機關冒用：不要點簡訊連結，改用官方網站/App 或 1999/165 查證。";
  }

  if (attackType === "romance_scam") {
    return "疑似感情詐騙：不要借款或代收代付，先和親友交叉確認。";
  }

  if (attackType === "payment_fraud") {
    return "疑似付款/物流詐騙：先停止付款，改從官方 App 或官網客服查證訂單。";
  }

  if (attackType === "credential_harvest" || attackType === "brand_impersonation") {
    return `疑似帳密釣魚：不要在 ${host} 輸入密碼，請手動輸入官方網址再登入。`;
  }

  if (isEmail) {
    return "郵件風險偏高：優先核對寄件網域與回覆地址，避免直接點連結或下載附件。";
  }

  return "建議先暫停操作，改走官方管道核實。";
}

function getNextSteps(result, features) {
  if (!result) {
    return [
      "先按 Rescan Current Tab 取得最新判斷。",
      "若是訊息或電話內容，可複製重點到文字分析端點再做二次確認。"
    ];
  }

  if (result?.suppression?.active) {
    if (result.suppression.type === "trusted_host") {
      return [
        "此站點已暫時信任 24 小時，請留意網址是否有細微變化。",
        "若再次收到異常付款/驗證要求，請到 Settings 清除暫時信任名單。",
        "涉及金流操作前，仍建議用官方 App 或客服電話交叉確認。"
      ];
    }
    return [
      "此網址已被忽略一次，下一次重掃會恢復正常警示。",
      "若你仍覺得可疑，請立即重掃並不要輸入帳密或驗證碼。",
      "可先截圖保留證據，必要時向 165 反詐騙專線通報。"
    ];
  }

  const attackType = String(result.attackType || "unknown");
  const host = features?.hostname || "目前網站";

  if (attackType === "customer_service_scam" || attackType === "phone_scam") {
    return [
      "不要依照對方指示操作 ATM、網銀或提供 OTP。",
      "掛斷電話後，主動回撥官方客服或 165 反詐騙專線查證。",
      "若已轉帳，立刻聯絡銀行並保留通話與交易紀錄。"
    ];
  }

  if (attackType === "investment_scam") {
    return [
      "不要加入投資群、不要入金、不要下載來路不明投資 App。",
      "先查詢金管會/證交所公開資訊，確認平台與老師是否可驗證。",
      "任何保證獲利、穩賺不賠都應視為高風險警訊。"
    ];
  }

  if (attackType === "government_impersonation") {
    return [
      "不要點簡訊/訊息中的政府連結，改手動進入官方網站或 App。",
      "遇到「監管帳戶」「配合調查匯款」一律先停手並查證。",
      "可撥 1999 或 165 進行官方管道確認。"
    ];
  }

  if (attackType === "payment_fraud") {
    return [
      "先停止付款，改從官方商城或物流頁面查詢訂單。",
      `不要在 ${host} 直接輸入信用卡、網銀或超商代碼付款資訊。`,
      "若被要求改用 LINE 私下交易，請直接拒絕並回到平台內溝通。"
    ];
  }

  if (attackType === "credential_harvest" || attackType === "brand_impersonation") {
    return [
      "不要輸入帳號密碼，改手動輸入官方網址登入。",
      "若已輸入密碼，立刻改密碼並開啟雙重驗證。",
      "檢查近 24 小時登入紀錄與異常交易紀錄。"
    ];
  }

  return result.riskLevel === "high"
    ? [
        "風險偏高：先離開頁面並暫停任何付款或個資提交。",
        "改用官方客服電話、官網或 App 重新確認需求真實性。",
        "將可疑網址/訊息截圖留存，必要時通報 165。"
      ]
    : [
        "保持警覺，先核對網址、品牌網域與訊息來源。",
        "避免在不熟悉頁面輸入帳密或付款資訊。",
        "若內容催促你立刻操作，先暫停並做第二管道查證。"
      ];
}

function shouldShowQuickActions(result) {
  if (!result) {
    return false;
  }

  if (result?.suppression?.active) {
    return false;
  }

  if (result.analysisUnavailable) {
    return false;
  }

  return result.recommendedAction === "warn" || result.recommendedAction === "block" || result.riskLevel === "high";
}

function formatTimestamp(value) {
  if (!value) {
    return "No recent analysis";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "No recent analysis";
  }

  return `Analyzed ${date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit"
  })}`;
}

function truncateText(value, limit) {
  const text = String(value || "").trim();
  if (!text) {
    return "--";
  }

  if (text.length <= limit) {
    return text;
  }

  return `${text.slice(0, limit - 1)}…`;
}

function isDevelopmentMode() {
  const manifest = chrome.runtime.getManifest();
  return !Object.prototype.hasOwnProperty.call(manifest, "update_url");
}

function setupDebugPanelVisibility() {
  const panel = document.getElementById("debug-panel");
  if (!panel) {
    return;
  }

  if (!isDevelopmentMode()) {
    panel.hidden = true;
  }
}

function updateRescanUi(state, message) {
  const button = document.getElementById("rescan-btn");
  const status = document.getElementById("rescan-status");

  if (!button || !status) {
    return;
  }

  button.disabled = state === "loading";
  status.textContent = message;
}

function updateFeedbackUi(state, message) {
  const safeButton = document.getElementById("mark-safe-btn");
  const phishingButton = document.getElementById("mark-phishing-btn");
  const status = document.getElementById("feedback-status");
  const ignoreOnceBtn = document.getElementById("ignore-once-btn");
  const trustHostBtn = document.getElementById("trust-host-btn");

  if (!safeButton || !phishingButton || !status || !ignoreOnceBtn || !trustHostBtn) {
    return;
  }

  const isLoading = state === "loading";
  safeButton.disabled = isLoading;
  phishingButton.disabled = isLoading;
  ignoreOnceBtn.disabled = isLoading;
  trustHostBtn.disabled = isLoading;
  status.textContent = message;
}

function restoreDebugPanelState() {
  const panel = document.getElementById("debug-panel");
  if (!panel) {
    return;
  }

  chrome.storage.local.get(["debugPanelOpen"], ({ debugPanelOpen }) => {
    panel.open = Boolean(debugPanelOpen);
  });

  panel.addEventListener("toggle", () => {
    chrome.storage.local.set({ debugPanelOpen: panel.open });
  });
}

function setStatus(result, features) {
  const isUnavailable = Boolean(result?.analysisUnavailable);
  const status = document.getElementById("status");
  const score = document.getElementById("score");
  const reasons = document.getElementById("reasons");
  const badge = document.getElementById("badge");
  const subtitle = document.getElementById("subtitle");
  const action = document.getElementById("action");
  const attackType = document.getElementById("attack-type");
  const confidence = document.getElementById("confidence");
  const provider = document.getElementById("provider");
  const ruleScore = document.getElementById("rule-score");
  const llmScore = document.getElementById("llm-score");
  const meterFill = document.getElementById("meter-fill");
  const timestamp = document.getElementById("timestamp");
  const source = document.getElementById("source");
  const mailProvider = document.getElementById("mail-provider");
  const hostname = document.getElementById("hostname");
  const debugSubject = document.getElementById("debug-subject");
  const debugSender = document.getElementById("debug-sender");
  const debugBody = document.getElementById("debug-body");
  const actionGuide = document.getElementById("action-guide");
  const nextSteps = document.getElementById("next-steps");
  const suppressionBanner = document.getElementById("suppression-banner");
  const suppressionText = document.getElementById("suppression-text");
  const quickActions = document.getElementById("quick-actions");
  const ignoreOnceBtn = document.getElementById("ignore-once-btn");
  const trustHostBtn = document.getElementById("trust-host-btn");

  status.className = `status ${isUnavailable ? "neutral" : result?.riskLevel ?? "neutral"}`;
  badge.className = `badge ${isUnavailable ? "neutral" : result?.riskLevel ?? "neutral"}`;
  score.textContent = result ? String(result.score) : "--";
  meterFill.style.width = `${Math.max(0, Math.min(100, result?.score ?? 0))}%`;

  const label = status.querySelector(".status-label");
  label.textContent = isUnavailable
    ? "ANALYSIS UNAVAILABLE"
    : result
    ? `${result.riskLevel.toUpperCase()} RISK • ${result.recommendedAction.toUpperCase()}`
    : "Waiting for analysis";
  badge.textContent = isUnavailable ? "Unavailable" : result ? `${result.riskLevel} risk` : "Idle";
  subtitle.textContent = isUnavailable
    ? "The local API could not be reached. ScamNoMom showed a manual-review warning instead."
    : result
    ? result.source === "email"
      ? "Mail content assessed from sender, subject, links, and message body."
      : "Live page assessment generated from rules and language analysis."
    : "Open a page and let the extension analyze it.";
  action.textContent = result ? formatTitleCase(result.recommendedAction) : "Pending";
  attackType.textContent = result ? formatTitleCase(result.attackType) : "Unknown";
  confidence.textContent = result ? `${Math.round((result.confidence ?? 0) * 100)}%` : "--";
  provider.textContent = result ? formatTitleCase(result.provider) : "Waiting";
  source.textContent = result ? formatTitleCase(result.source) : "Waiting";
  mailProvider.textContent = features?.email?.provider ? formatTitleCase(features.email.provider) : "N/A";
  hostname.textContent = features?.hostname || "--";
  ruleScore.textContent = result ? String(result.evidence?.ruleScore ?? "--") : "--";
  llmScore.textContent = result ? String(result.evidence?.llmScore ?? "--") : "--";
  timestamp.textContent = formatTimestamp(result?.analyzedAt);
  debugSubject.textContent = truncateText(features?.email?.subject, 120);
  debugSender.textContent = truncateText(features?.email?.sender || features?.email?.replyTo, 120);
  debugBody.textContent = truncateText(features?.email?.bodyText || features?.visibleText, 260);
  if (actionGuide) {
    actionGuide.textContent = getActionGuide(result, features);
  }
  if (nextSteps) {
    nextSteps.innerHTML = "";
    for (const step of getNextSteps(result, features)) {
      const item = document.createElement("li");
      item.textContent = step;
      nextSteps.appendChild(item);
    }
  }

  if (suppressionBanner && suppressionText) {
    if (result?.suppression?.active) {
      suppressionBanner.hidden = false;
      suppressionText.textContent = result.suppression.message || "This result is currently suppressed.";
    } else {
      suppressionBanner.hidden = true;
      suppressionText.textContent = "";
    }
  }

  if (quickActions) {
    quickActions.hidden = !shouldShowQuickActions(result);
  }

  if (ignoreOnceBtn) {
    ignoreOnceBtn.disabled = !features?.url || Boolean(result?.suppression?.active);
  }
  if (trustHostBtn) {
    trustHostBtn.disabled = !features?.hostname;
  }

  renderInterventionPanel(result);
  renderCalibrationHint(result);
  renderConversationPanel(result);

  reasons.innerHTML = "";
  for (const reason of result?.reasons ?? ["No analysis yet."]) {
    const item = document.createElement("li");
    item.textContent = reason;
    reasons.appendChild(item);
  }
}

function refreshFromStorage() {
  chrome.storage.local.get(["latestAnalysis", "latestFeatures"], ({ latestAnalysis, latestFeatures }) => {
    setStatus(latestAnalysis ?? null, latestFeatures ?? null);
  });
}

function submitFeedback(label) {
  updateFeedbackUi("loading", "Saving feedback...");

  chrome.storage.local.get(["latestAnalysis", "latestFeatures"], ({ latestAnalysis, latestFeatures }) => {
    if (!latestAnalysis || !latestFeatures) {
      updateFeedbackUi("idle", "No analysis available");
      return;
    }

    chrome.runtime.sendMessage(
      {
        type: "PHISHGUARD_SUBMIT_FEEDBACK",
        payload: {
          label,
          analysis: latestAnalysis,
          features: latestFeatures
        }
      },
      (response) => {
        if (chrome.runtime.lastError) {
          updateFeedbackUi("idle", "Feedback failed");
          return;
        }

        if (!response?.ok) {
          updateFeedbackUi("idle", "Feedback failed");
          return;
        }

        updateFeedbackUi("idle", `Saved as ${label}`);
      }
    );
  });
}

function suppressOnceCurrentUrl() {
  updateFeedbackUi("loading", "Ignoring once...");
  chrome.storage.local.get(["latestFeatures"], ({ latestFeatures }) => {
    const url = latestFeatures?.url;
    if (!url) {
      updateFeedbackUi("idle", "No URL available");
      return;
    }

    chrome.runtime.sendMessage(
      {
        type: "PHISHGUARD_IGNORE_CURRENT_URL_ONCE",
        payload: { url }
      },
      (response) => {
        if (chrome.runtime.lastError || !response?.ok) {
          updateFeedbackUi("idle", "Ignore once failed");
          return;
        }
        currentFeedbackContext().then(({ analysis, features }) => {
          sendLearningEvent("ignore_once", {
            reason: "user_ignored_once",
            analysis,
            features
          });
        });
        updateFeedbackUi("idle", "Ignored once for this URL");
        chrome.runtime.sendMessage({ type: "PHISHGUARD_TRIGGER_RESCAN" }, () => {
          refreshFromStorage();
        });
      }
    );
  });
}

function trustCurrentHostTemporarily() {
  updateFeedbackUi("loading", "Trusting host...");
  chrome.storage.local.get(["latestFeatures"], ({ latestFeatures }) => {
    const hostname = latestFeatures?.hostname;
    if (!hostname) {
      updateFeedbackUi("idle", "No host available");
      return;
    }

    chrome.runtime.sendMessage(
      {
        type: "PHISHGUARD_TRUST_CURRENT_HOST",
        payload: { hostname }
      },
      (response) => {
        if (chrome.runtime.lastError || !response?.ok) {
          updateFeedbackUi("idle", "Temporary trust failed");
          return;
        }
        currentFeedbackContext().then(({ analysis, features }) => {
          sendLearningEvent("trusted_host", {
            reason: "user_trusted_host_temporarily",
            analysis,
            features
          });
        });
        updateFeedbackUi("idle", "Host trusted for 24h");
        chrome.runtime.sendMessage({ type: "PHISHGUARD_TRIGGER_RESCAN" }, () => {
          refreshFromStorage();
        });
      }
    );
  });
}

document.getElementById("rescan-btn")?.addEventListener("click", () => {
  updateRescanUi("loading", "Rescanning...");

  chrome.runtime.sendMessage({ type: "PHISHGUARD_TRIGGER_RESCAN" }, (response) => {
    if (chrome.runtime.lastError) {
      updateRescanUi("idle", "Rescan failed");
      return;
    }

    if (!response?.ok) {
      updateRescanUi("idle", "Rescan failed");
      refreshFromStorage();
      return;
    }

    updateRescanUi("idle", "Scan updated");
    refreshFromStorage();
  });
});

document.getElementById("mark-safe-btn")?.addEventListener("click", () => {
  submitFeedback("safe");
});

document.getElementById("mark-phishing-btn")?.addEventListener("click", () => {
  submitFeedback("phishing");
});

document.getElementById("ignore-once-btn")?.addEventListener("click", () => {
  suppressOnceCurrentUrl();
});

document.getElementById("trust-host-btn")?.addEventListener("click", () => {
  trustCurrentHostTemporarily();
});

document.getElementById("settings-btn")?.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") {
    return;
  }

  if (changes.latestAnalysis || changes.latestFeatures) {
    refreshFromStorage();
  }
});

restoreDebugPanelState();
setupDebugPanelVisibility();
updateFeedbackUi("idle", "No feedback sent");
resetInterventionPanel();
refreshFromStorage();
