function formatTitleCase(text) {
  return String(text || "")
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
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

  if (!safeButton || !phishingButton || !status) {
    return;
  }

  const isLoading = state === "loading";
  safeButton.disabled = isLoading;
  phishingButton.disabled = isLoading;
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
refreshFromStorage();
