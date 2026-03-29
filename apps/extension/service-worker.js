const DEFAULT_SETTINGS = {
  apiBaseUrl: "http://localhost:8787",
  overlayEnabled: true,
  autoRescanEnabled: true
};
const REQUEST_TIMEOUT_MS = 8000;

function normalizeApiBaseUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    throw new Error("API base URL is empty.");
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("API base URL is invalid.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("API base URL must use http or https.");
  }

  parsed.hash = "";
  parsed.search = "";
  return parsed.toString().replace(/\/+$/, "");
}

async function getSettings() {
  const { settings } = await chrome.storage.sync.get(["settings"]);
  return {
    ...DEFAULT_SETTINGS,
    ...(settings || {})
  };
}

async function fetchJsonWithTimeout(url, init) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      ...init,
      signal: controller.signal
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error(`Request timed out after ${REQUEST_TIMEOUT_MS}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function analyzePayload(payload) {
  const settings = await getSettings();
  const baseUrl = normalizeApiBaseUrl(settings.apiBaseUrl);
  return fetchJsonWithTimeout(`${baseUrl}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
}

async function submitFeedback(payload) {
  const settings = await getSettings();
  const baseUrl = normalizeApiBaseUrl(settings.apiBaseUrl);
  return fetchJsonWithTimeout(`${baseUrl}/feedback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "PHISHGUARD_ANALYZE_PAGE") {
    analyzePayload(message.payload)
    .then(async (result) => {
      await chrome.storage.local.set({
        latestAnalysis: result,
        latestFeatures: message.payload
      });
      sendResponse({ ok: true, result });
    })
    .catch(async (error) => {
      const fallback = {
        source: message.payload?.source ?? "web",
        riskLevel: "low",
        score: 0,
        reasons: [`Analysis unavailable: ${error.message}`],
        confidence: 0,
        attackType: "unknown",
        recommendedAction: "warn",
        provider: "fallback",
        analyzedAt: new Date().toISOString(),
        analysisUnavailable: true,
        evidence: {
          ruleScore: 0,
          llmScore: 0,
          routerDecision: "warn"
        }
      };
      await chrome.storage.local.set({
        latestAnalysis: fallback,
        latestFeatures: message.payload
      });
      sendResponse({ ok: false, error: error.message, result: fallback });
    });

    return true;
  }

  if (message?.type === "PHISHGUARD_TRIGGER_RESCAN") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      if (!activeTab?.id) {
        sendResponse({ ok: false, error: "No active tab found." });
        return;
      }

      chrome.tabs.sendMessage(activeTab.id, { type: "PHISHGUARD_RESCAN" }, (response) => {
        if (chrome.runtime.lastError) {
          const rawMessage = chrome.runtime.lastError.message || "Rescan failed.";
          const friendlyMessage = rawMessage.includes("Receiving end does not exist")
            ? "This page cannot be scanned. Try a normal website tab or reload the page."
            : rawMessage;
          sendResponse({ ok: false, error: friendlyMessage });
          return;
        }

        sendResponse(response ?? { ok: false, error: "No response from content script." });
      });
    });

    return true;
  }

  if (message?.type === "PHISHGUARD_SUBMIT_FEEDBACK") {
    submitFeedback(message.payload)
      .then((result) => {
        sendResponse({ ok: true, result });
      })
      .catch((error) => {
        sendResponse({ ok: false, error: error.message });
      });

    return true;
  }

  return false;
});
