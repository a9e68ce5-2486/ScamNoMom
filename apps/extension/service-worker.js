const DEFAULT_SETTINGS = {
  apiBaseUrl: "http://localhost:8787",
  overlayEnabled: true,
  autoRescanEnabled: true
};

async function getSettings() {
  const { settings } = await chrome.storage.sync.get(["settings"]);
  return {
    ...DEFAULT_SETTINGS,
    ...(settings || {})
  };
}

async function analyzePayload(payload) {
  const settings = await getSettings();
  const response = await fetch(`${settings.apiBaseUrl}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return response.json();
}

async function submitFeedback(payload) {
  const settings = await getSettings();
  const response = await fetch(`${settings.apiBaseUrl}/feedback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return response.json();
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
          sendResponse({ ok: false, error: chrome.runtime.lastError.message });
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
