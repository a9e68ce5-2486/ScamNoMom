const DEFAULT_SETTINGS = {
  apiBaseUrl: "http://localhost:8787",
  overlayEnabled: true,
  autoRescanEnabled: true,
  notificationMode: "standard",
  calibrationProfile: {
    riskTolerance: "balanced",
    sensitivityBoost: 0,
    falsePositiveRateHint: 0.15,
    highValueProtection: true
  },
  temporaryTrustedHosts: {}
};
const REQUEST_TIMEOUT_MS = 8000;
const TRUST_HOST_TTL_MS = 24 * 60 * 60 * 1000;
const IGNORE_ONCE_TTL_MS = 2 * 60 * 60 * 1000;
const IGNORE_ONCE_KEY = "ignoreOnceUrls";
const FEEDBACK_EVENTS_KEY = "feedbackEvents";
const FEEDBACK_EVENT_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_TRUSTED_HOSTS = 300;

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
  const effective = sanitizeSettings({
    ...DEFAULT_SETTINGS,
    ...(settings || {})
  });
  if (JSON.stringify(settings || {}) !== JSON.stringify(effective)) {
    await chrome.storage.sync.set({ settings: effective });
  }
  return effective;
}

function normalizeHostname(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeNotificationMode(value) {
  const candidate = String(value || "").trim().toLowerCase();
  if (candidate === "quiet" || candidate === "standard" || candidate === "sensitive") {
    return candidate;
  }
  return "standard";
}

function sanitizeSettings(rawSettings) {
  const now = Date.now();
  const normalizedTrustedHosts = {};
  const trustedHosts = rawSettings?.temporaryTrustedHosts || {};
  for (const [host, expiresAt] of Object.entries(trustedHosts)) {
    const normalizedHost = normalizeHostname(host);
    const expiry = Number(expiresAt);
    if (!normalizedHost || !Number.isFinite(expiry) || expiry <= now) {
      continue;
    }
    normalizedTrustedHosts[normalizedHost] = expiry;
    if (Object.keys(normalizedTrustedHosts).length >= MAX_TRUSTED_HOSTS) {
      break;
    }
  }

  return {
    ...DEFAULT_SETTINGS,
    ...rawSettings,
    apiBaseUrl: rawSettings?.apiBaseUrl || DEFAULT_SETTINGS.apiBaseUrl,
    overlayEnabled: typeof rawSettings?.overlayEnabled === "boolean" ? rawSettings.overlayEnabled : DEFAULT_SETTINGS.overlayEnabled,
    autoRescanEnabled:
      typeof rawSettings?.autoRescanEnabled === "boolean" ? rawSettings.autoRescanEnabled : DEFAULT_SETTINGS.autoRescanEnabled,
    notificationMode: normalizeNotificationMode(rawSettings?.notificationMode),
    calibrationProfile: sanitizeCalibrationProfile(rawSettings?.calibrationProfile),
    temporaryTrustedHosts: normalizedTrustedHosts
  };
}

function sanitizeCalibrationProfile(value) {
  const profile = value && typeof value === "object" ? value : {};
  const riskTolerance =
    profile.riskTolerance === "low" || profile.riskTolerance === "high" ? profile.riskTolerance : "balanced";
  const sensitivityBoost = Number(profile.sensitivityBoost);
  const falsePositiveRateHint = Number(profile.falsePositiveRateHint);
  return {
    riskTolerance,
    sensitivityBoost: Number.isFinite(sensitivityBoost) ? Math.max(-20, Math.min(20, sensitivityBoost)) : 0,
    falsePositiveRateHint: Number.isFinite(falsePositiveRateHint)
      ? Math.max(0, Math.min(0.8, falsePositiveRateHint))
      : 0.15,
    highValueProtection: typeof profile.highValueProtection === "boolean" ? profile.highValueProtection : true
  };
}

async function setTrustedHost(hostname) {
  const normalizedHost = normalizeHostname(hostname);
  if (!normalizedHost) {
    throw new Error("No valid hostname to trust.");
  }
  const settings = await getSettings();
  const next = {
    ...settings.temporaryTrustedHosts,
    [normalizedHost]: Date.now() + TRUST_HOST_TTL_MS
  };
  const sanitized = sanitizeSettings({
    ...settings,
    temporaryTrustedHosts: next
  });
  await chrome.storage.sync.set({ settings: sanitized });
  await recordFeedbackEvent({
    eventType: "temporary_trust_host",
    hostname: normalizedHost
  });
  return {
    hostname: normalizedHost,
    expiresAt: sanitized.temporaryTrustedHosts[normalizedHost]
  };
}

async function removeTrustedHost(hostname) {
  const normalizedHost = normalizeHostname(hostname);
  const settings = await getSettings();
  const next = {
    ...settings.temporaryTrustedHosts
  };
  delete next[normalizedHost];
  await chrome.storage.sync.set({
    settings: sanitizeSettings({
      ...settings,
      temporaryTrustedHosts: next
    })
  });
}

async function clearTrustedHosts() {
  const settings = await getSettings();
  await chrome.storage.sync.set({
    settings: sanitizeSettings({
      ...settings,
      temporaryTrustedHosts: {}
    })
  });
}

function normalizePageUrl(url) {
  const raw = String(url || "").trim();
  if (!raw) {
    throw new Error("URL is empty.");
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("URL is invalid.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("URL must use http or https.");
  }

  parsed.hash = "";
  return parsed.toString();
}

async function setIgnoreOnceUrl(url) {
  const normalizedUrl = normalizePageUrl(url);
  const { [IGNORE_ONCE_KEY]: ignoreMap } = await chrome.storage.local.get([IGNORE_ONCE_KEY]);
  const next = {
    ...(ignoreMap || {}),
    [normalizedUrl]: Date.now() + IGNORE_ONCE_TTL_MS
  };
  await chrome.storage.local.set({
    [IGNORE_ONCE_KEY]: next
  });
  let hostname = "";
  try {
    hostname = new URL(normalizedUrl).hostname.toLowerCase();
  } catch {
    hostname = "";
  }
  await recordFeedbackEvent({
    eventType: "ignore_once_url",
    url: normalizedUrl,
    hostname
  });
  return normalizedUrl;
}

async function recordFeedbackEvent(event) {
  const now = Date.now();
  const { [FEEDBACK_EVENTS_KEY]: existing } = await chrome.storage.local.get([FEEDBACK_EVENTS_KEY]);
  const current = Array.isArray(existing) ? existing : [];
  const next = current
    .filter((item) => Number(item?.createdAtTs || 0) + FEEDBACK_EVENT_TTL_MS > now)
    .slice(-400);
  next.push({
    ...event,
    createdAtTs: now,
    createdAt: new Date(now).toISOString()
  });
  await chrome.storage.local.set({
    [FEEDBACK_EVENTS_KEY]: next
  });
}

async function consumeIgnoreOnceUrl(url) {
  const normalizedUrl = normalizePageUrl(url);
  const { [IGNORE_ONCE_KEY]: ignoreMap } = await chrome.storage.local.get([IGNORE_ONCE_KEY]);
  const now = Date.now();
  const current = ignoreMap || {};
  const next = {};
  let matched = false;

  for (const [entryUrl, expiresAt] of Object.entries(current)) {
    const expiry = Number(expiresAt);
    if (!Number.isFinite(expiry) || expiry <= now) {
      continue;
    }
    if (entryUrl === normalizedUrl && !matched) {
      matched = true;
      continue;
    }
    next[entryUrl] = expiry;
  }

  await chrome.storage.local.set({
    [IGNORE_ONCE_KEY]: next
  });
  return matched;
}

async function resolveSuppression(payload, settings) {
  const trustedHostExpiry = settings.temporaryTrustedHosts[normalizeHostname(payload?.hostname)];
  if (Number.isFinite(trustedHostExpiry) && trustedHostExpiry > Date.now()) {
    return {
      active: true,
      type: "trusted_host",
      message: "Suppressed by temporary trust for this host.",
      expiresAt: trustedHostExpiry
    };
  }

  if (payload?.url) {
    const ignored = await consumeIgnoreOnceUrl(payload.url).catch(() => false);
    if (ignored) {
      return {
        active: true,
        type: "ignore_once",
        message: "Suppressed once for this URL."
      };
    }
  }

  return null;
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
    body: JSON.stringify({
      ...payload,
      calibration: settings.calibrationProfile
    })
  });
}

async function submitFeedback(payload) {
  const settings = await getSettings();
  const baseUrl = normalizeApiBaseUrl(settings.apiBaseUrl);
  const { [FEEDBACK_EVENTS_KEY]: events } = await chrome.storage.local.get([FEEDBACK_EVENTS_KEY]);
  const feedbackEvents = Array.isArray(events) ? events.slice(-100) : [];
  return fetchJsonWithTimeout(`${baseUrl}/feedback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      ...payload,
      context: {
        feedbackEvents
      }
    })
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "PHISHGUARD_ANALYZE_PAGE") {
    Promise.all([analyzePayload(message.payload), getSettings()])
    .then(async ([result, settings]) => {
      const suppression = await resolveSuppression(message.payload, settings);
      const enhancedResult = suppression
        ? {
            ...result,
            suppression
          }
        : result;
      await chrome.storage.local.set({
        latestAnalysis: enhancedResult,
        latestFeatures: message.payload
      });
      sendResponse({ ok: true, result: enhancedResult });
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

  if (message?.type === "PHISHGUARD_RECORD_LEARNING_EVENT") {
    const payload = message.payload || {};
    const normalizedType =
      payload.type === "ignore_once" || payload.type === "trusted_host" ? payload.type : null;
    if (!normalizedType) {
      sendResponse({ ok: false, error: "Invalid learning event type." });
      return true;
    }

    recordFeedbackEvent({
      eventType: normalizedType,
      reason: String(payload.reason || "").slice(0, 200),
      url: payload.features?.url || "",
      hostname: payload.features?.hostname || "",
      analysis: payload.analysis || null,
      features: payload.features || null
    })
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message?.type === "PHISHGUARD_IGNORE_CURRENT_URL_ONCE") {
    setIgnoreOnceUrl(message.payload?.url || "")
      .then((url) => sendResponse({ ok: true, url }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message?.type === "PHISHGUARD_TRUST_CURRENT_HOST") {
    setTrustedHost(message.payload?.hostname || "")
      .then((result) => sendResponse({ ok: true, ...result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message?.type === "PHISHGUARD_REMOVE_TRUSTED_HOST") {
    removeTrustedHost(message.payload?.hostname || "")
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message?.type === "PHISHGUARD_CLEAR_TRUSTED_HOSTS") {
    clearTrustedHosts()
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  return false;
});
