const DEFAULT_SETTINGS = {
  apiBaseUrl: "http://localhost:8787",
  overlayEnabled: true,
  autoRescanEnabled: true,
  notificationMode: "standard",
  temporaryTrustedHosts: {}
};
window.__currentTrustedHosts = {};

function normalizeNotificationMode(value) {
  const mode = String(value || "").trim().toLowerCase();
  if (mode === "quiet" || mode === "standard" || mode === "sensitive") {
    return mode;
  }
  return "standard";
}

function normalizeTrustedHosts(value) {
  if (!value || typeof value !== "object") {
    return {};
  }
  const normalized = {};
  for (const [host, expiresAt] of Object.entries(value)) {
    const normalizedHost = String(host || "").trim().toLowerCase();
    const expiry = Number(expiresAt);
    if (!normalizedHost || !Number.isFinite(expiry)) {
      continue;
    }
    normalized[normalizedHost] = expiry;
  }
  return normalized;
}

function sanitizeSettings(rawSettings) {
  return {
    ...DEFAULT_SETTINGS,
    ...(rawSettings || {}),
    notificationMode: normalizeNotificationMode(rawSettings?.notificationMode),
    temporaryTrustedHosts: normalizeTrustedHosts(rawSettings?.temporaryTrustedHosts)
  };
}

function normalizeApiBaseUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    throw new Error("API Base URL cannot be empty.");
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("API Base URL format is invalid.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("API Base URL must start with http:// or https://");
  }

  parsed.hash = "";
  parsed.search = "";
  return parsed.toString().replace(/\/+$/, "");
}

function setStatus(message) {
  const status = document.getElementById("status");
  if (status) {
    status.textContent = message;
  }
}

function readForm() {
  const normalizedApiBaseUrl = normalizeApiBaseUrl(
    document.getElementById("api-base-url")?.value.trim() || DEFAULT_SETTINGS.apiBaseUrl
  );
  const notificationMode = normalizeNotificationMode(document.getElementById("notification-mode")?.value || "standard");
  const currentTrustedHosts = normalizeTrustedHosts(window.__currentTrustedHosts || {});
  return {
    apiBaseUrl: normalizedApiBaseUrl,
    overlayEnabled: Boolean(document.getElementById("overlay-enabled")?.checked),
    autoRescanEnabled: Boolean(document.getElementById("auto-rescan-enabled")?.checked),
    notificationMode,
    temporaryTrustedHosts: currentTrustedHosts
  };
}

function writeForm(settings) {
  const effective = sanitizeSettings(settings);
  window.__currentTrustedHosts = effective.temporaryTrustedHosts;

  const apiBaseUrl = document.getElementById("api-base-url");
  const overlayEnabled = document.getElementById("overlay-enabled");
  const autoRescanEnabled = document.getElementById("auto-rescan-enabled");
  const notificationMode = document.getElementById("notification-mode");
  const trustedHostsInfo = document.getElementById("trusted-hosts-info");

  const now = Date.now();
  const trustedHosts = Object.entries(effective.temporaryTrustedHosts)
    .filter(([, expiresAt]) => Number(expiresAt) > now)
    .map(([host, expiresAt]) => {
      const remainingMinutes = Math.max(1, Math.round((Number(expiresAt) - now) / 60000));
      return `${host} (${remainingMinutes}m)`;
    });

  if (apiBaseUrl) {
    apiBaseUrl.value = effective.apiBaseUrl;
  }
  if (overlayEnabled) {
    overlayEnabled.checked = effective.overlayEnabled;
  }
  if (autoRescanEnabled) {
    autoRescanEnabled.checked = effective.autoRescanEnabled;
  }
  if (notificationMode) {
    notificationMode.value = effective.notificationMode;
  }
  if (trustedHostsInfo) {
    trustedHostsInfo.textContent = trustedHosts.length > 0 ? trustedHosts.join(", ") : "No temporary trusted hosts.";
  }
}

function loadSettings() {
  chrome.storage.sync.get(["settings"], ({ settings }) => {
    writeForm(sanitizeSettings(settings));
    setStatus("Ready");
  });
}

function saveSettings() {
  try {
    const settings = sanitizeSettings(readForm());
    chrome.storage.sync.set({ settings }, () => {
      setStatus("Saved");
    });
  } catch (error) {
    setStatus(error.message || "Invalid API Base URL");
  }
}

function resetDefaults() {
  chrome.storage.sync.set({ settings: DEFAULT_SETTINGS }, () => {
    writeForm(DEFAULT_SETTINGS);
    setStatus("Reset to defaults");
  });
}

function clearTrustedHosts() {
  chrome.storage.sync.get(["settings"], ({ settings }) => {
    const current = sanitizeSettings(settings);
    const next = {
      ...current,
      temporaryTrustedHosts: {}
    };
    chrome.storage.sync.set({ settings: next }, () => {
      writeForm(next);
      setStatus("Cleared temporary trusted hosts");
    });
  });
}

document.getElementById("save-btn")?.addEventListener("click", saveSettings);
document.getElementById("reset-btn")?.addEventListener("click", resetDefaults);
document.getElementById("clear-trusted-btn")?.addEventListener("click", clearTrustedHosts);

loadSettings();
