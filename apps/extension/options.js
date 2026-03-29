const DEFAULT_SETTINGS = {
  apiBaseUrl: "http://localhost:8787",
  overlayEnabled: true,
  autoRescanEnabled: true
};

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
  return {
    apiBaseUrl: normalizedApiBaseUrl,
    overlayEnabled: Boolean(document.getElementById("overlay-enabled")?.checked),
    autoRescanEnabled: Boolean(document.getElementById("auto-rescan-enabled")?.checked)
  };
}

function writeForm(settings) {
  const effective = {
    ...DEFAULT_SETTINGS,
    ...(settings || {})
  };

  const apiBaseUrl = document.getElementById("api-base-url");
  const overlayEnabled = document.getElementById("overlay-enabled");
  const autoRescanEnabled = document.getElementById("auto-rescan-enabled");

  if (apiBaseUrl) {
    apiBaseUrl.value = effective.apiBaseUrl;
  }
  if (overlayEnabled) {
    overlayEnabled.checked = effective.overlayEnabled;
  }
  if (autoRescanEnabled) {
    autoRescanEnabled.checked = effective.autoRescanEnabled;
  }
}

function loadSettings() {
  chrome.storage.sync.get(["settings"], ({ settings }) => {
    writeForm(settings);
    setStatus("Ready");
  });
}

function saveSettings() {
  try {
    const settings = readForm();
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

document.getElementById("save-btn")?.addEventListener("click", saveSettings);
document.getElementById("reset-btn")?.addEventListener("click", resetDefaults);

loadSettings();
