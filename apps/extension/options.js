const DEFAULT_SETTINGS = {
  apiBaseUrl: "http://localhost:8787",
  overlayEnabled: true,
  autoRescanEnabled: true
};

function setStatus(message) {
  const status = document.getElementById("status");
  if (status) {
    status.textContent = message;
  }
}

function readForm() {
  return {
    apiBaseUrl: document.getElementById("api-base-url")?.value.trim() || DEFAULT_SETTINGS.apiBaseUrl,
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
  const settings = readForm();
  chrome.storage.sync.set({ settings }, () => {
    setStatus("Saved");
  });
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
