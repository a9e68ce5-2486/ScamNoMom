import { getThreatIntelConfig, shouldUseExternalThreatIntel } from "../config/threat-intel.js";

export interface ExternalThreatIntelResult {
  enabled: boolean;
  rdap?: {
    hostname: string;
    registrationDate?: string;
    lastChangedDate?: string;
    registrar?: string;
    domainAgeDays?: number;
  };
  blacklist?: {
    checked: boolean;
    listed: boolean;
    provider?: string;
    reason?: string;
  };
  reasons: string[];
  scoreDelta: number;
}

function normalizeHostname(value: string): string {
  return String(value || "").trim().toLowerCase();
}

function createTimeoutSignal(timeoutMs: number): { signal: AbortSignal; cleanup: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return {
    signal: controller.signal,
    cleanup: () => clearTimeout(timer)
  };
}

function isHostnameEligible(hostname: string): boolean {
  return Boolean(hostname) && !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) && hostname.includes(".");
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    promise
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}

async function fetchJson(url: string, init: RequestInit, timeoutMs: number, label: string): Promise<unknown> {
  const { signal, cleanup } = createTimeoutSignal(timeoutMs);
  try {
    const response = await withTimeout(
      fetch(url, {
        ...init,
        signal
      }),
      timeoutMs,
      label
    );
    if (!response.ok) {
      throw new Error(`${label} returned ${response.status}`);
    }
    return response.json();
  } catch (error) {
    if ((error as { name?: string }).name === "AbortError") {
      throw new Error(`${label} timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    cleanup();
  }
}

function parseRdapDate(events: unknown[], target: string): string | undefined {
  const event = events.find((entry) => {
    const action = String((entry as { eventAction?: string })?.eventAction || "").toLowerCase();
    return action === target;
  }) as { eventDate?: string } | undefined;

  return event?.eventDate;
}

async function fetchRdap(hostname: string): Promise<ExternalThreatIntelResult["rdap"] | undefined> {
  const config = getThreatIntelConfig();
  if (!config.rdapBaseUrl || !isHostnameEligible(hostname)) {
    return undefined;
  }

  const raw = (await fetchJson(
    `${config.rdapBaseUrl.replace(/\/+$/, "")}/${encodeURIComponent(hostname)}`,
    {
      method: "GET",
      headers: {
        "User-Agent": "scamnomom/external-threat-intel"
      }
    },
    config.timeoutMs,
    "RDAP lookup"
  )) as {
    events?: unknown[];
    entities?: Array<{ vcardArray?: unknown[]; roles?: string[]; handle?: string }>;
  };

  const events = Array.isArray(raw.events) ? raw.events : [];
  const registrationDate = parseRdapDate(events, "registration");
  const lastChangedDate = parseRdapDate(events, "last changed");
  const now = Date.now();
  const registrationTime = registrationDate ? Date.parse(registrationDate) : NaN;
  const domainAgeDays = Number.isFinite(registrationTime) ? Math.floor((now - registrationTime) / 86_400_000) : undefined;
  const registrarEntity = Array.isArray(raw.entities)
    ? raw.entities.find((entry) => Array.isArray(entry.roles) && entry.roles.some((role) => String(role).toLowerCase() === "registrar"))
    : undefined;

  return {
    hostname,
    registrationDate,
    lastChangedDate,
    registrar: registrarEntity?.handle,
    domainAgeDays
  };
}

async function fetchGenericBlacklist(hostname: string): Promise<ExternalThreatIntelResult["blacklist"] | undefined> {
  const config = getThreatIntelConfig();
  if (!config.blacklist.baseUrl || !hostname) {
    return undefined;
  }

  const url = new URL(config.blacklist.baseUrl);
  url.searchParams.set(config.blacklist.queryParam, hostname);

  const headers: Record<string, string> = {
    "User-Agent": "scamnomom/external-threat-intel"
  };

  if (config.blacklist.apiKey) {
    headers[config.blacklist.apiKeyHeader] = config.blacklist.apiKey;
  }

  const raw = (await fetchJson(
    url.toString(),
    {
      method: "GET",
      headers
    },
    config.timeoutMs,
    "Blacklist lookup"
  )) as {
    listed?: boolean;
    blocked?: boolean;
    malicious?: boolean;
    provider?: string;
    source?: string;
    reason?: string;
    description?: string;
  };

  const listed = Boolean(raw.listed || raw.blocked || raw.malicious);
  return {
    checked: true,
    listed,
    provider: raw.provider || raw.source || "generic",
    reason: raw.reason || raw.description
  };
}

export async function runExternalThreatIntel(hostname: string): Promise<ExternalThreatIntelResult> {
  if (!shouldUseExternalThreatIntel()) {
    return {
      enabled: false,
      reasons: [],
      scoreDelta: 0
    };
  }

  const normalizedHostname = normalizeHostname(hostname);
  const reasons: string[] = [];
  let scoreDelta = 0;

  const [rdap, blacklist] = await Promise.all([
    fetchRdap(normalizedHostname).catch(() => undefined),
    fetchGenericBlacklist(normalizedHostname).catch(() => undefined)
  ]);

  if (typeof rdap?.domainAgeDays === "number" && rdap.domainAgeDays >= 0 && rdap.domainAgeDays <= 30) {
    scoreDelta += 18;
    reasons.push("Domain appears to be very new based on RDAP registration data.");
  } else if (typeof rdap?.domainAgeDays === "number" && rdap.domainAgeDays <= 90) {
    scoreDelta += 10;
    reasons.push("Domain appears recently registered based on RDAP data.");
  }

  if (blacklist?.listed) {
    scoreDelta += 26;
    reasons.push(
      blacklist.reason
        ? `External blacklist provider flagged this host: ${blacklist.reason}.`
        : "External blacklist provider flagged this host as risky."
    );
  }

  return {
    enabled: true,
    rdap,
    blacklist,
    reasons,
    scoreDelta
  };
}
