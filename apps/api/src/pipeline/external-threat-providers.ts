import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ThreatIntelConfig } from "../config/threat-intel.js";

export interface ExternalThreatIntelInput {
  primaryHostname: string;
  relatedHostnames: string[];
  text?: string;
  brandSignals?: string[];
}

export interface ExternalThreatIntelProviderResult {
  provider: string;
  checked: boolean;
  scoreDelta: number;
  confidence: number;
  reasons: string[];
  evidence?: Record<string, unknown>;
}

export interface ExternalThreatIntelProvider {
  name: string;
  shouldRun: (config: ThreatIntelConfig, input: ExternalThreatIntelInput) => boolean;
  run: (config: ThreatIntelConfig, input: ExternalThreatIntelInput) => Promise<ExternalThreatIntelProviderResult>;
}

export interface ThreatIntelProfile {
  generatedAt: string;
  version: string;
  sampleStats: {
    phishing: number;
    safe: number;
  };
  tokenWeights: Array<{
    token: string;
    weight: number;
    phishingCount: number;
    safeCount: number;
  }>;
  riskyHosts: Array<{
    hostname: string;
    weight: number;
    phishingCount: number;
    safeCount: number;
  }>;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "../../../..");

const PROFILE_CACHE = {
  loadedAt: 0,
  path: "",
  profile: null as ThreatIntelProfile | null
};

function normalizeHostname(value: string): string {
  return String(value || "").trim().toLowerCase();
}

function isHostnameEligible(hostname: string): boolean {
  return Boolean(hostname) && !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) && hostname.includes(".");
}

function createTimeoutSignal(timeoutMs: number): { signal: AbortSignal; cleanup: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return {
    signal: controller.signal,
    cleanup: () => clearTimeout(timer)
  };
}

async function fetchJson(url: string, init: RequestInit, timeoutMs: number, label: string): Promise<unknown> {
  const { signal, cleanup } = createTimeoutSignal(timeoutMs);
  try {
    const response = await fetch(url, {
      ...init,
      signal
    });
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

function resolveProfilePath(rawPath: string): string {
  if (path.isAbsolute(rawPath)) {
    return rawPath;
  }

  return path.resolve(REPO_ROOT, rawPath);
}

function readThreatIntelProfile(config: ThreatIntelConfig): ThreatIntelProfile | null {
  const resolvedPath = resolveProfilePath(config.profile.path);
  const now = Date.now();
  if (PROFILE_CACHE.profile && PROFILE_CACHE.path === resolvedPath && now - PROFILE_CACHE.loadedAt < 5 * 60_000) {
    return PROFILE_CACHE.profile;
  }

  if (!existsSync(resolvedPath)) {
    PROFILE_CACHE.path = resolvedPath;
    PROFILE_CACHE.loadedAt = now;
    PROFILE_CACHE.profile = null;
    return null;
  }

  try {
    const parsed = JSON.parse(readFileSync(resolvedPath, "utf8")) as ThreatIntelProfile;
    const isValid =
      parsed &&
      Array.isArray(parsed.tokenWeights) &&
      Array.isArray(parsed.riskyHosts) &&
      typeof parsed.generatedAt === "string" &&
      typeof parsed.version === "string";
    PROFILE_CACHE.path = resolvedPath;
    PROFILE_CACHE.loadedAt = now;
    PROFILE_CACHE.profile = isValid ? parsed : null;
    return PROFILE_CACHE.profile;
  } catch {
    PROFILE_CACHE.path = resolvedPath;
    PROFILE_CACHE.loadedAt = now;
    PROFILE_CACHE.profile = null;
    return null;
  }
}

function extractLearningTokens(text: string): Set<string> {
  const normalized = String(text || "").toLowerCase();
  const chinese = normalized.match(/[\u4e00-\u9fff]{2,8}/g) || [];
  const latin = normalized.match(/[a-z0-9]{3,24}/g) || [];
  return new Set([...chinese, ...latin]);
}

function matchRiskyHosts(profile: ThreatIntelProfile, hostnames: string[]): Array<{ hostname: string; weight: number }> {
  const normalized = [...new Set(hostnames.map(normalizeHostname).filter(Boolean))];
  const matches: Array<{ hostname: string; weight: number }> = [];

  for (const candidate of profile.riskyHosts) {
    const profileHost = normalizeHostname(candidate.hostname);
    if (!profileHost) {
      continue;
    }

    const hasMatch = normalized.some((hostname) => hostname === profileHost || hostname.endsWith(`.${profileHost}`));
    if (hasMatch) {
      matches.push({ hostname: profileHost, weight: candidate.weight });
    }
  }

  return matches.sort((a, b) => b.weight - a.weight).slice(0, 6);
}

function matchRiskyTokens(
  profile: ThreatIntelProfile,
  tokens: Set<string>,
  minTokenWeight: number
): Array<{ token: string; weight: number }> {
  const matches: Array<{ token: string; weight: number }> = [];

  for (const candidate of profile.tokenWeights) {
    if (candidate.weight < minTokenWeight) {
      continue;
    }
    if (tokens.has(candidate.token.toLowerCase())) {
      matches.push({ token: candidate.token, weight: candidate.weight });
    }
  }

  return matches.sort((a, b) => b.weight - a.weight).slice(0, 8);
}

async function runRdapProvider(
  config: ThreatIntelConfig,
  input: ExternalThreatIntelInput
): Promise<ExternalThreatIntelProviderResult> {
  const hostname = normalizeHostname(input.primaryHostname);
  if (!config.rdapBaseUrl || !isHostnameEligible(hostname)) {
    return {
      provider: "rdap",
      checked: false,
      scoreDelta: 0,
      confidence: 0,
      reasons: []
    };
  }

  const raw = (await fetchJson(
    `${config.rdapBaseUrl.replace(/\/+$/, "")}/${encodeURIComponent(hostname)}`,
    {
      method: "GET",
      headers: {
        "User-Agent": "scamnomom/external-threat-intel-rdap"
      }
    },
    config.timeoutMs,
    "RDAP lookup"
  )) as {
    events?: unknown[];
    entities?: Array<{ roles?: string[]; handle?: string }>;
  };

  const events = Array.isArray(raw.events) ? raw.events : [];
  const registrationDate = parseRdapDate(events, "registration");
  const lastChangedDate = parseRdapDate(events, "last changed");
  const registrationTime = registrationDate ? Date.parse(registrationDate) : NaN;
  const domainAgeDays = Number.isFinite(registrationTime)
    ? Math.floor((Date.now() - registrationTime) / 86_400_000)
    : undefined;
  const registrarEntity = Array.isArray(raw.entities)
    ? raw.entities.find((entry) => Array.isArray(entry.roles) && entry.roles.some((role) => String(role).toLowerCase() === "registrar"))
    : undefined;

  let scoreDelta = 0;
  const reasons: string[] = [];
  let confidence = 0.4;

  if (typeof domainAgeDays === "number" && domainAgeDays >= 0 && domainAgeDays <= 30) {
    scoreDelta += 18;
    confidence = 0.78;
    reasons.push("Domain appears very new based on RDAP registration age.");
  } else if (typeof domainAgeDays === "number" && domainAgeDays <= 90) {
    scoreDelta += 10;
    confidence = 0.68;
    reasons.push("Domain appears recently registered based on RDAP.");
  }

  return {
    provider: "rdap",
    checked: true,
    scoreDelta,
    confidence,
    reasons,
    evidence: {
      hostname,
      registrationDate,
      lastChangedDate,
      registrar: registrarEntity?.handle,
      domainAgeDays
    }
  };
}

async function runGenericBlacklistProvider(
  config: ThreatIntelConfig,
  input: ExternalThreatIntelInput
): Promise<ExternalThreatIntelProviderResult> {
  const hostname = normalizeHostname(input.primaryHostname);
  if (!config.blacklist.baseUrl || !hostname) {
    return {
      provider: "blacklist",
      checked: false,
      scoreDelta: 0,
      confidence: 0,
      reasons: []
    };
  }

  const url = new URL(config.blacklist.baseUrl);
  url.searchParams.set(config.blacklist.queryParam, hostname);
  const headers: Record<string, string> = {
    "User-Agent": "scamnomom/external-threat-intel-blacklist"
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
  const reason = raw.reason || raw.description;

  return {
    provider: "blacklist",
    checked: true,
    scoreDelta: listed ? 26 : 0,
    confidence: listed ? 0.86 : 0.52,
    reasons: listed
      ? [reason ? `External blacklist provider flagged this host: ${reason}.` : "External blacklist provider flagged this host as risky."]
      : [],
    evidence: {
      checked: true,
      listed,
      provider: raw.provider || raw.source || "generic",
      reason
    }
  };
}

async function runLearningProfileProvider(
  config: ThreatIntelConfig,
  input: ExternalThreatIntelInput
): Promise<ExternalThreatIntelProviderResult> {
  const profile = readThreatIntelProfile(config);
  if (!profile) {
    return {
      provider: "learning_profile",
      checked: false,
      scoreDelta: 0,
      confidence: 0,
      reasons: []
    };
  }

  const mergedText = `${input.text || ""} ${(input.brandSignals || []).join(" ")}`.trim();
  const tokens = extractLearningTokens(mergedText);
  const matchedTokens = matchRiskyTokens(profile, tokens, config.profile.minTokenWeight);
  const matchedHosts = matchRiskyHosts(profile, [input.primaryHostname, ...input.relatedHostnames]);

  const tokenDelta = matchedTokens.reduce((sum, entry) => sum + Math.max(1, Math.round((entry.weight - 1) * 3)), 0);
  const hostDelta = matchedHosts.reduce((sum, entry) => sum + Math.max(2, Math.round(entry.weight * 4)), 0);
  const scoreDelta = Math.min(24, tokenDelta + hostDelta);
  const confidence = Math.min(0.92, 0.45 + matchedTokens.length * 0.06 + matchedHosts.length * 0.1);
  const reasons: string[] = [];

  if (matchedTokens.length > 0) {
    reasons.push(
      `Learning profile matched scam-like language tokens: ${matchedTokens
        .slice(0, 4)
        .map((entry) => entry.token)
        .join(", ")}.`
    );
  }

  if (matchedHosts.length > 0) {
    reasons.push(
      `Learning profile matched historically risky hosts/patterns: ${matchedHosts
        .slice(0, 3)
        .map((entry) => entry.hostname)
        .join(", ")}.`
    );
  }

  return {
    provider: "learning_profile",
    checked: true,
    scoreDelta,
    confidence: scoreDelta > 0 ? confidence : 0.4,
    reasons,
    evidence: {
      profileVersion: profile.version,
      generatedAt: profile.generatedAt,
      sampleStats: profile.sampleStats,
      matchedTokens,
      matchedHosts
    }
  };
}

export const EXTERNAL_THREAT_INTEL_PROVIDERS: ExternalThreatIntelProvider[] = [
  {
    name: "rdap",
    shouldRun: (config, input) => Boolean(config.rdapBaseUrl) && isHostnameEligible(input.primaryHostname),
    run: runRdapProvider
  },
  {
    name: "blacklist",
    shouldRun: (config, input) => Boolean(config.blacklist.baseUrl) && Boolean(input.primaryHostname),
    run: runGenericBlacklistProvider
  },
  {
    name: "learning_profile",
    shouldRun: (_config, input) => Boolean(input.primaryHostname),
    run: runLearningProfileProvider
  }
];
