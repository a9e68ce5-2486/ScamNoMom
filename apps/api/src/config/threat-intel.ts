export type ThreatIntelMode = "off" | "local" | "auto";

export interface ThreatIntelConfig {
  mode: ThreatIntelMode;
  timeoutMs: number;
  rdapBaseUrl: string;
  blacklist: {
    baseUrl: string;
    queryParam: string;
    apiKey: string;
    apiKeyHeader: string;
  };
  profile: {
    path: string;
    minTokenWeight: number;
  };
  policy: {
    maxScoreDelta: number;
    singleProviderPenalty: number;
    multiProviderBoost: number;
  };
}

function clampNumber(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, parsed));
}

function parseMode(value: string | undefined): ThreatIntelMode {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "off" || normalized === "local" || normalized === "auto") {
    return normalized;
  }
  return "auto";
}

export function getThreatIntelConfig() {
  const mode = parseMode(process.env.THREAT_INTEL_MODE);
  return {
    mode,
    timeoutMs: clampNumber(process.env.THREAT_INTEL_TIMEOUT_MS, 3000, 500, 15_000),
    rdapBaseUrl: process.env.THREAT_INTEL_RDAP_BASE_URL?.trim() || "https://rdap.org/domain/",
    blacklist: {
      baseUrl: process.env.THREAT_INTEL_BLACKLIST_BASE_URL?.trim() || "",
      queryParam: process.env.THREAT_INTEL_BLACKLIST_QUERY_PARAM?.trim() || "target",
      apiKey: process.env.THREAT_INTEL_BLACKLIST_API_KEY?.trim() || "",
      apiKeyHeader: process.env.THREAT_INTEL_BLACKLIST_API_KEY_HEADER?.trim() || "x-api-key"
    },
    profile: {
      path: process.env.THREAT_INTEL_PROFILE_PATH?.trim() || "data/processed/threat-intel-profile.json",
      minTokenWeight: clampNumber(process.env.THREAT_INTEL_PROFILE_MIN_TOKEN_WEIGHT, 1.4, 0.8, 5)
    },
    policy: {
      maxScoreDelta: clampNumber(process.env.THREAT_INTEL_POLICY_MAX_DELTA, 38, 10, 80),
      singleProviderPenalty: clampNumber(process.env.THREAT_INTEL_POLICY_SINGLE_PROVIDER_PENALTY, 0.72, 0.3, 1),
      multiProviderBoost: clampNumber(process.env.THREAT_INTEL_POLICY_MULTI_PROVIDER_BOOST, 4, 0, 20)
    }
  } satisfies ThreatIntelConfig;
}

export function shouldUseExternalThreatIntel(): boolean {
  const config = getThreatIntelConfig();
  return config.mode === "auto";
}
