export type ThreatIntelMode = "off" | "local" | "auto";

export function getThreatIntelConfig() {
  return {
    mode: (process.env.THREAT_INTEL_MODE?.trim().toLowerCase() || "auto") as ThreatIntelMode,
    timeoutMs: Number(process.env.THREAT_INTEL_TIMEOUT_MS || 3000),
    rdapBaseUrl: process.env.THREAT_INTEL_RDAP_BASE_URL?.trim() || "https://rdap.org/domain/",
    blacklist: {
      baseUrl: process.env.THREAT_INTEL_BLACKLIST_BASE_URL?.trim() || "",
      queryParam: process.env.THREAT_INTEL_BLACKLIST_QUERY_PARAM?.trim() || "target",
      apiKey: process.env.THREAT_INTEL_BLACKLIST_API_KEY?.trim() || "",
      apiKeyHeader: process.env.THREAT_INTEL_BLACKLIST_API_KEY_HEADER?.trim() || "x-api-key"
    }
  };
}

export function shouldUseExternalThreatIntel(): boolean {
  const config = getThreatIntelConfig();
  return config.mode === "auto";
}
