import { readFile, readdir } from "node:fs/promises";
import dns from "node:dns/promises";
import path from "node:path";

export interface ThreatIntelDnsFinding {
  hostname: string;
  aRecordCount: number;
  nsRecordCount: number;
  mxRecordCount: number;
  hasSpfRecord: boolean;
  lookupError?: string;
}

export interface ThreatIntelResult {
  checkedHostnames: string[];
  blacklistMatches: string[];
  riskyIpHosts: string[];
  dnsFindings: ThreatIntelDnsFinding[];
  reasons: string[];
  scoreDelta: number;
}

const EXTERNAL_DATA_DIR = path.resolve(process.cwd(), "../../data/raw/external");
const TRAINING_SAMPLES_PATH = path.resolve(process.cwd(), "../../data/processed/training-samples.json");

const blacklistCache = {
  loadedAt: 0,
  hostnames: new Set<string>()
};

function isIpHostname(hostname: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function normalizeHostname(value: string): string {
  return String(value || "").trim().toLowerCase();
}

function hostnameFromUrl(value: string): string {
  try {
    return normalizeHostname(new URL(value).hostname);
  } catch {
    return "";
  }
}

async function readOptionalJsonArray(filePath: string): Promise<unknown[]> {
  try {
    const raw = await readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }

    return [];
  }
}

async function collectFeedHostnames(): Promise<Set<string>> {
  const hostnames = new Set<string>();

  try {
    const fileNames = await readdir(EXTERNAL_DATA_DIR);

    for (const fileName of fileNames) {
      const fullPath = path.join(EXTERNAL_DATA_DIR, fileName);
      const raw = await readFile(fullPath, "utf8");

      if (fileName.endsWith(".txt")) {
        for (const line of raw.split(/\r?\n/)) {
          const hostname = hostnameFromUrl(line);
          if (hostname) {
            hostnames.add(hostname);
          }
        }
        continue;
      }

      if (fileName.endsWith(".json")) {
        const records = JSON.parse(raw);
        if (!Array.isArray(records)) {
          continue;
        }

        for (const record of records) {
          const url =
            typeof record === "string"
              ? record
              : String(record?.url || record?.phish_url || record?.phishURL || "");
          const hostname = hostnameFromUrl(url);
          if (hostname) {
            hostnames.add(hostname);
          }
        }
      }
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }

  const trainingSamples = await readOptionalJsonArray(TRAINING_SAMPLES_PATH);
  for (const sample of trainingSamples) {
    const label = String((sample as { label?: string })?.label || "");
    if (label !== "phishing") {
      continue;
    }

    const hostname =
      normalizeHostname((sample as { content?: { hostname?: string } })?.content?.hostname || "") ||
      hostnameFromUrl((sample as { content?: { url?: string } })?.content?.url || "");

    if (hostname) {
      hostnames.add(hostname);
    }
  }

  return hostnames;
}

async function loadBlacklistHostnames(): Promise<Set<string>> {
  const now = Date.now();
  if (now - blacklistCache.loadedAt < 5 * 60_000 && blacklistCache.hostnames.size > 0) {
    return blacklistCache.hostnames;
  }

  blacklistCache.hostnames = await collectFeedHostnames();
  blacklistCache.loadedAt = now;
  return blacklistCache.hostnames;
}

async function lookupDns(hostname: string): Promise<ThreatIntelDnsFinding> {
  try {
    const [aRecords, nsRecords, mxRecords, txtRecords] = await Promise.all([
      dns.resolve4(hostname).catch(() => []),
      dns.resolveNs(hostname).catch(() => []),
      dns.resolveMx(hostname).catch(() => []),
      dns.resolveTxt(hostname).catch(() => [])
    ]);

    const hasSpfRecord = txtRecords.some((parts) => parts.join("").toLowerCase().includes("v=spf1"));

    return {
      hostname,
      aRecordCount: aRecords.length,
      nsRecordCount: nsRecords.length,
      mxRecordCount: mxRecords.length,
      hasSpfRecord
    };
  } catch (error) {
    return {
      hostname,
      aRecordCount: 0,
      nsRecordCount: 0,
      mxRecordCount: 0,
      hasSpfRecord: false,
      lookupError: (error as Error).message
    };
  }
}

export async function runThreatIntel(hostnames: string[], emailSenderDomain?: string | null): Promise<ThreatIntelResult> {
  const normalizedHostnames = [...new Set(hostnames.map(normalizeHostname).filter(Boolean))].slice(0, 8);
  const checkedHostnames = [...normalizedHostnames];
  const riskyIpHosts = normalizedHostnames.filter(isIpHostname);
  const blacklist = await loadBlacklistHostnames();
  const blacklistMatches = normalizedHostnames.filter((hostname) => blacklist.has(hostname));

  if (emailSenderDomain) {
    const normalizedSender = normalizeHostname(emailSenderDomain);
    if (normalizedSender && !checkedHostnames.includes(normalizedSender)) {
      checkedHostnames.push(normalizedSender);
    }
  }

  const dnsTargets = checkedHostnames.slice(0, 5);
  const dnsFindings = await Promise.all(dnsTargets.map((hostname) => lookupDns(hostname)));
  const reasons: string[] = [];
  let scoreDelta = 0;

  if (blacklistMatches.length > 0) {
    scoreDelta += 24;
    reasons.push(`Host matched local phishing feed intelligence: ${blacklistMatches.slice(0, 3).join(", ")}.`);
  }

  if (riskyIpHosts.length > 0) {
    scoreDelta += 14;
    reasons.push("Link or page uses a raw IP address instead of a normal domain name.");
  }

  const unresolvedHosts = dnsFindings.filter(
    (finding) =>
      !finding.lookupError &&
      finding.aRecordCount === 0 &&
      finding.nsRecordCount === 0 &&
      finding.mxRecordCount === 0
  );
  if (unresolvedHosts.length > 0) {
    scoreDelta += 8;
    reasons.push("Some checked hosts expose unusually weak DNS signals.");
  }

  return {
    checkedHostnames,
    blacklistMatches,
    riskyIpHosts,
    dnsFindings,
    reasons,
    scoreDelta
  };
}
