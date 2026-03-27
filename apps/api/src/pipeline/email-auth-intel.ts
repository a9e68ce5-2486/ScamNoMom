import dns from "node:dns/promises";

export interface EmailAuthIntelResult {
  domain: string;
  mxRecordCount: number;
  hasSpfRecord: boolean;
  hasDmarcRecord: boolean;
  dmarcPolicy?: "none" | "quarantine" | "reject";
  discoverableDkimSelectors: string[];
  checkedDkimSelectors: string[];
  reasons: string[];
  scoreDelta: number;
}

const COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "dkim", "mail", "s1", "s2"];

function normalizeDomain(value: string | null | undefined): string {
  return String(value || "").trim().toLowerCase();
}

async function resolveTxt(hostname: string): Promise<string[]> {
  try {
    const records = await dns.resolveTxt(hostname);
    return records.map((parts) => parts.join(""));
  } catch {
    return [];
  }
}

async function resolveMxCount(hostname: string): Promise<number> {
  try {
    const records = await dns.resolveMx(hostname);
    return records.length;
  } catch {
    return 0;
  }
}

function parseDmarcPolicy(records: string[]): "none" | "quarantine" | "reject" | undefined {
  for (const record of records) {
    const match = record.match(/\bp=([a-z]+)/i);
    const policy = match?.[1]?.toLowerCase();
    if (policy === "none" || policy === "quarantine" || policy === "reject") {
      return policy;
    }
  }

  return undefined;
}

async function discoverDkimSelectors(domain: string): Promise<string[]> {
  const found: string[] = [];

  for (const selector of COMMON_DKIM_SELECTORS) {
    const records = await resolveTxt(`${selector}._domainkey.${domain}`);
    if (records.length > 0) {
      found.push(selector);
    }
  }

  return found;
}

export async function runEmailAuthIntel(senderDomain: string | null | undefined, hasBrandClaim: boolean): Promise<EmailAuthIntelResult | null> {
  const domain = normalizeDomain(senderDomain);
  if (!domain) {
    return null;
  }

  const [mxRecordCount, rootTxtRecords, dmarcTxtRecords, discoverableDkimSelectors] = await Promise.all([
    resolveMxCount(domain),
    resolveTxt(domain),
    resolveTxt(`_dmarc.${domain}`),
    discoverDkimSelectors(domain)
  ]);

  const hasSpfRecord = rootTxtRecords.some((record) => record.toLowerCase().includes("v=spf1"));
  const hasDmarcRecord = dmarcTxtRecords.some((record) => record.toLowerCase().includes("v=dmarc1"));
  const dmarcPolicy = parseDmarcPolicy(dmarcTxtRecords);

  const reasons: string[] = [];
  let scoreDelta = 0;

  if (mxRecordCount === 0) {
    scoreDelta += 10;
    reasons.push("Sender domain does not expose MX records, which is unusual for a real mail sender.");
  }

  if (!hasSpfRecord) {
    scoreDelta += hasBrandClaim ? 10 : 6;
    reasons.push("Sender domain does not expose an SPF TXT record.");
  }

  if (!hasDmarcRecord) {
    scoreDelta += hasBrandClaim ? 12 : 8;
    reasons.push("Sender domain does not expose a DMARC record.");
  } else if (dmarcPolicy === "none" && hasBrandClaim) {
    scoreDelta += 4;
    reasons.push("Sender domain publishes DMARC but uses a monitoring-only policy.");
  }

  if (discoverableDkimSelectors.length > 0) {
    reasons.push(`Sender domain exposes discoverable DKIM selectors: ${discoverableDkimSelectors.slice(0, 3).join(", ")}.`);
  } else if (hasBrandClaim) {
    reasons.push("No common DKIM selectors were discoverable for the sender domain.");
  }

  return {
    domain,
    mxRecordCount,
    hasSpfRecord,
    hasDmarcRecord,
    dmarcPolicy,
    discoverableDkimSelectors,
    checkedDkimSelectors: COMMON_DKIM_SELECTORS,
    reasons,
    scoreDelta
  };
}
