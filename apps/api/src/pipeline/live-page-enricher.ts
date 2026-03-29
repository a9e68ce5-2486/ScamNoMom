import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { JSDOM } from "jsdom";
import type { PageFeatures } from "../types/analysis.js";

type DomElement = {
  getAttribute: (name: string) => string | null;
  textContent: string | null;
};

interface LiveEnrichmentConfig {
  enabled: boolean;
  timeoutMs: number;
  cacheTtlMs: number;
  maxCacheEntries: number;
  maxHtmlBytes: number;
  maxVisibleTextLength: number;
  minInitialScore: number;
  maxInitialScore: number;
}

export interface LiveEnrichmentMeta {
  attempted: boolean;
  used: boolean;
  reason?: string;
  cacheHit?: boolean;
  fetchMs?: number;
}

export interface LiveEnrichmentResult {
  features: PageFeatures;
  meta: LiveEnrichmentMeta;
}

interface CacheEntry {
  expiresAt: number;
  features: PageFeatures;
}

const CACHE = new Map<string, CacheEntry>();

function parseNumber(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, parsed));
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "true" || normalized === "1" || normalized === "yes") {
    return true;
  }
  if (normalized === "false" || normalized === "0" || normalized === "no") {
    return false;
  }
  return fallback;
}

function getConfig(): LiveEnrichmentConfig {
  return {
    enabled: parseBoolean(process.env.LIVE_DOM_ENRICHMENT_ENABLED, true),
    timeoutMs: parseNumber(process.env.LIVE_DOM_ENRICHMENT_TIMEOUT_MS, 3500, 500, 12_000),
    cacheTtlMs: parseNumber(process.env.LIVE_DOM_ENRICHMENT_CACHE_TTL_MS, 3 * 60 * 1000, 20_000, 30 * 60 * 1000),
    maxCacheEntries: Math.floor(parseNumber(process.env.LIVE_DOM_ENRICHMENT_CACHE_MAX, 200, 20, 1000)),
    maxHtmlBytes: parseNumber(process.env.LIVE_DOM_ENRICHMENT_MAX_HTML_BYTES, 600_000, 50_000, 2_000_000),
    maxVisibleTextLength: parseNumber(process.env.LIVE_DOM_ENRICHMENT_MAX_TEXT_LENGTH, 6000, 800, 20_000),
    minInitialScore: parseNumber(process.env.LIVE_DOM_ENRICHMENT_MIN_SCORE, 18, 0, 90),
    maxInitialScore: parseNumber(process.env.LIVE_DOM_ENRICHMENT_MAX_SCORE, 82, 5, 100)
  };
}

function normalizeHostname(hostname: string): string {
  return String(hostname || "").trim().toLowerCase();
}

function normalizeUrl(url: string): URL {
  const parsed = new URL(url);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Live enrichment only allows http/https.");
  }
  parsed.hash = "";
  return parsed;
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  if (parts[0] === 10 || parts[0] === 127) {
    return true;
  }
  if (parts[0] === 169 && parts[1] === 254) {
    return true;
  }
  if (parts[0] === 192 && parts[1] === 168) {
    return true;
  }
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
    return true;
  }
  return false;
}

function isPrivateIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80:");
}

function isPrivateOrLocalAddress(value: string): boolean {
  const ipType = isIP(value);
  if (ipType === 4) {
    return isPrivateIpv4(value);
  }
  if (ipType === 6) {
    return isPrivateIpv6(value);
  }
  const host = normalizeHostname(value);
  return host === "localhost" || host.endsWith(".local") || host.endsWith(".internal");
}

async function assertPublicResolvableHostname(hostname: string): Promise<void> {
  const host = normalizeHostname(hostname);
  if (!host) {
    throw new Error("Hostname is empty.");
  }
  if (isPrivateOrLocalAddress(host)) {
    throw new Error("Blocked local/private hostname.");
  }

  const records = await lookup(host, { all: true, verbatim: true });
  if (!records.length) {
    throw new Error("No DNS records for hostname.");
  }

  for (const record of records) {
    if (isPrivateOrLocalAddress(record.address)) {
      throw new Error("Blocked local/private resolved address.");
    }
  }
}

function countOf(value: string, pattern: RegExp): number {
  return (String(value || "").match(pattern) || []).length;
}

function cleanText(value: string, maxLength: number): string {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function collectBrandSignals(text: string): string[] {
  const knownBrands = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "icloud",
    "line",
    "shopee",
    "momo",
    "pchome",
    "國泰",
    "玉山",
    "台新",
    "中國信託",
    "中信",
    "富邦",
    "永豐",
    "兆豐",
    "郵局",
    "黑貓",
    "新竹物流"
  ];
  const lower = text.toLowerCase();
  return knownBrands.filter((brand) => lower.includes(brand)).slice(0, 20);
}

function countSuspiciousTldsFromAnchors(anchors: DomElement[], pageUrl: string): number {
  const suspiciousTlds = new Set(["zip", "click", "top", "gq", "work", "country", "xyz", "cfd", "icu", "rest"]);
  let count = 0;
  for (const anchor of anchors) {
    const href = anchor.getAttribute("href") || "";
    if (!href) {
      continue;
    }
    try {
      const hostname = new URL(href, pageUrl).hostname.toLowerCase();
      const tld = hostname.split(".").pop();
      if (tld && suspiciousTlds.has(tld)) {
        count += 1;
      }
    } catch {
      continue;
    }
  }
  return count;
}

function countMismatchedAnchors(anchors: DomElement[], pageUrl: string): number {
  let count = 0;
  for (const anchor of anchors) {
    const text = (anchor.textContent || "").trim();
    const href = anchor.getAttribute("href") || "";
    if (!text || !href) {
      continue;
    }
    try {
      const hostname = new URL(href, pageUrl).hostname.toLowerCase();
      if (text.includes(".") && !text.toLowerCase().includes(hostname)) {
        count += 1;
      }
    } catch {
      continue;
    }
  }
  return count;
}

function collectAnchorHostnames(anchors: DomElement[], pageUrl: string, limit = 20): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const anchor of anchors) {
    const href = anchor.getAttribute("href") || "";
    if (!href) {
      continue;
    }
    try {
      const hostname = new URL(href, pageUrl).hostname.toLowerCase();
      if (!hostname || seen.has(hostname)) {
        continue;
      }
      seen.add(hostname);
      result.push(hostname);
      if (result.length >= limit) {
        break;
      }
    } catch {
      continue;
    }
  }
  return result;
}

function collectAnchorUrls(anchors: DomElement[], pageUrl: string, limit = 20): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const anchor of anchors) {
    const href = anchor.getAttribute("href") || "";
    if (!href) {
      continue;
    }
    try {
      const normalized = new URL(href, pageUrl).toString();
      if (!normalized || seen.has(normalized)) {
        continue;
      }
      seen.add(normalized);
      result.push(normalized);
      if (result.length >= limit) {
        break;
      }
    } catch {
      continue;
    }
  }
  return result;
}

function buildUrlSignals(url: string, hostname: string): NonNullable<PageFeatures["urlSignals"]> {
  const parsed = new URL(url);
  return {
    dotCount: countOf(hostname, /\./g),
    hyphenCount: countOf(hostname, /-/g),
    digitCount: countOf(hostname, /\d/g),
    length: url.length,
    hasIpHost: isIP(hostname) > 0,
    hasAtSymbol: url.includes("@"),
    hasPunycode: hostname.includes("xn--"),
    hasHexEncoding: /%[0-9a-f]{2}/i.test(url),
    hasSuspiciousPathKeyword: /(login|verify|account|secure|signin|auth|password|billing)/i.test(parsed.pathname),
    hasSuspiciousQueryKeyword: /(token|session|redirect|verify|login|password|auth)/i.test(parsed.search),
    hasLongHostname: hostname.length >= 35,
    hasManySubdomains: hostname.split(".").filter(Boolean).length >= 4,
    isShortenerHost: /^(bit\.ly|tinyurl\.com|t\.co|rb\.gy|reurl\.cc|ppt\.cc|lihi\.cc|cutt\.ly)$/i.test(hostname)
  };
}

function mergeFeatures(base: PageFeatures, html: string, config: LiveEnrichmentConfig): PageFeatures {
  const dom = new JSDOM(html);
  const { document } = dom.window;
  const anchors = Array.from(document.querySelectorAll("a[href]")) as DomElement[];
  const forms = Array.from(document.querySelectorAll("form")) as DomElement[];
  const passwordFields = document.querySelectorAll("input[type='password']").length;
  const externalSubmitCount = forms.filter((form) => {
    const action = form.getAttribute("action") || "";
    if (!action) {
      return false;
    }
    try {
      return new URL(action, base.url).hostname.toLowerCase() !== normalizeHostname(base.hostname);
    } catch {
      return false;
    }
  }).length;

  const bodyText = cleanText(document.body?.textContent || "", config.maxVisibleTextLength);
  const title = cleanText(document.title || base.title || "", 400);
  const hiddenElementCount = document.querySelectorAll("[hidden], [style*='display:none'], [style*='visibility:hidden']").length;
  const iframeCount = document.querySelectorAll("iframe").length;
  const hostnames = collectAnchorHostnames(anchors, base.url, 20);
  const urls = collectAnchorUrls(anchors, base.url, 20);
  const brandSignals = [...new Set([...base.brandSignals, ...collectBrandSignals(`${title} ${bodyText}`)])].slice(0, 24);
  const normalizedHostname = normalizeHostname(base.hostname);

  return {
    ...base,
    title: title || base.title,
    visibleText: bodyText || base.visibleText,
    forms: {
      total: forms.length,
      passwordFields,
      externalSubmitCount
    },
    links: {
      total: anchors.length,
      mismatchedTextCount: countMismatchedAnchors(anchors, base.url),
      suspiciousTldCount: countSuspiciousTldsFromAnchors(anchors, base.url),
      hostnames: hostnames.length > 0 ? hostnames : base.links.hostnames,
      urls: urls.length > 0 ? urls : base.links.urls
    },
    dom: {
      hiddenElementCount,
      iframeCount
    },
    brandSignals,
    urlSignals: {
      ...buildUrlSignals(base.url, normalizedHostname),
      ...(base.urlSignals || {})
    }
  };
}

function shouldAttemptEnrichment(features: PageFeatures, initialScore: number, config: LiveEnrichmentConfig): { ok: boolean; reason?: string } {
  if (!config.enabled) {
    return { ok: false, reason: "disabled_by_config" };
  }
  if (features.source !== "web") {
    return { ok: false, reason: "source_not_web" };
  }
  if (initialScore < config.minInitialScore || initialScore > config.maxInitialScore) {
    return { ok: false, reason: "outside_uncertain_score_band" };
  }

  const visibleTextLength = String(features.visibleText || "").trim().length;
  const hasSparseContent = visibleTextLength < 260 || features.links.total <= 1 || features.forms.total === 0;
  if (!hasSparseContent) {
    return { ok: false, reason: "already_has_content_signals" };
  }
  return { ok: true };
}

function trimCache(maxEntries: number): void {
  if (CACHE.size <= maxEntries) {
    return;
  }
  const keys = [...CACHE.keys()];
  const overflow = Math.max(0, CACHE.size - maxEntries);
  for (let index = 0; index < overflow; index += 1) {
    const key = keys[index];
    CACHE.delete(key);
  }
}

async function fetchHtml(url: string, timeoutMs: number, maxHtmlBytes: number): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"
      }
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const contentType = String(response.headers.get("content-type") || "").toLowerCase();
    if (!contentType.includes("text/html")) {
      throw new Error("non_html_response");
    }
    const html = await response.text();
    if (!html.trim()) {
      throw new Error("empty_html");
    }
    return html.slice(0, maxHtmlBytes);
  } catch (error) {
    if ((error as { name?: string }).name === "AbortError") {
      throw new Error(`timeout_${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export async function enrichPageFeaturesLive(features: PageFeatures, initialScore: number): Promise<LiveEnrichmentResult> {
  const config = getConfig();
  const gate = shouldAttemptEnrichment(features, initialScore, config);
  if (!gate.ok) {
    return {
      features,
      meta: {
        attempted: false,
        used: false,
        reason: gate.reason
      }
    };
  }

  let parsedUrl: URL;
  try {
    parsedUrl = normalizeUrl(features.url);
  } catch (error) {
    return {
      features,
      meta: {
        attempted: true,
        used: false,
        reason: error instanceof Error ? error.message : "invalid_url"
      }
    };
  }

  const cacheKey = parsedUrl.toString();
  const cacheEntry = CACHE.get(cacheKey);
  const now = Date.now();
  if (cacheEntry && cacheEntry.expiresAt > now) {
    return {
      features: cacheEntry.features,
      meta: {
        attempted: true,
        used: true,
        cacheHit: true
      }
    };
  }

  try {
    await assertPublicResolvableHostname(parsedUrl.hostname);
  } catch (error) {
    return {
      features,
      meta: {
        attempted: true,
        used: false,
        reason: `ssrf_guard:${error instanceof Error ? error.message : "blocked"}`
      }
    };
  }

  const start = Date.now();
  try {
    const html = await fetchHtml(cacheKey, config.timeoutMs, config.maxHtmlBytes);
    const enriched = mergeFeatures(features, html, config);
    CACHE.set(cacheKey, {
      expiresAt: now + config.cacheTtlMs,
      features: enriched
    });
    trimCache(config.maxCacheEntries);
    return {
      features: enriched,
      meta: {
        attempted: true,
        used: true,
        cacheHit: false,
        fetchMs: Date.now() - start
      }
    };
  } catch (error) {
    return {
      features,
      meta: {
        attempted: true,
        used: false,
        reason: error instanceof Error ? error.message : "fetch_error",
        fetchMs: Date.now() - start
      }
    };
  }
}

export const enrichFeaturesWithLiveDom = enrichPageFeaturesLive;
