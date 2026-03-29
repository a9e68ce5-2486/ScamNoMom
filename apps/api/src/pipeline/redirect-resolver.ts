export const SHORTENER_HOSTS = new Set([
  "bit.ly",
  "reurl.cc",
  "tinyurl.com",
  "t.co",
  "rb.gy",
  "lihi.cc",
  "ppt.cc",
  "rebrand.ly",
  "shorturl.at",
  "cutt.ly"
]);

const REDIRECT_PARAM_KEYS = ["url", "u", "target", "dest", "destination", "redirect", "redir", "next", "continue", "to"];
const REQUEST_TIMEOUT_MS = 4500;

export interface RedirectResolution {
  originalUrl: string;
  finalUrl: string;
  hopCount: number;
  via: "query_param" | "http_redirect" | "none";
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

function isPrivateIpv4(hostname: string): boolean {
  const octets = hostname.split(".").map((part) => Number.parseInt(part, 10));
  if (octets.length !== 4 || octets.some((part) => Number.isNaN(part) || part < 0 || part > 255)) {
    return false;
  }

  if (octets[0] === 10) {
    return true;
  }

  if (octets[0] === 127) {
    return true;
  }

  if (octets[0] === 169 && octets[1] === 254) {
    return true;
  }

  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) {
    return true;
  }

  if (octets[0] === 192 && octets[1] === 168) {
    return true;
  }

  return false;
}

function isDisallowedHostname(hostname: string): boolean {
  const normalized = hostname.trim().toLowerCase();
  if (!normalized) {
    return true;
  }

  if (normalized === "localhost" || normalized.endsWith(".localhost") || normalized.endsWith(".local")) {
    return true;
  }

  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(normalized)) {
    return isPrivateIpv4(normalized);
  }

  const isIpv6Literal = normalized.includes(":");
  if (
    isIpv6Literal &&
    (
      normalized === "::1" ||
      normalized === "0:0:0:0:0:0:0:1" ||
      normalized.startsWith("fe80:") ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd")
    )
  ) {
    return true;
  }

  return false;
}

function sanitizeRedirectUrl(value: string): string | null {
  try {
    const parsed = new URL(value);
    if (!isHttpUrl(parsed.toString())) {
      return null;
    }

    if (parsed.username || parsed.password) {
      return null;
    }

    if (isDisallowedHostname(parsed.hostname)) {
      return null;
    }

    return parsed.toString();
  } catch {
    return null;
  }
}

function extractRedirectParam(url: URL): string | null {
  for (const key of REDIRECT_PARAM_KEYS) {
    const value = url.searchParams.get(key);
    if (value && isHttpUrl(value)) {
      const sanitized = sanitizeRedirectUrl(value);
      if (sanitized) {
        return sanitized;
      }
    }
  }

  return null;
}

async function requestOnce(url: string, method: "HEAD" | "GET"): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, {
      method,
      redirect: "manual",
      headers: {
        "User-Agent": "scamnomom/redirect-resolver"
      },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function resolveHttpRedirects(startUrl: string, maxHops = 4): Promise<RedirectResolution> {
  let currentUrl = sanitizeRedirectUrl(startUrl) || startUrl;
  let hopCount = 0;

  for (let i = 0; i < maxHops; i += 1) {
    const safeCurrentUrl = sanitizeRedirectUrl(currentUrl);
    if (!safeCurrentUrl) {
      break;
    }

    const response = await requestOnce(safeCurrentUrl, "HEAD").catch(() => requestOnce(safeCurrentUrl, "GET"));
    const location = response.headers.get("location");

    if (!location || response.status < 300 || response.status >= 400) {
      break;
    }

    const nextCandidate = new URL(location, safeCurrentUrl).toString();
    const safeNextUrl = sanitizeRedirectUrl(nextCandidate);
    if (!safeNextUrl) {
      break;
    }

    currentUrl = safeNextUrl;
    hopCount += 1;
  }

  return {
    originalUrl: startUrl,
    finalUrl: currentUrl,
    hopCount,
    via: hopCount > 0 ? "http_redirect" : "none"
  };
}

export async function resolveRedirectChain(inputUrl: string): Promise<RedirectResolution> {
  try {
    const sanitizedInput = sanitizeRedirectUrl(inputUrl);
    if (!sanitizedInput) {
      return {
        originalUrl: inputUrl,
        finalUrl: inputUrl,
        hopCount: 0,
        via: "none"
      };
    }

    const parsed = new URL(sanitizedInput);
    const redirectParam = extractRedirectParam(parsed);

    if (redirectParam) {
      return {
        originalUrl: sanitizedInput,
        finalUrl: redirectParam,
        hopCount: 1,
        via: "query_param"
      };
    }

    if (SHORTENER_HOSTS.has(parsed.hostname.toLowerCase())) {
      return await resolveHttpRedirects(sanitizedInput);
    }

    return {
      originalUrl: sanitizedInput,
      finalUrl: sanitizedInput,
      hopCount: 0,
      via: "none"
    };
  } catch {
    return {
      originalUrl: inputUrl,
      finalUrl: inputUrl,
      hopCount: 0,
      via: "none"
    };
  }
}
