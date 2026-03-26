const SHORTENER_HOSTS = new Set([
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

export interface RedirectResolution {
  originalUrl: string;
  finalUrl: string;
  hopCount: number;
  via: "query_param" | "http_redirect" | "none";
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

function extractRedirectParam(url: URL): string | null {
  for (const key of REDIRECT_PARAM_KEYS) {
    const value = url.searchParams.get(key);
    if (value && isHttpUrl(value)) {
      return value;
    }
  }

  return null;
}

async function requestOnce(url: string, method: "HEAD" | "GET"): Promise<Response> {
  return fetch(url, {
    method,
    redirect: "manual",
    headers: {
      "User-Agent": "scamnomom/redirect-resolver"
    }
  });
}

async function resolveHttpRedirects(startUrl: string, maxHops = 4): Promise<RedirectResolution> {
  let currentUrl = startUrl;
  let hopCount = 0;

  for (let i = 0; i < maxHops; i += 1) {
    const response = await requestOnce(currentUrl, "HEAD").catch(() => requestOnce(currentUrl, "GET"));
    const location = response.headers.get("location");

    if (!location || response.status < 300 || response.status >= 400) {
      break;
    }

    currentUrl = new URL(location, currentUrl).toString();
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
    const parsed = new URL(inputUrl);
    const redirectParam = extractRedirectParam(parsed);

    if (redirectParam) {
      return {
        originalUrl: inputUrl,
        finalUrl: redirectParam,
        hopCount: 1,
        via: "query_param"
      };
    }

    if (SHORTENER_HOSTS.has(parsed.hostname.toLowerCase())) {
      return await resolveHttpRedirects(inputUrl);
    }

    return {
      originalUrl: inputUrl,
      finalUrl: inputUrl,
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
