export interface BrandDomainEntry {
  brand: string;
  aliases: string[];
  domains: string[];
}

export const TW_BRAND_DOMAINS: BrandDomainEntry[] = [
  { brand: "蝦皮", aliases: ["蝦皮", "shopee"], domains: ["shopee.tw", "shopeemobile.com"] },
  { brand: "momo", aliases: ["momo", "富邦momo"], domains: ["momoshop.com.tw"] },
  { brand: "PChome", aliases: ["pchome", "pc home"], domains: ["pchome.com.tw"] },
  { brand: "博客來", aliases: ["博客來", "books.com.tw"], domains: ["books.com.tw"] },
  { brand: "LINE", aliases: ["line", "line pay", "line bank"], domains: ["line.me", "linebiz.com", "linebank.com.tw"] },
  { brand: "中國信託", aliases: ["中國信託", "中信", "ctbc"], domains: ["ctbcbank.com", "ctbcbank.com.tw"] },
  { brand: "國泰", aliases: ["國泰", "cathay"], domains: ["cathaybk.com.tw", "cathaylife.com.tw", "cathay-ins.com.tw"] },
  { brand: "玉山", aliases: ["玉山", "esun"], domains: ["esunbank.com", "esunbank.com.tw"] },
  { brand: "台新", aliases: ["台新", "taishin"], domains: ["taishinbank.com.tw"] },
  { brand: "富邦", aliases: ["富邦", "fubon"], domains: ["fubon.com", "fubon.com.tw", "taipeifubon.com.tw"] },
  { brand: "永豐", aliases: ["永豐", "sinopac"], domains: ["sinopac.com", "sinopac.com.tw"] },
  { brand: "兆豐", aliases: ["兆豐", "mega bank", "megabank"], domains: ["megabank.com.tw"] },
  { brand: "郵局", aliases: ["郵局", "中華郵政", "post"], domains: ["post.gov.tw"] },
  { brand: "街口", aliases: ["街口", "jkopay"], domains: ["jkopay.com"] },
  { brand: "全支付", aliases: ["全支付", "px pay", "全聯支付"], domains: ["pxplus.com.tw"] },
  { brand: "7-11", aliases: ["7-11", "統一超商", "ibon"], domains: ["7-11.com.tw", "ibon.com.tw"] },
  { brand: "全家", aliases: ["全家", "familymart"], domains: ["family.com.tw"] },
  { brand: "黑貓", aliases: ["黑貓", "yamato", "黑貓宅急便"], domains: ["t-cat.com.tw"] },
  { brand: "新竹物流", aliases: ["新竹物流", "hct"], domains: ["hct.com.tw"] },
  { brand: "宅配通", aliases: ["宅配通", "pelican"], domains: ["e-can.com.tw"] }
];

function hostnameMatchesDomain(hostname: string, domain: string): boolean {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

export function findMismatchedBrands(hostname: string, brandSignals: string[]): BrandDomainEntry[] {
  const lowerSignals = brandSignals.map((signal) => signal.toLowerCase());

  return TW_BRAND_DOMAINS.filter((entry) => {
    const mentioned = entry.aliases.some((alias) => lowerSignals.includes(alias.toLowerCase()));
    if (!mentioned) {
      return false;
    }

    return !entry.domains.some((domain) => hostnameMatchesDomain(hostname.toLowerCase(), domain.toLowerCase()));
  });
}

export function findMismatchedBrandLinks(linkHostnames: string[], brandSignals: string[]): BrandDomainEntry[] {
  const lowerSignals = brandSignals.map((signal) => signal.toLowerCase());

  return TW_BRAND_DOMAINS.filter((entry) => {
    const mentioned = entry.aliases.some((alias) => lowerSignals.includes(alias.toLowerCase()));
    if (!mentioned) {
      return false;
    }

    const relevantLinks = linkHostnames.filter(Boolean);
    if (relevantLinks.length === 0) {
      return false;
    }

    const hasOfficialLink = relevantLinks.some((hostname) =>
      entry.domains.some((domain) => hostnameMatchesDomain(hostname.toLowerCase(), domain.toLowerCase()))
    );

    return !hasOfficialLink;
  });
}
