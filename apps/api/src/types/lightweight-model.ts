export interface LightweightModelFeatureWeights {
  bias: number;
  hasPasswordField: number;
  externalSubmitCount: number;
  mismatchedTextCount: number;
  suspiciousTldCount: number;
  hiddenElementCount: number;
  iframeCount: number;
  brandSignalCount: number;
  urlLengthNorm: number;
  dotCountNorm: number;
  hyphenCountNorm: number;
  digitCountNorm: number;
  hasIpHost: number;
  hasAtSymbol: number;
  hasPunycode: number;
  hasHexEncoding: number;
  hasSuspiciousPathKeyword: number;
  hasSuspiciousQueryKeyword: number;
  hasLongHostname: number;
  hasManySubdomains: number;
  isShortenerHost: number;
  liveDomEnriched: number;
  liveDomFetchError: number;
  highRiskPathHint: number;
  lowTextDensity: number;
  emailContext: number;
}

export interface LightweightModelVector {
  hasPasswordField: number;
  externalSubmitCount: number;
  mismatchedTextCount: number;
  suspiciousTldCount: number;
  hiddenElementCount: number;
  iframeCount: number;
  brandSignalCount: number;
  urlLengthNorm: number;
  dotCountNorm: number;
  hyphenCountNorm: number;
  digitCountNorm: number;
  hasIpHost: number;
  hasAtSymbol: number;
  hasPunycode: number;
  hasHexEncoding: number;
  hasSuspiciousPathKeyword: number;
  hasSuspiciousQueryKeyword: number;
  hasLongHostname: number;
  hasManySubdomains: number;
  isShortenerHost: number;
  liveDomEnriched: number;
  liveDomFetchError: number;
  highRiskPathHint: number;
  lowTextDensity: number;
  emailContext: number;
}

export interface LightweightModelProfile {
  version: string;
  generatedAt: string;
  samples: {
    total: number;
    phishing: number;
    safe: number;
  };
  priors: {
    phishing: number;
  };
  featureWeights: LightweightModelFeatureWeights;
  intercept: number;
}
