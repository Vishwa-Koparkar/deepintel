(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.DeepIntelFeatures = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
  "use strict";

  const FEATURES = [
    "url_length", "path_length", "num_subdomains", "num_digits",
    "num_hyphens_domain", "is_https", "is_domain_ip", "has_shortener",
    "has_suspicious_keywords", "is_brand_impersonation", "has_at_symbol",
    "has_double_slash", "has_encoded_chars", "num_query_params",
    "domain_entropy", "tld_category", "is_safe_country_tld", "domain_word_len",
    "has_safe_extension", "digit_ratio"
  ];

  // Runtime metadata supplies set iteration order from the Python model build.
  const DEFAULT_CONFIG = {
    brands: ["paypal", "apple", "microsoft", "amazon", "netflix", "ebay", "google", "facebook", "instagram", "twitter", "linkedin", "dropbox", "adobe", "chase", "bankofamerica", "wellsfargo", "dhl", "fedex", "ups"],
    suspiciousKeywords: ["login", "signin", "verify", "secure", "account", "update", "confirm", "banking", "password", "credential", "suspend", "alert", "urgent", "free", "winner", "click", "download", "invoice", "paypal", "apple", "microsoft", "amazon", "netflix", "ebay", "support"],
    shorteners: ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "short.link", "rebrand.ly", "cutt.ly"],
    suspiciousTlds: [".xyz", ".top", ".club", ".online", ".site", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".zip", ".review", ".country", ".stream", ".download", ".racing", ".win", ".bid"],
    safeTlds: [".com", ".org", ".edu", ".gov", ".net", ".io", ".co"],
    safeCountryTlds: [".co.uk", ".gov.uk", ".ac.uk", ".org.uk", ".com.au", ".gov.au", ".edu.au", ".co.jp", ".go.jp", ".com.br", ".gov.br", ".co.in", ".gov.in", ".ac.in", ".fr", ".de", ".it", ".es", ".nl", ".se", ".no", ".dk", ".fi", ".ca", ".mx", ".ar", ".cl", ".gov", ".mil", ".edu"],
    safeExtensions: [".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".pdf", ".png", ".jpg", ".gif", ".css", ".js"]
  };

  const SUPERSCRIPT_DIGITS = new Set(["\u00b2", "\u00b3", "\u00b9", "\u2070", "\u2074", "\u2075", "\u2076", "\u2077", "\u2078", "\u2079"]);

  function codePointLength(value) {
    return Array.from(value).length;
  }

  function splitOnce(value, separator) {
    const index = value.indexOf(separator);
    return index < 0 ? [value, ""] : [value.slice(0, index), value.slice(index + separator.length)];
  }

  // Preserve the URL text the same way urllib.parse.urlparse does for HTTP URLs.
  function parseUrl(value) {
    if (typeof value !== "string") return null;
    const source = value;
    const schemeMatch = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(source);
    const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : "";
    let rest = schemeMatch ? source.slice(schemeMatch[0].length) : source;

    const [beforeFragment, fragment] = splitOnce(rest, "#");
    const [beforeQuery, query] = splitOnce(beforeFragment, "?");
    let netloc = "";
    let path = beforeQuery;
    if (beforeQuery.startsWith("//")) {
      const authorityAndPath = beforeQuery.slice(2);
      const slash = authorityAndPath.indexOf("/");
      netloc = slash < 0 ? authorityAndPath : authorityAndPath.slice(0, slash);
      path = slash < 0 ? "" : authorityAndPath.slice(slash);
      if (!isBracketStructureValid(netloc)) return null;
    }

    let params = "";
    const lastSlash = path.lastIndexOf("/");
    const semicolon = path.indexOf(";", lastSlash + 1);
    if (semicolon >= 0) {
      params = path.slice(semicolon + 1);
      path = path.slice(0, semicolon);
    }
    return { scheme, netloc, path, params, query, fragment };
  }

  function isBracketStructureValid(netloc) {
    const opens = (netloc.match(/\[/g) || []).length;
    const closes = (netloc.match(/\]/g) || []).length;
    if (opens !== closes || opens > 1) return false;
    if (opens === 1 && netloc.indexOf("]") < netloc.indexOf("[")) return false;
    return true;
  }

  function normalizeForAnalysis(value) {
    const url = typeof value === "string" ? value.trim() : "";
    try {
      const parsed = parseUrl(url);
      if (parsed && parsed.path === "/" && !parsed.params && !parsed.query && !parsed.fragment && url.endsWith("/")) {
        return url.slice(0, -1);
      }
    } catch (_) {
      // analyzer.normalize_for_analysis leaves a URL unchanged when urlparse rejects it.
    }
    return url;
  }

  function pythonIsDigit(character) {
    return /\p{Nd}/u.test(character) || SUPERSCRIPT_DIGITS.has(character);
  }

  function pythonIsWordCharacter(character) {
    return /[\p{L}\p{N}_]/u.test(character);
  }

  function round4(value) {
    const scaled = value * 10000;
    const lower = Math.floor(scaled);
    const fraction = scaled - lower;
    if (fraction === 0.5) return (lower % 2 === 0 ? lower : lower + 1) / 10000;
    return Math.round(scaled) / 10000;
  }

  function entropy(value) {
    if (!value) return 0;
    const counts = new Map();
    for (const character of value) counts.set(character, (counts.get(character) || 0) + 1);
    const length = codePointLength(value);
    let result = 0;
    for (const count of counts.values()) {
      const probability = count / length;
      result -= probability * Math.log2(probability);
    }
    return result;
  }

  function zeroFeatures() {
    return Object.fromEntries(FEATURES.map(name => [name, 0]));
  }

  function extractFeatures(url, featureConfig = DEFAULT_CONFIG) {
    try {
      if (typeof url !== "string") return zeroFeatures();
      const parsed = parseUrl(url);
      if (!parsed) return zeroFeatures();
      const config = { ...DEFAULT_CONFIG, ...(featureConfig || {}) };
      const domain = parsed.netloc.toLowerCase().split(":")[0];
      const path = parsed.path.toLowerCase();
      const query = parsed.query.toLowerCase();
      const full = url.toLowerCase();
      const parts = domain.split(".");
      const tld = parts.length > 1 ? `.${parts[parts.length - 1]}` : "";
      const tld2 = parts.length > 2 ? `.${parts.slice(-2).join(".")}` : tld;
      const folded = domain.replaceAll("rn", "m").replaceAll("vv", "w").replace(/[0135$]/g, character => ({ "0": "o", "1": "l", "3": "e", "5": "s", "$": "s" })[character]);
      const brand = config.brands.find(candidate => folded.includes(candidate));
      const isRealBrandDomain = brand
        ? new RegExp(`(^|\\.)${brand}\\.((com|org|net)|[a-z]{2}|(co|com|org|gov|ac)\\.[a-z]{2})$`).test(domain)
        : false;
      const domainClean = domain
        .replace(/\.(com|org|net|edu|gov|co|uk|jp|fr|de|au|br|in|ca|mx)$/, "")
        .replace(/./gu, character => pythonIsWordCharacter(character) ? character : "");
      const extension = path.includes(".") ? `.${path.split(".").at(-1)}` : "";
      const digitsInDomain = Array.from(domain).filter(pythonIsDigit).length;

      return {
        url_length: codePointLength(url),
        path_length: codePointLength(path),
        num_subdomains: Math.max(0, parts.length - 2),
        num_digits: Array.from(full).filter(pythonIsDigit).length,
        num_hyphens_domain: domain.split("-").length - 1,
        is_https: Number(parsed.scheme === "https"),
        is_domain_ip: Number(/^[\p{Nd}]{1,3}\.[\p{Nd}]{1,3}\.[\p{Nd}]{1,3}\.[\p{Nd}]{1,3}$/u.test(domain)),
        has_shortener: Number(config.shorteners.includes(domain)),
        has_suspicious_keywords: Number(config.suspiciousKeywords.some(keyword => full.includes(keyword))),
        is_brand_impersonation: Number(Boolean(brand) && !isRealBrandDomain),
        has_at_symbol: Number(url.includes("@")),
        has_double_slash: Number(path.includes("//")),
        has_encoded_chars: Number(url.includes("%")),
        num_query_params: query ? query.split("&").length : 0,
        domain_entropy: round4(entropy(domain)),
        tld_category: config.safeTlds.includes(tld) ? 0 : (config.suspiciousTlds.includes(tld) ? 2 : 1),
        is_safe_country_tld: Number(config.safeCountryTlds.includes(tld2) || config.safeCountryTlds.includes(tld)),
        domain_word_len: codePointLength(domainClean),
        has_safe_extension: Number(config.safeExtensions.includes(extension)),
        digit_ratio: round4(digitsInDomain / Math.max(codePointLength(domain), 1))
      };
    } catch (_) {
      return zeroFeatures();
    }
  }

  return { FEATURES, DEFAULT_CONFIG, codePointLength, parseUrl, normalizeForAnalysis, extractFeatures, zeroFeatures };
});
