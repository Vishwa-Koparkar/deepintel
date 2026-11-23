(function (root, factory) {
  const api = factory(root.DeepIntelFeatures);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.DeepIntelBrowserEngine = api;
})(typeof globalThis === "object" ? globalThis : this, function (URLFeatures) {
  "use strict";

  const W_ML = 0.70, W_HEURISTIC = 0.15, W_THREAT = 0.15;
  const MAX_HEURISTIC_SCORE = 1.06;
  const LOOKALIKE_SCORE = { confusable: 0.80, typo: 0.65, subdomain: 0.65 };
  const BRAND_SUBDOMAIN_OK = new Set(["github.io", "gitlab.io", "readthedocs.io", "stackexchange.com"]);
  const IMPACT_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, None: 4 };
  const DECIDER_LABEL = {
    feedback: "Your correction", blocklist: "Threat-intel blocklist", allowlist: "Trusted-domain allowlist",
    lookalike: "Lookalike check", fusion: "Combined risk score", ml: "ML model"
  };
  const RULES = [
    ["is_ip_address", 0.15, "Domain is a raw IP address"],
    ["is_http_not_https", 0.08, "URL uses HTTP instead of HTTPS"],
    ["has_brand_impersonation", 0.15, "Domain mimics a known brand"],
    ["has_suspicious_keywords", 0.08, "URL contains phishing-related keywords"],
    ["has_at_symbol", 0.10, "URL contains @ symbol (redirects real domain)"],
    ["has_double_slash", 0.08, "Path contains // redirect pattern"],
    ["has_encoded_chars", 0.05, "URL contains encoded characters"],
    ["excessive_subdomains", 0.08, "Domain has 3+ subdomains"],
    ["long_url", 0.05, "URL is unusually long (>75 chars)"],
    ["high_domain_entropy", 0.08, "Domain name looks randomly generated"],
    ["suspicious_tld", 0.08, "TLD is commonly abused"],
    ["has_shortener", 0.08, "Uses a URL shortening service"]
  ];
  const RULE_REASONS = {
    has_brand_impersonation: [1, "High", "Domain impersonates a known brand"],
    is_ip_address: [1, "High", "Domain is a raw IP address, not a real website name"],
    has_at_symbol: [1, "High", "URL contains @ symbol which can redirect to a different site"],
    has_double_slash: [1, "High", "URL contains // redirect pattern in the path"],
    has_shortener: [1, "Medium", "URL uses a shortener service hiding the real destination"],
    high_domain_entropy: [2, "Medium", "Domain name appears randomly generated"],
    excessive_subdomains: [2, "Medium", "Unusually high number of subdomains"],
    suspicious_tld: [2, "Medium", "Domain uses a TLD commonly associated with malicious sites"],
    long_url: [2, "Low", "URL is abnormally long"],
    has_suspicious_keywords: [2, "High", "URL contains keywords commonly used in phishing attacks"],
    is_http_not_https: [3, "Medium", "Website does not use secure HTTPS connection"],
    has_encoded_chars: [3, "Low", "URL contains encoded characters used to obfuscate content"]
  };
  const ML_REASONS = {
    phishing: [3, "Medium", "The overall shape of this URL closely matches known phishing sites"],
    malware: [3, "Medium", "The overall shape of this URL closely matches known malware download links"],
    benign: [3, "None", "No suspicious signals found in the URL"]
  };
  const INTENT_MAP = {
    login: "Please visit the official website directly and log in from there.",
    signin: "Please visit the official website directly and sign in from there.",
    banking: "Please visit your bank's official website directly.",
    download: "Please download software only from the official vendor website.",
    invoice: "Please verify invoices directly on the sender's official website.",
    verify: "Please verify your account on the official website directly.",
    confirm: "Please confirm your details on the official website directly."
  };
  const TRUSTED_DOMAINS = {
    paypal: "https://www.paypal.com", apple: "https://www.apple.com", microsoft: "https://www.microsoft.com",
    amazon: "https://www.amazon.com", netflix: "https://www.netflix.com", ebay: "https://www.ebay.com",
    google: "https://www.google.com", facebook: "https://www.facebook.com", instagram: "https://www.instagram.com",
    twitter: "https://www.twitter.com", linkedin: "https://www.linkedin.com", dropbox: "https://www.dropbox.com",
    adobe: "https://www.adobe.com", chase: "https://www.chase.com", bankofamerica: "https://www.bankofamerica.com",
    wellsfargo: "https://www.wellsfargo.com", dhl: "https://www.dhl.com", fedex: "https://www.fedex.com", ups: "https://www.ups.com"
  };

  let metadata = null;
  let engineData = null;
  let session = null;
  let featureConfig = null;
  let origin = null;

  function round4(value) {
    const scaled = value * 10000;
    const lower = Math.floor(scaled), fraction = scaled - lower;
    // ONNX and sklearn probabilities can differ by <1e-6; treat that near-tie
    // as Python's ties-to-even rounding instead of letting it flip one digit.
    const tied = Math.abs(fraction - 0.5) < 0.005;
    return (tied ? (lower % 2 === 0 ? lower : lower + 1) : Math.round(scaled)) / 10000;
  }
  function percent0(value) {
    const scaled = value * 100, lower = Math.floor(scaled), fraction = scaled - lower;
    const tied = Math.abs(fraction - 0.5) < 0.0001;
    return tied ? (lower % 2 === 0 ? lower : lower + 1) : Math.round(scaled);
  }

  function parse(url) {
    const parsed = URLFeatures.parseUrl(url);
    if (!parsed) throw new Error("Could not parse URL.");
    return parsed;
  }

  function domainOf(url) { return parse(url).netloc.toLowerCase().split(":")[0]; }
  function baseDomain(host) {
    const parts = host.toLowerCase().split(":")[0].split(".");
    const twoLevel = new Set(["co", "com", "org", "net", "gov", "edu", "ac", "go", "or", "ne"]);
    if (parts.length >= 3 && parts[parts.length - 1].length === 2 && twoLevel.has(parts[parts.length - 2])) return parts.slice(-3).join(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : host;
  }
  function entropy(value) {
    if (!value) return 0;
    const counts = new Map();
    for (const char of value) counts.set(char, (counts.get(char) || 0) + 1);
    const length = URLFeatures.codePointLength(value);
    let score = 0;
    for (const count of counts.values()) { const p = count / length; score -= p * Math.log2(p); }
    return score;
  }
  function isDigit(char) { return /\p{Nd}/u.test(char) || /[²³¹⁰⁴⁵⁶⁷⁸⁹]/u.test(char); }
  function isLetter(char) { return /\p{L}/u.test(char); }
  function isAlpha(char) { return isLetter(char); }
  function foldBrand(value) {
    return value.replaceAll("rn", "m").replaceAll("vv", "w").replace(/[0135$]/g, ch => ({ "0": "o", "1": "l", "3": "e", "5": "s", "$": "s" })[ch]);
  }
  function isRealBrandDomain(domain, brand) {
    return new RegExp(`(^|\\.)${brand}\\.((com|org|net)|[a-z]{2}|(co|com|org|gov|ac)\\.[a-z]{2})$`).test(domain);
  }
  function isIp(domain) { return /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(domain); }
  function riskLevel(score) {
    if (score < 0.20) return "safe";
    if (score < 0.40) return "low";
    if (score < 0.60) return "medium";
    if (score < 0.80) return "high";
    return "critical";
  }

  function heuristic(url, config) {
    let parsed, domain, path, full, parts, tld;
    try {
      parsed = parse(url);
      domain = parsed.netloc.toLowerCase().split(":")[0];
      path = parsed.path.toLowerCase();
      full = url.toLowerCase();
      parts = domain.split(".");
      tld = parts.length > 1 ? `.${parts.at(-1)}` : "";
    } catch (_) {
      return { score: 1, triggered: [["parse_error", 1, "Could not parse URL"]] };
    }
    const folded = foldBrand(domain);
    const brand = config.brands.find(item => folded.includes(item));
    const tests = {
      is_ip_address: isIp(domain),
      is_http_not_https: parsed.scheme === "http",
      has_brand_impersonation: Boolean(brand) && !isRealBrandDomain(domain, brand),
      has_suspicious_keywords: config.suspiciousKeywords.some(keyword => full.includes(keyword)),
      has_at_symbol: url.includes("@"),
      has_double_slash: path.includes("//"),
      has_encoded_chars: url.includes("%"),
      excessive_subdomains: parts.length - 2 >= 3,
      long_url: URLFeatures.codePointLength(url) > 75,
      high_domain_entropy: entropy(domain) > 3.5,
      suspicious_tld: config.suspiciousTlds.includes(tld),
      has_shortener: config.shorteners.includes(domain)
    };
    const triggered = RULES.filter(([name]) => tests[name]);
    const raw = triggered.reduce((total, row) => total + row[1], 0);
    return { score: round4(Math.min(raw / MAX_HEURISTIC_SCORE, 1)), triggered };
  }

  function threatLookup(url) {
    let domain;
    try { domain = domainOf(url); } catch (_) { return { score: 1, flag: true, matched: ["parse_error"] }; }
    const matched = [];
    for (const [name, values] of Object.entries(engineData.blocklists)) {
      const entries = new Set(values);
      if (entries.has(domain)) { matched.push(name); continue; }
      const parts = domain.split(".");
      for (let i = 1; i < parts.length; i++) {
        if (entries.has(parts.slice(i).join("."))) { matched.push(`${name}(subdomain)`); break; }
      }
    }
    if (!matched.length) return { score: 0, flag: false, matched };
    return { score: round4(Math.min(0.5 + (matched.length - 1) * 0.25, 1)), flag: true, matched };
  }

  function isTrustedHost(host) {
    const base = baseDomain(host);
    return engineData.trusted.clean.includes(base) || engineData.trusted.apex.includes(host);
  }
  function hasThreatHistory(host) { return engineData.trusted.threat.includes(baseDomain(host)); }
  function loadPlatforms() { return engineData.platforms; }

  function lookalikeFold(value) {
    return value.toLowerCase().replaceAll("rn", "m").replaceAll("vv", "w").replaceAll("cl", "d")
      .replace(/[01i35$|]/g, ch => ({ "0": "o", "1": "l", i: "l", "3": "e", "5": "s", "$": "s", "|": "l" })[ch]);
  }
  function editDistanceLe1(a, b) {
    if (a === b || Math.abs(a.length - b.length) > 1) return false;
    if (a.length === b.length) {
      const diff = [];
      for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) diff.push(i);
      return diff.length === 1 || (diff.length === 2 && diff[1] === diff[0] + 1 && a[diff[0]] === b[diff[1]] && a[diff[1]] === b[diff[0]]);
    }
    if (a.length > b.length) [a, b] = [b, a];
    let i = 0;
    while (i < a.length && a[i] === b[i]) i++;
    return a.slice(i) === b.slice(i + 1);
  }
  function splitDomain(domain) { const [sld, ...rest] = domain.split("."); return [sld, rest.join(".")]; }
  function isCountryTld(tld) {
    const parts = tld.split(".");
    return parts.length > 0 && parts.at(-1).length === 2 && /^[a-z]{2}$/i.test(parts.at(-1));
  }
  function findLookalike(registeredDomain) {
    const d = registeredDomain.toLowerCase();
    const targets = engineData.lookalikeTargets;
    if (targets.includes(d)) return null;
    const [sld, tld] = splitDomain(d);
    const folded = engineData.foldedLookalikes[lookalikeFold(d)];
    if (folded && folded !== d) return [folded, "confusable"];
    for (const target of targets) {
      const [targetSld, targetTld] = splitDomain(target);
      if (sld === targetSld) {
        if (tld !== targetTld && !isCountryTld(tld)) return [target, "typo"];
        continue;
      }
      if (sld.length >= 6 && targetSld.length >= 6 && editDistanceLe1(sld, targetSld) && (tld === targetTld || !isCountryTld(tld))) return [target, "typo"];
    }
    return null;
  }
  function describeLookalike(domain, target, kind) {
    const [domainSld, domainTld] = splitDomain(domain.toLowerCase());
    const [targetSld, targetTld] = splitDomain(target.toLowerCase());
    if (kind === "confusable") {
      const substitutions = [["rn", "m"], ["vv", "w"], ["cl", "d"], ["0", "o"], ["1", "l"], ["i", "l"], ["3", "e"], ["5", "s"], ["$", "s"], ["|", "l"]];
      const found = substitutions.filter(([a, b]) => domainSld.includes(a) && !targetSld.includes(a) && targetSld.includes(b)).map(([a, b]) => `'${a}' looks like '${b}'`);
      return `${domain} imitates ${target}: ${[...new Set(found)].join("; ") || "it reads the same as the real name once look-alike characters are swapped"}`;
    }
    if (kind === "subdomain") return `'${targetSld}' appears in the subdomain of ${domain}, which is not ${target}`;
    if (domainSld === targetSld) return `${domain} is ${target} with a different ending (.${domainTld} instead of .${targetTld})`;
    return `${domain} is one character away from ${target} (a missing, extra, swapped or wrong letter)`;
  }
  function brandInSubdomain(host, config) {
    const base = baseDomain(host);
    if (BRAND_SUBDOMAIN_OK.has(base) || !host.endsWith(base)) return null;
    const sub = host.slice(0, -base.length).replace(/\.+$/, "");
    if (!sub) return null;
    const tokens = new Set(foldBrand(sub).split(/[.\-_]/));
    for (const brand of [...config.brands].sort()) {
      if (tokens.has(brand) && !isRealBrandDomain(base, brand)) return brand;
    }
    return null;
  }

  function trace({ finalLabel, decider, threat, matchedLists, trusted, host, lookalike, lookalikeDetail,
    weakBenignOverride, fused, mlLabel, mlConfidence, heuristicScore, triggeredRules }) {
    const threatVerdict = finalLabel !== "benign";
    const stance = pointsToThreat => pointsToThreat === threatVerdict ? "agrees" : "overruled";
    const steps = [{ id: "feedback", title: "Your correction", status: "no_signal", detail: "No correction saved for this URL, site or domain." }];
    if (threat.flag) steps.push({ id: "blocklist", title: "Threat-intel blocklist", status: decider === "blocklist" ? "decided" : "agrees", detail: `Domain found on: ${matchedLists.join(", ")}.` });
    else steps.push({ id: "blocklist", title: "Threat-intel blocklist", status: "no_signal", detail: "Not on the URLhaus or OpenPhish blocklists." });
    if (trusted) steps.push({ id: "allowlist", title: "Trusted-domain allowlist", status: decider === "allowlist" ? "decided" : "agrees", detail: `${baseDomain(host)} is a top-ranked site with no threat history.` });
    else steps.push({ id: "allowlist", title: "Trusted-domain allowlist", status: "no_signal", detail: "Domain is not on the trusted list, or its trust was revoked." });
    if (lookalike) steps.push({ id: "lookalike", title: "Lookalike check", status: decider === "lookalike" ? "decided" : "agrees", detail: `${lookalikeDetail}.` });
    else steps.push({ id: "lookalike", title: "Lookalike check", status: "no_signal", detail: "Does not imitate a well-known brand or site." });
    if (triggeredRules.length) {
      const names = triggeredRules.slice(0, 3).map(rule => rule[2].toLowerCase()).join(", ") + (triggeredRules.length > 3 ? ` and ${triggeredRules.length - 3} more` : "");
      steps.push({ id: "heuristic", title: "Heuristic rules", status: stance(heuristicScore >= 0.2), detail: `Score ${heuristicScore.toFixed(2)}: ${names}.` });
    } else steps.push({ id: "heuristic", title: "Heuristic rules", status: "no_signal", detail: "No rule fired." });
    steps.push({ id: "ml", title: "ML model", status: decider === "ml" ? "decided" : stance(mlLabel !== "benign"), detail: `Predicted ${mlLabel} (${percent0(mlConfidence)}%) from the URL's structure.` });
    if (weakBenignOverride) steps.push({ id: "fusion", title: "Combined risk score", status: "decided", detail: `The model leaned benign, but the combined risk of ${fused.toFixed(2)} is high enough to reclassify it.` });
    return steps;
  }

  function specificReason(ruleName, url, config) {
    const host = domainOf(url), full = url.toLowerCase();
    if (ruleName === "has_suspicious_keywords") {
      const brands = new Set(config.brands);
      const words = config.suspiciousKeywords.filter(word => !brands.has(word)).sort().filter(word => full.includes(word));
      if (words.length) return `URL contains words used to bait victims: ${words.slice(0, 4).join(", ")}`;
    } else if (ruleName === "suspicious_tld") {
      return `Uses the .${host.split(".").at(-1)} ending, which is heavily abused for phishing and malware`;
    } else if (ruleName === "high_domain_entropy") {
      const base = baseDomain(host);
      const skip = Object.hasOwn(loadPlatforms(), base) ? new Set([base.split(".")[0]]) : new Set();
      for (const label of host.split(".").slice(0, -1).filter(item => !skip.has(item) && URLFeatures.codePointLength(item) >= 6)) {
        const letters = Array.from(label).filter(isAlpha);
        const digits = Array.from(label).filter(isDigit).length;
        const vowelRatio = letters.filter(char => "aeiou".includes(char)).length / Math.max(letters.length, 1);
        if ((digits >= 2 && letters.length >= 3) || (letters.length && vowelRatio < 0.3 && !label.includes("-"))) return `The name "${label}" looks randomly generated`;
      }
      return false;
    } else if (ruleName === "has_brand_impersonation") {
      const brand = [...config.brands].sort().find(item => foldBrand(host).includes(item));
      if (brand) return `Uses the brand name "${brand}" but is not ${brand}'s real website`;
    } else if (ruleName === "excessive_subdomains") {
      return `${host.split(".").length - 2} subdomains are stacked in front of the real domain, which can hide where the link goes`;
    } else if (ruleName === "long_url") {
      return `The URL is unusually long (${URLFeatures.codePointLength(url)} characters), which can bury the real domain`;
    } else if (ruleName === "is_http_not_https") {
      return "The address starts with http://, so the connection is not encrypted";
    }
    return null;
  }
  function extraFacts(url) {
    const host = domainOf(url), base = baseDomain(host), out = [];
    const platforms = loadPlatforms();
    if (Object.hasOwn(platforms, base) && host !== base && host !== `www.${base}`) out.push([2, "Medium", `Hosted on ${base}, a free hosting service where ${platforms[base]} phishing or malware sites were found in our data`]);
    const hyphens = host.split("-").length - 1;
    if (hyphens >= 2) out.push([2, "Medium", `The domain has ${hyphens} hyphens, a common trick to imitate a brand name`]);
    const digits = Array.from(host).filter(isDigit).length;
    if (host && digits / URLFeatures.codePointLength(host) >= 0.25 && !/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(host)) out.push([2, "Medium", "The domain is full of digits, typical of auto-generated names"]);
    return out;
  }
  function reasons(result, config) {
    const out = [];
    if (result.threat.flag) out.push({ priority: 1, impact: "Critical", reason: `Domain found in known threat intelligence blocklist (${result.threat.matched.join(", ")})`, source: "threat_intel" });
    const la = result.lookalike;
    if (la) out.push({ priority: 1, impact: la.kind === "confusable" ? "Critical" : "High", reason: la.detail, source: "lookalike" });
    if (result.trusted) out.push({ priority: 3, impact: "None", reason: "Domain is a well-known, highly ranked website with no threat history", source: "allowlist" });
    const ml = result.mlLabel;
    if (ml !== "benign" && !result.trusted) {
      const [priority, impact, reason] = ML_REASONS[ml];
      out.push({ priority, impact, reason, source: "ml" });
    }
    for (const [name] of result.heuristic.triggered) {
      const configReason = RULE_REASONS[name];
      if (!configReason) continue;
      const [priority, impact, fallback] = configReason;
      const detail = specificReason(name, result.url, config);
      if (detail === false) continue;
      out.push({ priority, impact, reason: detail || fallback, source: "heuristic" });
    }
    if (result.prediction !== "benign") for (const [priority, impact, reason] of extraFacts(result.url)) out.push({ priority, impact, reason, source: "heuristic" });
    let visible = result.prediction === "benign" ? out.filter(item => ["allowlist", "ml"].includes(item.source)) : out;
    if (result.prediction === "benign" && !visible.length) visible = [{ priority: 3, impact: "None", reason: "No suspicious signals found in the URL", source: "ml" }];
    visible.sort((a, b) => a.priority - b.priority || (IMPACT_ORDER[a.impact] ?? 5) - (IMPACT_ORDER[b.impact] ?? 5));
    const seen = new Set();
    return visible.filter(item => !seen.has(item.reason) && seen.add(item.reason)).slice(0, 5);
  }
  function suggestion(url, risk) {
    if (["safe", "low"].includes(risk)) return null;
    let parsed;
    try { parsed = parse(url); } catch (_) { return null; }
    const domain = parsed.netloc.toLowerCase().split(":")[0];
    const full = url.toLowerCase(), path = parsed.path.toLowerCase();
    const brand = Object.keys(TRUSTED_DOMAINS).find(item => domain.includes(item) || path.includes(item));
    if (brand) {
      const safeUrl = TRUSTED_DOMAINS[brand];
      const safeDomain = parse(safeUrl).netloc.toLowerCase();
      if (domain === safeDomain || domain === `www.${safeDomain}`) return null;
      return { type: "brand", brand, safe_url: safeUrl, message: `This URL appears to impersonate ${brand[0].toUpperCase()}${brand.slice(1)}. Visit the official website instead.` };
    }
    const intent = Object.keys(INTENT_MAP).find(keyword => full.includes(keyword));
    return intent ? { type: "intent", intent, safe_url: null, message: INTENT_MAP[intent] } : null;
  }

  function resultFor(url, probabilities) {
    const classes = metadata.classes;
    let predictedIndex = 0;
    for (let i = 1; i < probabilities.length; i++) if (probabilities[i] > probabilities[predictedIndex]) predictedIndex = i;
    const mlLabel = classes[predictedIndex];
    const mlConfidence = round4(Math.max(...probabilities));
    const mlScore = round4(1 - probabilities[classes.indexOf("benign")]);
    const rule = heuristic(url, featureConfig);
    const threat = threatLookup(url);
    let fused = round4(W_ML * mlScore + W_HEURISTIC * rule.score + W_THREAT * threat.score);
    if (threat.flag) fused = Math.max(fused, 0.75);

    let finalLabel = mlLabel, decider = "ml", trusted = false;
    if (threat.flag && mlLabel === "benign") {
      decider = "blocklist";
      // Preserve analyzer.py's exact list-name comparison, including its current label behavior.
      finalLabel = threat.matched.some(name => name.toLowerCase() === "urlhaus") ? "malware" : "phishing";
    }

    const host = domainOf(url), brandSub = brandInSubdomain(host, featureConfig);
    const isIpAddress = Boolean(URLFeatures.extractFeatures(url, featureConfig).is_domain_ip);
    trusted = !threat.flag && !isIpAddress && isTrustedHost(host) && !brandSub;
    if (trusted) { decider = "allowlist"; finalLabel = "benign"; fused = Math.min(fused, 0.10); }

    const foldedHost = foldBrand(host);
    const obfuscated = featureConfig.brands.find(brand => foldedHost.includes(brand) && !host.includes(brand));
    let lookalike = null, weakBenignOverride = false;
    if (!trusted && !threat.flag && !isIpAddress) lookalike = findLookalike(baseDomain(host));
    if (lookalike) {
      decider = "lookalike";
      if (finalLabel === "benign") finalLabel = "phishing";
      fused = Math.max(fused, LOOKALIKE_SCORE[lookalike[1]]);
    } else if (brandSub && !threat.flag) {
      decider = "lookalike";
      if (finalLabel === "benign") finalLabel = "phishing";
      fused = Math.max(fused, LOOKALIKE_SCORE.subdomain);
      lookalike = [`${brandSub}.com`, "subdomain"];
    } else if (obfuscated && !trusted && !threat.flag) {
      decider = "lookalike";
      if (finalLabel === "benign") finalLabel = "phishing";
      fused = Math.max(fused, LOOKALIKE_SCORE.typo);
      lookalike = [`${obfuscated}.com`, "confusable"];
    } else if (finalLabel === "benign" && fused >= 0.30) {
      decider = "fusion"; weakBenignOverride = true;
      const threatClasses = classes.filter(name => name !== "benign");
      finalLabel = threatClasses.reduce((best, name) => probabilities[classes.indexOf(name)] > probabilities[classes.indexOf(best)] ? name : best);
    }

    const lookalikeDetail = lookalike ? describeLookalike(baseDomain(host), lookalike[0], lookalike[1]) : null;
    const confidence = finalLabel === mlLabel ? mlConfidence : finalLabel === "benign" ? round4(1 - fused) : round4(Math.max(fused, probabilities[classes.indexOf(finalLabel)]));
    const level = riskLevel(fused);
    const finalRisk = finalLabel !== "benign" && ["safe", "low"].includes(level) ? "medium" : level;
    const traced = trace({ finalLabel, decider, threat, matchedLists: threat.matched, trusted, host,
      lookalike, lookalikeDetail, weakBenignOverride, fused, mlLabel, mlConfidence,
      heuristicScore: rule.score, triggeredRules: rule.triggered });
    const raw = {
      url, prediction: finalLabel, risk_level: finalRisk, score: fused, confidence,
      lookalike_score: lookalike ? LOOKALIKE_SCORE[lookalike[1]] : 0,
      trusted_domain: trusted, feedback: null, feedback_conflict: false,
      lookalike: lookalike ? { target: lookalike[0], kind: lookalike[1], detail: lookalikeDetail } : null,
      decided_by: decider, trace: traced,
      ml: { label: mlLabel, confidence: mlConfidence, score: mlScore, probabilities: Object.fromEntries(classes.map((label, index) => [label, round4(probabilities[index])])) },
      heuristic: { score: rule.score, triggered_rules: rule.triggered.map(([name, , description]) => [name, description]) },
      threat_intel: { score: threat.score, flag: threat.flag, matched_lists: threat.matched }
    };
    return {
      url, prediction: finalLabel, risk_level: finalRisk, score: fused,
      reasons: reasons({ ...raw, mlLabel, threat, heuristic: rule, lookalike: raw.lookalike, trusted }, featureConfig),
      confidence, layers: { ml: mlScore, heuristic: rule.score, threat_intel: threat.score,
        lookalike: raw.lookalike_score, trusted, feedback: null },
      drivers: [], driver_status: "TreeSHAP contributions are not available in this static browser build.",
      decided_by: decider, decided_by_label: DECIDER_LABEL[decider], trace: traced,
      feedback: null, ml_probs: raw.ml.probabilities, suggestion: suggestion(url, finalRisk),
      elapsed_ms: 0
    };
  }

  function probabilityRows(outputs, outputNames, count, classCount) {
    const preferred = [...outputNames].sort((a, b) => Number(/prob/i.test(b)) - Number(/prob/i.test(a)));
    for (const name of preferred) {
      const value = outputs[name], data = value && value.data !== undefined ? value.data : value;
      if ((ArrayBuffer.isView(data) || Array.isArray(data)) && data.length >= count * classCount && Number.isFinite(Number(data[0]))) {
        return Array.from(data).slice(0, count * classCount);
      }
      if (Array.isArray(value) && count === 1 && value.length === 1) {
        const entry = value[0] instanceof Map ? value[0] : value[0];
        if (entry && typeof entry === "object") {
          return metadata.classes.map((label, index) => Number(entry instanceof Map ? (entry.has(label) ? entry.get(label) : entry.get(index)) : (entry[label] ?? entry[index] ?? entry[String(index)])));
        }
      }
    }
    throw new Error("The ONNX model did not return class probabilities.");
  }

  function validateUrl(value) {
    if (typeof value !== "string") throw new TypeError("URL must be text.");
    let url = URLFeatures.normalizeForAnalysis(value);
    if (!/^[a-z][a-z0-9+.-]*:/i.test(url)) url = `https://${url}`;
    if (URLFeatures.codePointLength(url) > 4096) throw new RangeError("URL is longer than 4,096 characters.");
    const parsed = parse(url);
    if (!["http", "https"].includes(parsed.scheme) || !parsed.netloc || /[\s\u0000-\u001f]/u.test(parsed.netloc)) throw new TypeError("Use a valid HTTP or HTTPS URL.");
    return URLFeatures.normalizeForAnalysis(url);
  }

  async function initialize(options = {}) {
    if (session) return { metadata, data: engineData };
    if (!URLFeatures) throw new Error("The URL feature extractor is not loaded.");
    if (typeof ort === "undefined") throw new Error("ONNX Runtime Web is not loaded.");
    const assetBase = new URL(options.assetBase || "./", options.baseUrl || document.baseURI);
    origin = assetBase;
    const fetchJson = async name => {
      const response = await fetch(new URL(name, assetBase));
      if (!response.ok) throw new Error(`Could not load ${name} (${response.status}).`);
      return response.json();
    };
    [metadata, engineData] = await Promise.all([fetchJson("metadata.json"), fetchJson("engine-data.json")]);
    if (engineData.schema !== 1 || metadata.features.length !== URLFeatures.FEATURES.length || metadata.classes.length !== 3) throw new Error("Browser model metadata is incomplete.");
    if (metadata.features.some((name, index) => name !== URLFeatures.FEATURES[index])) throw new Error("Browser feature order does not match the exported model.");
    featureConfig = metadata.featureConfig;
    ort.env.wasm.wasmPaths = new URL("runtime/", assetBase).href;
    ort.env.wasm.numThreads = 1;
    const onnx = new URL("model.onnx", assetBase).href;
    session = await ort.InferenceSession.create(onnx, { executionProviders: ["wasm"] });
    return { metadata, data: engineData };
  }

  async function analyzeMany(urls) {
    if (!session) await initialize();
    if (!urls.length) return [];
    const normalized = urls.map(validateUrl);
    const vectors = normalized.map(url => URLFeatures.extractFeatures(url, featureConfig));
    const input = Float32Array.from(vectors.flatMap(row => metadata.features.map(name => row[name])));
    const tensor = new ort.Tensor("float32", input, [normalized.length, metadata.features.length]);
    const started = performance.now();
    const outputs = await session.run({ [session.inputNames[0]]: tensor });
    const values = probabilityRows(outputs, session.outputNames, normalized.length, metadata.classes.length);
    const elapsed = performance.now() - started;
    return normalized.map((url, index) => {
      const probabilities = values.slice(index * metadata.classes.length, (index + 1) * metadata.classes.length).map(Number);
      return { ...resultFor(url, probabilities), elapsed_ms: elapsed / normalized.length };
    });
  }

  async function analyze(url) { return (await analyzeMany([url]))[0]; }
  function status() { return { ready: Boolean(session), metadata, origin: origin && origin.href }; }

  return { initialize, analyze, analyzeMany, status, validateUrl, _internals: { baseDomain, heuristic, threatLookup, findLookalike, reasons, riskLevel } };
});
