const assert = require("node:assert/strict");
const metadata = require("./metadata.json");
const { FEATURES, extractFeatures, normalizeForAnalysis, parseUrl, zeroFeatures } = require("./features.js");

assert.deepEqual(FEATURES, metadata.features);
assert.equal(normalizeForAnalysis("  https://example.com/  "), "https://example.com");
assert.equal(normalizeForAnalysis("https://example.com/?x=1"), "https://example.com/?x=1");
assert.equal(normalizeForAnalysis("https://example.com/;v=1"), "https://example.com/;v=1");
assert.deepEqual(
  (({ path, params }) => ({ path, params }))(parseUrl("https://example.com/a/../B%2Fc;v=1?q=%2F#part")),
  { path: "/a/../B%2Fc", params: "v=1" }
);

const unicode = "https://paypa1.example.co.uk/Login/Путь.PDF;mode=1?x=%2F&digit=٢#section";
const features = extractFeatures(normalizeForAnalysis(unicode), metadata.featureConfig);
assert.equal(features.is_https, 1);
assert.equal(features.path_length, Array.from("/login/путь.pdf").length);
assert.equal(features.num_query_params, 2);
assert.equal(features.num_digits, 4); // ASCII 1s, the encoded 2, and Arabic-Indic ٢.
assert.equal(features.is_brand_impersonation, 1);
assert.equal(features.is_safe_country_tld, 1);
assert.equal(features.has_safe_extension, 1);
assert.equal(features.has_suspicious_keywords, 1);
assert.equal(features.has_encoded_chars, 1);

const ip = extractFeatures("http://192.168.0.1:8080/a//b", metadata.featureConfig);
assert.equal(ip.is_domain_ip, 1);
assert.equal(ip.is_https, 0);
assert.equal(ip.has_double_slash, 1);
assert.equal(ip.num_subdomains, 2);

const astral = extractFeatures("https://example.com/🧪", metadata.featureConfig);
assert.equal(astral.url_length, Array.from("https://example.com/🧪").length);
assert.equal(astral.path_length, Array.from("/🧪").length);
assert.deepEqual(extractFeatures("https://example.com]", metadata.featureConfig), zeroFeatures());

console.log("Feature edge cases passed");
