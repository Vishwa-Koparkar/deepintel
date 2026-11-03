const assert = require("assert");
const { isOnionHost, onionInfo, ONION_REGEX } = require("./onion.js");
const v3 = "a".repeat(55) + "d", bad = "a".repeat(56), v2 = "abcdefghij234567";
const re = new RegExp(ONION_REGEX, "i");
const cases = [
  [`${v3}.onion`, true], [`${v3}.onion.ws`, true], [`${v2}.onion`, true], ["example.com", false], ["notonion.com", false],
];
for (const [h, want] of cases) {
  assert.strictEqual(isOnionHost(h), want, h);
  assert.strictEqual(re.test(`https://${h}/p?q=1#f`), want, "regex " + h);
}
assert.ok(re.test(`http://www.${v2}.onion:8080`));
assert.ok(!re.test("https://example.com/x.onion"));
assert.deepStrictEqual(onionInfo(`${v3}.onion`), { v3: true, v2: false, gateway: false, malformed: false });
assert.deepStrictEqual(onionInfo(`${v3}.onion.ws`), { v3: true, v2: false, gateway: true, malformed: false });
assert.deepStrictEqual(onionInfo(`${v2}.onion`), { v3: false, v2: true, gateway: false, malformed: false });
assert.strictEqual(onionInfo(`${bad}.onion`).malformed, true);
assert.strictEqual(onionInfo("example.com").v3, false);
console.log("onion tests passed");
