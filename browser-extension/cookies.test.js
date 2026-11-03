const assert = require("assert");
const { classifyCookie, pageScore, mask } = require("./cookies.js");
const base = { name: "x", value: "v", path: "/", secure: true, httpOnly: true, sameSite: "lax", session: true, hostOnly: true, party: "1p" };
const cc = (o, https = true) => classifyCookie({ ...base, ...o }, https);

let r = cc({ name: "_ga", value: "GA1.2.3", party: "3p" });
assert.equal(r.kind, "tracking"); assert(r.flags.includes("third-party tracker")); assert.equal(r.penalty, 1);

r = cc({ name: "sessionid", secure: false, httpOnly: false }, false);
assert.equal(r.kind, "session/auth");
assert(r.flags.includes("not Secure") && r.flags.includes("readable by page scripts") && r.flags.includes("sent over plain http"));
assert.equal(r.penalty, 6);

r = cc({ sameSite: "no_restriction", secure: false });
assert(r.flags.includes("SameSite=None without Secure"));

r = cc({ name: "__Host-a", path: "/x" });
assert(r.flags.includes("__Host- prefix rules violated"));

r = cc({ value: "eyJhbGciOi.eyJzdWIiOjF9.sig", httpOnly: false });
assert.equal(r.kind, "jwt"); assert(r.flags.includes("readable by page scripts"));

r = cc({ value: "bob%40example.com" });
assert(r.flags.includes("contains an email address"));

r = cc({});
assert.equal(r.penalty, 0); assert.equal(r.kind, "other");

assert.equal(mask("short"), "***");
assert.equal(mask("abcdefghij"), "abc…ij");

let s = pageScore([cc({}), cc({})].map(x => ({ ...x, party: "1p" })));
assert.equal(s.grade, "Good"); assert.equal(s.score, 100);
const bad = { ...cc({ name: "sid", secure: false, httpOnly: false, sameSite: "unspecified" }), party: "3p" };
s = pageScore([bad, bad]);
assert.equal(s.grade, "Poor"); assert.equal(s.counts.insecure, 2); assert.equal(s.counts.thirdParty, 2);
assert(s.top.length <= 3);
console.log("cookies ok");
