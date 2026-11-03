const assert = require("assert");
const { hopFlags } = require("./hops.js");
const h = (url, host) => ({ url, host: host || new URL(url).hostname });

let f = hopFlags([h("https://a.com/x"), h("http://a.com/y")]);
assert(f[1].includes("https→http downgrade"));
assert(!f[1].includes("domain change"));

f = hopFlags([h("https://a.com/x"), h("http://a.com/")]); // bare http = Chrome fallback
assert(!f[1].includes("https→http downgrade"));

f = hopFlags([h("https://a.com/x"), h("https://1.2.3.4/p")]);
assert(f[1].includes("raw IP host"));
f = hopFlags([h("https://a.com/x"), h("https://[::1]/p")]);
assert(f[1].includes("raw IP host"));

f = hopFlags([h("https://www.a.com/x"), h("https://b.com/y")]);
assert(f[1].includes("domain change"));
f = hopFlags([h("https://www.a.com/x"), h("https://m.a.com/y")]);
assert(!f[1].includes("domain change"));

f = hopFlags([h("https://a.com/1"), h("https://a.com/2"), h("https://a.com/3"), h("https://a.com/4")]);
assert(!f[3].includes("long chain"));
f = hopFlags([h("https://a.com/1"), h("https://a.com/2"), h("https://a.com/3"), h("https://a.com/4"), h("https://a.com/5")]);
assert(f[4].includes("long chain") && !f[0].includes("long chain"));
console.log("hops tests passed");
