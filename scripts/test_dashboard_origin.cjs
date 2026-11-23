const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('dashboard.html', 'utf8');
const declaration = source.match(/^const API = .+;$/m)[0];
const cases = [
  [{protocol:'https:', pathname:'/dashboard', port:'', origin:'https://demo.example'}, 'https://demo.example'],
  [{protocol:'http:', pathname:'/dashboard', port:'7860', origin:'http://localhost:7860'}, 'http://localhost:7860'],
  [{protocol:'http:', pathname:'/dashboard.html', port:'4173', origin:'http://localhost:4173'}, 'http://127.0.0.1:8000'],
  [{protocol:'file:', pathname:'/dashboard.html', port:'', origin:'null'}, 'http://127.0.0.1:8000'],
  [{protocol:'http:', pathname:'/', port:'8000', origin:'http://localhost:8000'}, 'http://localhost:8000'],
];
for (const [location, expected] of cases) {
  assert.equal(vm.runInNewContext(`${declaration}\nAPI`, {location}), expected);
}
console.log('Dashboard origin: hosted, local API, static preview, and file cases pass.');

async function checkDemoMode(configResponse, enabled, browserMode = false) {
  const nodes = {};
  const requests = [];
  const context = vm.createContext({
    location: {protocol:'https:', pathname:'/dashboard', port:'', origin:'https://demo.example', href:'https://demo.example/dashboard'},
    USE_BROWSER_ENGINE: browserMode, URL,
    DeepIntelBrowserEngine: {async initialize(){}, status(){return {metadata:{modelBytes:100}};}},
    document: {getElementById(id) { return nodes[id] ||= {style:{}, addEventListener(){}}; }},
    fetch: async url => {
      requests.push(url);
      if (url.endsWith('/demo-config')) {
        if (configResponse instanceof Error) throw configResponse;
        return configResponse;
      }
      return {ok:true, json: async () => ({items:[], untrained:0})};
    },
  });
  const mainScript = [...source.matchAll(/<script>([\s\S]*?)<\/script>/g)].find(match => match[1].includes('const API ='))[1];
  vm.runInContext(mainScript, context);
  await vm.runInContext('demoReady', context);
  await vm.runInContext('loadCorrections()', context);
  assert.equal(nodes.feedbackSection.hidden, !enabled);
  assert.equal(nodes.readOnlyNotice.hidden, enabled);
  if (!enabled) {
    await assert.rejects(vm.runInContext('feedbackRequest("/feedback", {method:"POST"})', context), /disabled/);
    assert.equal(requests.filter(url => url.endsWith('/feedback')).length, 0);
  }
}
(async () => {
  await checkDemoMode({ok:true, json:async () => ({feedbackEnabled:false})}, false);
  await checkDemoMode({ok:false, status:404}, true);
  await checkDemoMode(new Error('offline'), false);
  await checkDemoMode(null, false, true);
  console.log('Dashboard modes: public read-only, local fallback, and offline guard pass.');
})().catch(error => {console.error(error); process.exitCode = 1;});
