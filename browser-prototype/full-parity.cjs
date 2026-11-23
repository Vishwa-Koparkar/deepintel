const { chromium } = require("playwright");
const assert = require("node:assert/strict");

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser", headless: true });
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(120000);
    await page.goto("http://127.0.0.1:4180/full-verify.html");
    const result = await page.evaluate(() => window.runFullParity());
    console.log(JSON.stringify(result, null, 2));
    assert.equal(result.mismatches.length, 0, JSON.stringify(result.mismatches.slice(0, 3)));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
