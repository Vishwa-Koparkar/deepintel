import { chromium } from 'playwright';
import { copyFile, mkdir, rm } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { server, fixture } from './demo-api.mjs';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repo = resolve(project, '..');
const extensionDir = resolve(repo, 'browser-extension');
const productDir = resolve(repo, 'website/assets/product');
const texturesDir = resolve(project, 'public/textures');
const profileDir = resolve(project, '.cache/brave-profile');
// shortcut: this capture runner targets the repository author's macOS Brave install; update when moving it to another machine.
const bravePath = '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser';
const sampleUrl = 'https://secure-northstar.example/sign-in';
const onion = `${'a'.repeat(55)}d.onion`;
const onionUrl = `https://${onion}/catalog`;

await mkdir(productDir, { recursive: true });
await mkdir(texturesDir, { recursive: true });
await rm(profileDir, { recursive: true, force: true });
await new Promise((resolveListen, reject) => {
  server.once('error', reject);
  server.listen(8000, '127.0.0.1', resolveListen);
});

let context;
try {
  context = await chromium.launchPersistentContext(profileDir, {
    executablePath: bravePath,
    headless: false,
    viewport: { width: 1600, height: 900 },
    deviceScaleFactor: 2,
    args: [
      `--disable-extensions-except=${extensionDir}`,
      `--load-extension=${extensionDir}`,
      '--no-first-run', '--no-default-browser-check', '--disable-sync',
      '--window-position=0,0', '--window-size=1680,1000',
    ],
  });

  const worker = context.serviceWorkers().find((w) => w.url().endsWith('/background.js'))
    || await context.waitForEvent('serviceworker', { timeout: 20000 });
  const extensionId = new URL(worker.url()).host;

  const dashboard = await context.newPage();
  await dashboard.goto('http://127.0.0.1:8000/dashboard', { waitUntil: 'domcontentloaded' });
  await dashboard.locator('#urlInput').fill(sampleUrl);
  await dashboard.locator('#analyzeBtn').click();
  await dashboard.waitForFunction(() => document.getElementById('results')?.style.display === 'block');
  await dashboard.evaluate(() => document.fonts.ready);
  await dashboard.addStyleTag({ content: `
    .header-status::after { content: 'SYNTHETIC DEMO DATA'; display: inline-block; margin-left: 12px; padding: 4px 8px; border-radius: 999px; background: #fff3e0; color: #7a4a00; font: 600 10px 'JetBrains Mono', monospace; letter-spacing: .4px; }
  ` });
  await dashboard.waitForTimeout(600);
  const dashboardPath = resolve(productDir, 'dashboard.png');
  await dashboard.screenshot({ path: dashboardPath });
  await copyFile(dashboardPath, resolve(texturesDir, 'dashboard.png'));

  const popup = await context.newPage();
  await popup.setViewportSize({ width: 360, height: 430 });
  await popup.goto(`chrome-extension://${extensionId}/popup.html`, { waitUntil: 'domcontentloaded' });
  await popup.waitForFunction(() => typeof window.render === 'function');
  await popup.waitForTimeout(500);
  await popup.evaluate(({ result, url }) => {
    document.getElementById('current-url').textContent = new URL(url).hostname;
    document.getElementById('error').classList.add('hidden');
    window.render(result);
    const notice = document.createElement('div');
    notice.textContent = 'SYNTHETIC DEMO · NO LIVE MODEL OUTPUT';
    notice.style.cssText = 'margin:8px 12px 0;padding:5px 8px;width:max-content;border:1px solid #f3d9a8;border-radius:999px;background:#fff3e0;color:#7a4a00;font:600 9px ui-monospace,monospace;letter-spacing:.25px';
    document.body.prepend(notice);
  }, { result: fixture, url: sampleUrl });
  const popupPath = resolve(productDir, 'extension.png');
  await popup.screenshot({ path: popupPath });
  await copyFile(popupPath, resolve(texturesDir, 'extension.png'));

  const warning = await context.newPage();
  await warning.goto(`chrome-extension://${extensionId}/warning.html?url=${onionUrl}`, { waitUntil: 'domcontentloaded' });
  await warning.locator('main').waitFor();
  await warning.evaluate(() => {
    const notice = document.createElement('div');
    notice.textContent = 'SYNTHETIC DEMO URL';
    notice.style.cssText = 'display:inline-block;margin:0 0 12px;padding:5px 8px;border:1px solid #f3d9a8;border-radius:999px;background:#fff3e0;color:#7a4a00;font:600 10px ui-monospace,monospace;letter-spacing:.25px';
    document.querySelector('main').insertBefore(notice, document.getElementById('target'));
  });
  const warningPath = resolve(productDir, 'warning.png');
  await warning.locator('main').screenshot({ path: warningPath });
  await copyFile(warningPath, resolve(texturesDir, 'warning.png'));

  console.log(JSON.stringify({ dashboard: dashboardPath, extension: popupPath, warning: warningPath, extensionId }));
} finally {
  if (context) await context.close();
  await new Promise((resolveClose) => server.close(resolveClose));
}
