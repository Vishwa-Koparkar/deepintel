import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const fixture = {
  url: 'https://secure-northstar.example/sign-in',
  prediction: 'phishing',
  risk_level: 'high',
  score: 0.742,
  confidence: 0.842,
  ml_probs: { benign: 0.084, phishing: 0.842, malware: 0.074 },
  reasons: [
    { priority: 1, impact: 'High', reason: 'Sign-in language appears on a domain with no verified brand association.' },
    { priority: 2, impact: 'Medium', reason: 'The URL uses an account-verification path on a newly styled host.' },
    { priority: 3, impact: 'Low', reason: 'The reserved .example domain cannot resolve to a public site.' },
  ],
  feedback: null,
  suggestion: null,
};

const reply = (res, status, data, origin = '*') => {
  res.writeHead(status, {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(data));
};

export const server = createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return reply(res, 204, {});
  const url = new URL(req.url || '/', 'http://localhost');
  if (req.method === 'GET' && ['/dashboard', '/dashboard.html', '/'].includes(url.pathname)) {
    const html = await readFile(resolve(root, 'dashboard.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(html);
  }
  if (req.method === 'GET' && url.pathname === '/demo-config') return reply(res, 200, { feedbackEnabled: true });
  if (req.method === 'GET' && url.pathname === '/feedback') return reply(res, 200, { items: [], untrained: 0 });
  if (req.method === 'POST' && url.pathname === '/analyze') {
    let body = '';
    for await (const chunk of req) body += chunk;
    let requestedUrl = fixture.url;
    try { requestedUrl = JSON.parse(body).url || fixture.url; } catch {}
    return reply(res, 200, { ...fixture, url: requestedUrl });
  }
  if (req.method === 'POST' && url.pathname === '/feedback') return reply(res, 200, { ok: true });
  if (req.method === 'DELETE' && url.pathname.startsWith('/feedback/')) return reply(res, 200, { ok: true });
  return reply(res, 404, { detail: 'Not found' });
});

export { fixture };
