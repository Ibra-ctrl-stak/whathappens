// Day 5 slice 1: the local timeline page. Security properties first, then content.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, readdirSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { buildTimeline } from '../src/timeline.js';
import { timelineView } from '../src/server/view-model.js';
import { startServer } from '../src/server/server.js';

const golden = JSON.parse(readFileSync(new URL('./fixtures/github-robots/session.json', import.meta.url), 'utf8'));
const timeline = buildTimeline(loadSession(golden));
const WEB_DIR = new URL('../web/', import.meta.url);

let server;
before(async () => {
  server = await startServer({ view: timelineView(timeline) });
});
after(() => server.close());

/** Raw request so Host/Origin can be set freely (fetch forbids Host). */
function request(path, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: server.port, path, method, headers: { host: `127.0.0.1:${server.port}`, ...headers } },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

const page = () => `/${server.token}/`;

test('listens on loopback only, on a random port, behind an unguessable token', () => {
  assert.equal(server.host, '127.0.0.1');
  assert.ok(server.port > 0);
  assert.ok(server.token.length >= 32);
  assert.equal(server.url, `http://127.0.0.1:${server.port}/${server.token}/`);
});

test('the page is served with a strict CSP and hardening headers', async () => {
  const res = await request(page());
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /^text\/html; charset=utf-8/);
  const csp = res.headers['content-security-policy'];
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['referrer-policy'], 'no-referrer'); // the token is in the URL
  assert.equal(res.headers['cache-control'], 'no-store');
});

for (const [label, path] of [
  ['the root without a token', '/'],
  ['a wrong token', '/not-the-token/'],
  ['a path traversal attempt', () => `/${server.token}/../package.json`],
  ['an encoded traversal attempt', () => `/${server.token}/%2e%2e/package.json`],
  ['a file that is not on the allow-list', () => `/${server.token}/server.js`],
]) {
  test(`404 for ${label}`, async () => {
    const res = await request(typeof path === 'function' ? path() : path);
    assert.equal(res.status, 404);
    assert.doesNotMatch(res.body, /keylog|SECRET/);
  });
}

test('a foreign Host header is refused (DNS rebinding)', async () => {
  const res = await request(page(), { headers: { host: 'evil.example' } });
  assert.equal(res.status, 403);
});

test('a foreign Origin is refused', async () => {
  const res = await request(`${page()}timeline.json`, { headers: { origin: 'http://evil.example' } });
  assert.equal(res.status, 403);
});

test('only GET and HEAD are allowed', async () => {
  const res = await request(`${page()}timeline.json`, { method: 'POST' });
  assert.equal(res.status, 405);
});

test('timeline.json carries the events and nothing secret', async () => {
  const res = await request(`${page()}timeline.json`);
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /^application\/json/);
  const view = JSON.parse(res.body);
  assert.equal(view.events.length, timeline.events.length);
  assert.deepEqual(Object.keys(view.events[0]).sort(), ['buffer', 'damaged', 'dir', 'kind', 'layer', 'length', 'offset', 'problem', 'summary', 't'].sort());
  for (const line of golden.tls.keylog) assert.ok(!res.body.includes(line.split(' ')[2]), 'no session secret');
  assert.ok(!res.body.includes(golden.tls.raw[0].hex.slice(0, 64)), 'no raw wire bytes');
  assert.ok(!/keylog/i.test(res.body));
});

test('the page scripts never build HTML from strings', () => {
  for (const file of readdirSync(WEB_DIR).filter((f) => f.endsWith('.js'))) {
    const source = readFileSync(new URL(file, WEB_DIR), 'utf8');
    assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/, file);
  }
});

test('the page has no inline script or style', () => {
  const html = readFileSync(new URL('index.html', WEB_DIR), 'utf8');
  assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)[^>]*>/i, 'every script has a src');
  assert.doesNotMatch(html, /<style|\sstyle=|\son[a-z]+=/i);
});
