// Local page server. Only 127.0.0.1, random port, random token as the first path segment.
// Routes are a fixed allow-list of in-memory bodies: request paths never touch the file system.
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

const HOST = '127.0.0.1';
const TOKEN_BYTES = 32;
const WEB_DIR = new URL('../../web/', import.meta.url);
const STATIC = Object.freeze({
  '': ['index.html', 'text/html; charset=utf-8'],
  'app.js': ['app.js', 'text/javascript; charset=utf-8'],
  'hex.js': ['hex.js', 'text/javascript; charset=utf-8'],
  'style.css': ['style.css', 'text/css; charset=utf-8'],
});

const SECURITY_HEADERS = Object.freeze({
  'content-security-policy': [
    "default-src 'self'", "script-src 'self'", "style-src 'self'", "img-src 'self'", "connect-src 'self'",
    "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
  ].join('; '),
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
  'cross-origin-resource-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'x-frame-options': 'DENY',
});

function routes(view) {
  const files = Object.entries(STATIC).map(([route, [file, type]]) => [route, { type, body: readFileSync(new URL(file, WEB_DIR)) }]);
  const json = { type: 'application/json; charset=utf-8', body: Buffer.from(JSON.stringify(view)) };
  return new Map([...files, ['timeline.json', json]]);
}

function send(res, status, type, body, method) {
  res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': type, 'content-length': body.length });
  res.end(method === 'HEAD' ? undefined : body);
}

// events/<index>/bytes with a canonical decimal index (no sign, no leading zeros)
const EVENT_BYTES = /^events\/(0|[1-9]\d{0,8})\/bytes$/;

function eventBytesRoute(path, bytesOf) {
  const match = EVENT_BYTES.exec(path);
  const bytes = match ? bytesOf(Number(match[1])) : null;
  return bytes ? { type: 'application/octet-stream', body: bytes } : null;
}

/** Decide one request; returns [status, route-or-null]. */
function check(req, { port, token, table, bytesOf }) {
  const self = `${HOST}:${port}`;
  if (req.headers.host !== self) return [403, null]; // DNS rebinding: a foreign name pointing at us
  if (req.headers.origin !== undefined && req.headers.origin !== `http://${self}`) return [403, null];
  if (req.method !== 'GET' && req.method !== 'HEAD') return [405, null];
  const prefix = `/${token}/`;
  if (!req.url.startsWith(prefix)) return [404, null];
  const path = req.url.slice(prefix.length);
  const route = table.get(path) ?? eventBytesRoute(path, bytesOf);
  return route ? [200, route] : [404, null];
}

/**
 * view: timelineView(...) output; bytesOf: eventBytes(...) — (index) -> Buffer | null.
 * Resolves to { host, port, token, url, close }.
 */
export function startServer({ view, bytesOf = () => null }) {
  const token = randomBytes(TOKEN_BYTES).toString('base64url');
  const table = routes(view);
  const server = http.createServer((req, res) => {
    const [status, route] = check(req, { port: server.address().port, token, table, bytesOf });
    if (route) send(res, status, route.type, route.body, req.method);
    else send(res, status, 'text/plain; charset=utf-8', Buffer.from(`${status}\n`), req.method);
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, HOST, () => {
      const { port } = server.address();
      resolve({ host: HOST, port, token, url: `http://${HOST}:${port}/${token}/`, close: () => server.close() });
    });
  });
}
