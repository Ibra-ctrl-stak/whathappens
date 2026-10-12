import { isIP } from 'node:net';

export function validateHostname(host) {
  if (typeof host !== 'string' || host.length > 253 || !host.length || /[^a-z0-9.-]/i.test(host) ||
      !host.split('.').every((label) => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))) {
    throw new Error('Invalid hostname: use a DNS name such as example.com.');
  }
}

export function validatePath(path) {
  if (typeof path !== 'string' || path.length > 16384 || !path.startsWith('/') || /[^\x21-\x7e]|[#\\]/.test(path)) {
    throw new Error('Invalid request path: use /path?query with spaces and Unicode percent-encoded.');
  }
}

/** One HTTPS request, with IDN encoding and an origin-form request target. */
export function parseTarget(input) {
  if (typeof input !== 'string' || !input || /[\s\x00-\x1f\x7f\\]/u.test(input) || input.startsWith('/')) {
    throw new Error('Enter a hostname or an HTTPS URL without spaces or control characters.');
  }
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`);
  } catch {
    throw new Error('Invalid URL. Example: https://example.com/robots.txt');
  }
  if (url.protocol !== 'https:') throw new Error('Only HTTPS is supported in this version.');
  if (url.username || url.password) throw new Error('URLs containing a username or password are not supported.');
  const host = url.hostname.replace(/\.$/, '');
  if (isIP(host) || host.startsWith('[')) throw new Error('Use a DNS hostname, not an IP address, to record iterative DNS.');
  validateHostname(host);
  const port = Number(url.port || 443);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid HTTPS port.');
  const path = `${url.pathname}${url.search}`;
  validatePath(path);
  url.hostname = host;
  url.hash = '';
  return { host, port, path, url: url.href };
}
