// session.json: everything one run recorded, as hex, on one clock (epoch ms).
import { createHash } from 'node:crypto';

export const SESSION_FORMAT = 2;

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const fromHex = (hex) => Buffer.from(hex, 'hex');

/** Recorded run (Buffers) -> JSON-safe object. */
export function serializeSession({ startedAt, host, path, dns, tls }) {
  return {
    format: SESSION_FORMAT,
    startedAt: new Date(startedAt).toISOString(),
    host,
    path,
    dns: dns.map((e) => ({
      server: e.server,
      localPort: e.localPort,
      qname: e.qname,
      sentAt: e.sentAt,
      receivedAt: e.receivedAt,
      queryHex: e.query.toString('hex'),
      // A lost datagram: the query went out, nothing came back.
      responseHex: e.response ? e.response.toString('hex') : null,
      ...(e.error ? { failedAt: e.failedAt, error: e.error } : {}),
    })),
    tls: {
      ip: tls.ip,
      port: tls.port,
      local: tls.local,
      info: tls.tls,
      times: tls.times,
      raw: tls.raw.map((c) => ({ dir: c.dir, at: c.at, hex: c.bytes.toString('hex') })),
      keylog: tls.keylog,
    },
    // What Node's TLS stack handed to us; lets tests check our decryption without storing it twice.
    plaintext: { sentSha256: sha256(tls.plaintext.sent), receivedSha256: sha256(tls.plaintext.received) },
  };
}

/** JSON object -> Buffers. Throws on formats this code does not understand. */
export function loadSession(json) {
  if (json.format !== SESSION_FORMAT) {
    throw new Error(`session format ${json.format ?? 1} is not supported (expected ${SESSION_FORMAT}); re-record it`);
  }
  return {
    ...json,
    dns: json.dns.map((e) => ({
      ...e,
      query: fromHex(e.queryHex),
      response: e.responseHex === null ? null : fromHex(e.responseHex),
    })),
    tls: { ...json.tls, raw: json.tls.raw.map((c) => ({ dir: c.dir, at: c.at, bytes: fromHex(c.hex) })) },
  };
}
