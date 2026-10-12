// Replace the server's HTTP bytes of a recorded session with chosen fragments: each fragment is
// re-encrypted with the session's own keys as one TLS record that arrives `stepMs` after the
// previous one, so tests control both record boundaries and arrival times.
import { loadSession } from '../../src/session.js';
import { decryptSession, parseKeylog, trafficKeys, SUITES } from '../../src/tls/decrypt.js';
import { sealRecord } from './tls-seal.mjs';

const APP_DATA = 23;
const ALERT = 21;
const CLOSE_NOTIFY = Buffer.from([1, 0]);

export function withServerResponse(sessionJson, fragments, { stepMs = 10 } = {}) {
  const decrypted = decryptSession(loadSession(sessionJson).tls);
  const suite = SUITES[decrypted.suite.id];
  const keys = trafficKeys(suite, parseKeylog(sessionJson.tls.keylog).secrets.SERVER_TRAFFIC_SECRET_0);
  const first = decrypted.server.records.find((r) => r.epoch === 'application' && r.contentType === APP_DATA);
  const sealed = [
    ...fragments.map((f, i) => sealRecord(suite, keys, first.seq + i, APP_DATA, Buffer.isBuffer(f) ? f : Buffer.from(f, 'latin1'))),
    sealRecord(suite, keys, first.seq + fragments.length, ALERT, CLOSE_NOTIFY),
  ];

  // Keep the server bytes before the first application-data record in their original chunks.
  let pos = 0;
  let lastAt = 0;
  const kept = sessionJson.tls.raw.flatMap((c) => {
    if (c.dir !== 'in') return [c];
    const length = Math.max(0, Math.min(c.hex.length / 2, first.offset - pos));
    pos += c.hex.length / 2;
    if (length === 0) return [];
    lastAt = c.at;
    return [{ ...c, hex: c.hex.slice(0, length * 2) }];
  });
  const added = sealed.map((bytes, i) => ({ dir: 'in', at: lastAt + (i + 1) * stepMs, hex: bytes.toString('hex') }));
  const closedAt = added.at(-1).at + 1;
  return { ...sessionJson, tls: { ...sessionJson.tls, raw: [...kept, ...added], times: { ...sessionJson.tls.times, closedAt } } };
}
