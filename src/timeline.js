// One timeline for a recorded session: DNS -> TCP -> TLS -> HTTP.
// Every event points at bytes we recorded: { buffer, offset, length }. Events with no bytes we
// could see (TCP connect/close, a lost datagram) say so with buffer null and length 0.
import { parseResponse, TYPE } from './dns/packet.js';
import { decryptSession } from './tls/decrypt.js';
import { parseHttpMessage, headerValue } from './http/message.js';

const LAYER_ORDER = Object.freeze({ dns: 0, tcp: 1, tls: 2, http: 3 });
const RECORD_HEADER_LEN = 5;
const MAX_LISTED_NS = 2;
const CONTENT_NAMES = Object.freeze({ 20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'ApplicationData' });
const HANDSHAKE_NAMES = Object.freeze({
  1: 'ClientHello', 2: 'ServerHello', 4: 'NewSessionTicket', 8: 'EncryptedExtensions', 11: 'Certificate',
  13: 'CertificateRequest', 15: 'CertificateVerify', 20: 'Finished', 24: 'KeyUpdate',
});
const ALERT_NAMES = Object.freeze({ 0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac', 40: 'handshake_failure' });

const event = (fields) => ({ dir: null, buffer: null, offset: 0, length: 0, detail: {}, ...fields });
const bytesEvent = (buffer, bytes, fields) => event({ buffer, offset: 0, length: bytes.length, ...fields });

// ---- DNS -------------------------------------------------------------------------------------

function describeDns(msg) {
  const a = msg.answers.filter((r) => r.type === TYPE.A).map((r) => r.data);
  if (a.length > 0) return `A ${a.join(', ')}${msg.authoritative ? ' (authoritative)' : ''}`;
  const ns = msg.authority.filter((r) => r.type === TYPE.NS);
  const more = ns.length > MAX_LISTED_NS ? ` (+${ns.length - MAX_LISTED_NS})` : '';
  const zone = ns[0]?.name ?? '?';
  return `referral: ${zone} is served by ${ns.slice(0, MAX_LISTED_NS).map((r) => r.data).join(', ')}${more}`;
}

function dnsPart(dns) {
  const parts = dns.map((e, i) => {
    const qId = `dns/${i}/query`;
    const common = { server: e.server, localPort: e.localPort };
    const query = bytesEvent(qId, e.query, {
      at: e.sentAt, layer: 'dns', kind: 'query', dir: 'out',
      summary: `A? ${e.qname} -> ${e.server.name} (${e.server.ip})`,
      detail: { ...common, id: e.query.readUInt16BE(0) },
    });
    if (!e.response) {
      const lost = event({ at: e.failedAt, layer: 'dns', kind: 'lost', summary: `no answer from ${e.server.name}: ${e.error}`, detail: common });
      return { buffers: [[qId, e.query]], events: [query, lost] };
    }
    const rId = `dns/${i}/response`;
    const msg = parseResponse(e.response);
    const response = bytesEvent(rId, e.response, {
      at: e.receivedAt, layer: 'dns', kind: 'response', dir: 'in', summary: describeDns(msg),
      detail: { ...common, id: msg.id, rcode: msg.rcode, authoritative: msg.authoritative, rttMs: e.receivedAt - e.sentAt },
    });
    return { buffers: [[qId, e.query], [rId, e.response]], events: [query, response] };
  });
  return { buffers: parts.flatMap((p) => p.buffers), events: parts.flatMap((p) => p.events) };
}

// ---- TCP -------------------------------------------------------------------------------------

/** Per direction: where each recorded chunk ends in the stream, and when it was seen. */
function chunkBounds(raw, dir) {
  let end = 0;
  return raw.filter((c) => c.dir === dir).map((c) => ({ start: end, end: (end += c.bytes.length), at: c.at, bytes: c.bytes }));
}

const timeAtByte = (bounds, pos) => bounds.find((b) => pos < b.end).at;

function tcpPart(tls, bounds) {
  const remote = `${tls.ip}:${tls.port}`;
  const chunks = ['out', 'in'].flatMap((dir) =>
    bounds[dir].map((b) => event({
      at: b.at, layer: 'tcp', kind: dir === 'out' ? 'write' : 'read', dir, buffer: `tcp/${dir}`,
      offset: b.start, length: b.bytes.length, summary: `${dir === 'out' ? 'sent' : 'received'} ${b.bytes.length} B`,
    })),
  );
  const t = tls.times;
  return {
    buffers: ['out', 'in'].map((dir) => [`tcp/${dir}`, Buffer.concat(bounds[dir].map((b) => b.bytes))]),
    events: [
      event({ at: t.connectStartedAt, layer: 'tcp', kind: 'connect', summary: `connect ${tls.local.address}:${tls.local.port} -> ${remote}` }),
      event({ at: t.connectedAt, layer: 'tcp', kind: 'established', summary: 'connected (SYN / SYN-ACK / ACK are handled by the OS, not visible to Node)' }),
      ...chunks,
      event({ at: t.closedAt, layer: 'tcp', kind: 'close', summary: 'connection closed' }),
    ],
  };
}

// ---- TLS -------------------------------------------------------------------------------------

function describeRecord(r) {
  const hs = r.handshakeTypes?.length ? r.handshakeTypes.map((t) => HANDSHAKE_NAMES[t] ?? `handshake ${t}`).join(' + ') : null;
  const inner = r.contentType === 22 ? hs ?? 'Handshake fragment'
    : r.contentType === 21 ? `Alert: ${ALERT_NAMES[r.content[1]] ?? r.content[1]}`
      : r.contentType === 23 ? `ApplicationData ${r.content.length} B`
        : CONTENT_NAMES[r.contentType] ?? `type ${r.contentType}`;
  return r.epoch === 'plaintext' ? inner : `encrypted (${r.epoch} #${r.seq}): ${inner}`;
}

const recordEnd = (r) => r.offset + RECORD_HEADER_LEN + r.length - 1;

function tlsPart(tls, decrypted, bounds) {
  const sides = [['out', decrypted.client], ['in', decrypted.server]];
  const records = sides.flatMap(([dir, side]) =>
    side.records.map((r) => event({
      at: timeAtByte(bounds[dir], recordEnd(r)), layer: 'tls', kind: 'record', dir, buffer: `tcp/${dir}`,
      offset: r.offset, length: RECORD_HEADER_LEN + r.length, summary: describeRecord(r),
      detail: {
        epoch: r.epoch, seq: r.seq ?? null, outerType: r.outerType, contentType: r.contentType,
        handshakeTypes: r.handshakeTypes ?? [], plaintextLength: r.content.length, appDataOffset: r.appDataOffset ?? null,
      },
    })),
  );
  const { protocol, cipher, alpn } = tls.info;
  const secure = event({ at: tls.times.secureAt, layer: 'tls', kind: 'secure', summary: `${protocol} ${cipher.standardName}, ALPN ${alpn}` });
  return { buffers: [], events: [...records, secure] };
}

// ---- HTTP ------------------------------------------------------------------------------------

/** Time at which plaintext byte `pos` of a direction's appData became available. */
function plaintextTime(side, bounds, pos) {
  const r = side.records.find((rec) => rec.appDataOffset !== undefined && pos < rec.appDataOffset + rec.content.length);
  return timeAtByte(bounds, recordEnd(r));
}

function httpPart(decrypted, bounds) {
  const events = [];
  const buffers = [['http/out', decrypted.client.appData], ['http/in', decrypted.server.appData]];
  if (decrypted.client.appData.length > 0) {
    const req = parseHttpMessage(decrypted.client.appData);
    events.push(event({
      at: plaintextTime(decrypted.client, bounds.out, req.head.length - 1), layer: 'http', kind: 'request', dir: 'out',
      buffer: 'http/out', ...req.head, summary: `${req.startLine.method} ${req.startLine.target}`,
      detail: { headers: req.headers.length, host: headerValue(req, 'host') },
    }));
  }
  if (decrypted.server.appData.length > 0) {
    const res = parseHttpMessage(decrypted.server.appData);
    const { status, reason } = res.startLine;
    events.push(event({
      at: plaintextTime(decrypted.server, bounds.in, res.head.length - 1), layer: 'http', kind: 'response-head', dir: 'in',
      buffer: 'http/in', ...res.head, summary: `${status} ${reason}, ${headerValue(res, 'content-type') ?? 'no content-type'}`,
      detail: { status, headers: res.headers.length },
    }));
    if (res.body.length > 0) {
      events.push(event({
        at: plaintextTime(decrypted.server, bounds.in, res.body.offset + res.body.length - 1), layer: 'http', kind: 'response-body',
        dir: 'in', buffer: 'http/in', offset: res.body.offset, length: res.body.length,
        summary: `body ${res.body.length} B (${res.body.framing})`, detail: { framing: res.body.framing, declaredLength: res.body.declaredLength },
      }));
    }
  }
  return { buffers, events };
}

// ---- assembly --------------------------------------------------------------------------------

const roundUs = (ms) => Math.round(ms * 1000) / 1000;

/** session: as returned by loadSession(). */
export function buildTimeline(session) {
  const decrypted = decryptSession({ raw: session.tls.raw, keylog: session.tls.keylog });
  const bounds = { out: chunkBounds(session.tls.raw, 'out'), in: chunkBounds(session.tls.raw, 'in') };
  const parts = [dnsPart(session.dns), tcpPart(session.tls, bounds), tlsPart(session.tls, decrypted, bounds), httpPart(decrypted, bounds)];
  const all = parts.flatMap((p) => p.events);
  const missing = all.find((e) => !Number.isFinite(e.at));
  if (missing) throw new Error(`${missing.layer}/${missing.kind} has no timestamp in this recording`);

  const origin = Math.min(...all.map((e) => e.at));
  const events = all
    .map((e, index) => ({ t: roundUs(e.at - origin), ...e, index }))
    .sort((a, b) => a.t - b.t || LAYER_ORDER[a.layer] - LAYER_ORDER[b.layer] || a.index - b.index)
    .map(({ index, ...e }) => e);
  return { origin, buffers: Object.fromEntries(parts.flatMap((p) => p.buffers)), events };
}
