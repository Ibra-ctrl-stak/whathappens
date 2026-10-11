// One timeline for a recorded session: DNS -> TCP -> TLS -> HTTP.
// Every event points at bytes we recorded: { buffer, offset, length }. Events with no bytes we
// could see (TCP connect/close, a lost datagram) say so with buffer null and length 0.
// Nothing broken is hidden: what cannot be parsed or decrypted becomes an event with
// damaged: true and a problem, over the bytes it occupies; the other layers stay intact.
import { parseResponse, TYPE } from './dns/packet.js';
import { decryptSession } from './tls/decrypt.js';
import { parseHttpMessage, headerValue } from './http/message.js';
import { printable, printableDeep } from './text.js';

const LAYER_ORDER = Object.freeze({ dns: 0, tcp: 1, tls: 2, http: 3 });
const RECORD_HEADER_LEN = 5;
const MAX_LISTED_NS = 2;
const RCODE_NAMES = Object.freeze({ 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' });
const CONTENT_NAMES = Object.freeze({ 20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'ApplicationData' });
const HANDSHAKE_NAMES = Object.freeze({
  1: 'ClientHello', 2: 'ServerHello', 4: 'NewSessionTicket', 8: 'EncryptedExtensions', 11: 'Certificate',
  13: 'CertificateRequest', 15: 'CertificateVerify', 20: 'Finished', 24: 'KeyUpdate',
});
const ALERT_NAMES = Object.freeze({ 0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac', 40: 'handshake_failure' });
const HTTP_KINDS = Object.freeze({
  out: { head: 'request', body: 'request-body' },
  in: { head: 'response-head', body: 'response-body' },
});

const event = (fields) => ({ dir: null, buffer: null, offset: 0, length: 0, detail: {}, damaged: false, problem: null, ...fields });
const bytesEvent = (buffer, bytes, fields) => event({ buffer, offset: 0, length: bytes.length, ...fields });
const damage = (problem) => ({ damaged: true, problem });

// ---- DNS -------------------------------------------------------------------------------------

function describeDns(msg) {
  if (msg.rcode !== 0) return `${RCODE_NAMES[msg.rcode] ?? 'error'} (rcode ${msg.rcode})`;
  const a = msg.answers.filter((r) => r.type === TYPE.A).map((r) => r.data);
  if (a.length > 0) return `A ${a.join(', ')}${msg.authoritative ? ' (authoritative)' : ''}`;
  const cname = msg.answers.find((r) => r.type === TYPE.CNAME);
  if (cname) return `CNAME ${cname.data}`;
  const ns = msg.authority.filter((r) => r.type === TYPE.NS);
  if (ns.length === 0) return 'no records (NOERROR, empty answer)';
  const more = ns.length > MAX_LISTED_NS ? ` (+${ns.length - MAX_LISTED_NS})` : '';
  return `referral: ${ns[0].name} is served by ${ns.slice(0, MAX_LISTED_NS).map((r) => r.data).join(', ')}${more}`;
}

function dnsResponseEvent(e, rId) {
  const fields = { at: e.receivedAt, layer: 'dns', kind: 'response', dir: 'in', detail: { server: e.server, localPort: e.localPort } };
  let msg;
  try {
    msg = parseResponse(e.response);
  } catch (err) {
    return bytesEvent(rId, e.response, { ...fields, summary: `damaged response from ${e.server.name}`, ...damage(`malformed response: ${err.message}`) });
  }
  return bytesEvent(rId, e.response, {
    ...fields,
    summary: describeDns(msg),
    detail: { ...fields.detail, id: msg.id, rcode: msg.rcode, authoritative: msg.authoritative, rttMs: e.receivedAt - e.sentAt },
  });
}

function dnsPart(dns) {
  const parts = dns.map((e, i) => {
    const qId = `dns/${i}/query`;
    const query = bytesEvent(qId, e.query, {
      at: e.sentAt, layer: 'dns', kind: 'query', dir: 'out',
      summary: `A? ${e.qname} -> ${e.server.name} (${e.server.ip})`,
      detail: { server: e.server, localPort: e.localPort, id: e.query.readUInt16BE(0) },
    });
    if (!e.response) {
      const lost = event({ at: e.failedAt, layer: 'dns', kind: 'lost', summary: `no answer from ${e.server.name}: ${e.error}`, detail: { server: e.server, localPort: e.localPort } });
      return { buffers: [[qId, e.query]], events: [query, lost] };
    }
    const rId = `dns/${i}/response`;
    return { buffers: [[qId, e.query], [rId, e.response]], events: [query, dnsResponseEvent(e, rId)] };
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

function describeInner(r) {
  if (r.contentType === 22) {
    return r.handshakeTypes?.length ? r.handshakeTypes.map((t) => HANDSHAKE_NAMES[t] ?? `handshake ${t}`).join(' + ') : 'Handshake fragment';
  }
  if (r.contentType === 21) return `Alert: ${ALERT_NAMES[r.content[1]] ?? r.content[1]}`;
  if (r.contentType === 23) return `ApplicationData ${r.content.length} B`;
  return CONTENT_NAMES[r.contentType] ?? `type ${r.contentType}`;
}

export function describeRecord(r) {
  if (r.damaged) return `damaged (${r.epoch} #${r.seq})`;
  return r.epoch === 'plaintext' ? describeInner(r) : `encrypted (${r.epoch} #${r.seq}): ${describeInner(r)}`;
}

const recordEnd = (r) => r.offset + RECORD_HEADER_LEN + r.length - 1;

function recordEvent(dir, r, bounds) {
  return event({
    at: timeAtByte(bounds[dir], recordEnd(r)), layer: 'tls', kind: 'record', dir, buffer: `tcp/${dir}`,
    offset: r.offset, length: RECORD_HEADER_LEN + r.length, summary: describeRecord(r),
    detail: {
      epoch: r.epoch, seq: r.seq ?? null, outerType: r.outerType, contentType: r.contentType,
      handshakeTypes: r.handshakeTypes ?? [], plaintextLength: r.content?.length ?? 0, appDataOffset: r.appDataOffset ?? null,
    },
    ...(r.damaged ? damage(r.problem) : {}),
  });
}

/** The stream ended inside a record: its bytes are shown, flagged. */
function incompleteRecordEvent(dir, streamLength, trailing, bounds) {
  return event({
    at: timeAtByte(bounds[dir], streamLength - 1), layer: 'tls', kind: 'record', dir, buffer: `tcp/${dir}`,
    offset: streamLength - trailing, length: trailing, summary: 'incomplete record',
    ...damage(`incomplete record: ${trailing} bytes, the stream ended mid-record`),
  });
}

/** TLS could not be read at all (no hello, unknown suite, keys missing): one event per direction. */
function undecodableStreams(tls, bounds, reason) {
  const events = ['out', 'in']
    .filter((dir) => bounds[dir].length > 0)
    .map((dir) => {
      const length = bounds[dir].at(-1).end;
      return event({ at: bounds[dir].at(-1).at, layer: 'tls', kind: 'stream', dir, buffer: `tcp/${dir}`, length, summary: 'TLS stream not readable', ...damage(reason) });
    });
  return { buffers: [], events };
}

function tlsPart(tls, decrypted, bounds) {
  if (decrypted.error) return undecodableStreams(tls, bounds, decrypted.error);
  const sides = [['out', decrypted.client, 'client'], ['in', decrypted.server, 'server']];
  const records = sides.flatMap(([dir, side, name]) => {
    const trailing = decrypted.trailingBytes[name];
    const streamLength = bounds[dir].at(-1)?.end ?? 0;
    const tail = trailing > 0 ? [incompleteRecordEvent(dir, streamLength, trailing, bounds)] : [];
    return [...side.records.map((r) => recordEvent(dir, r, bounds)), ...tail];
  });
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

function headSummary(msg) {
  if (msg.kind === 'request') return `${msg.startLine.method} ${msg.startLine.target}`;
  return `${msg.startLine.status} ${msg.startLine.reason}, ${headerValue(msg, 'content-type') ?? 'no content-type'}`;
}

function messageEvents(msg, dir, buffer, timeAt) {
  const kinds = HTTP_KINDS[dir];
  const detail = msg.kind === 'request'
    ? { headers: msg.headers.length, host: headerValue(msg, 'host') ?? null }
    : { status: msg.startLine.status, headers: msg.headers.length };
  const head = event({ at: timeAt(msg.head.length - 1), layer: 'http', kind: kinds.head, dir, buffer, ...msg.head, summary: headSummary(msg), detail });
  const { body, extra, problems } = msg;
  const bodyProblem = body.framing === 'invalid' || body.complete === false ? problems[0] : null;
  const events = [head];
  if (body.length > 0 || bodyProblem) {
    events.push(event({
      at: timeAt(Math.max(body.offset + body.length, msg.head.length) - 1), layer: 'http', kind: kinds.body, dir, buffer,
      offset: body.offset, length: body.length, summary: `body ${body.length} B (${body.framing})`,
      detail: { framing: body.framing, declaredLength: body.declaredLength, complete: body.complete },
      ...(bodyProblem ? damage(bodyProblem) : {}),
    }));
  }
  if (extra) {
    events.push(event({
      at: timeAt(extra.offset + extra.length - 1), layer: 'http', kind: 'extra-bytes', dir, buffer, ...extra,
      summary: `${extra.length} B after the message`, ...damage(problems.at(-1)),
    }));
  }
  return events;
}

function httpDirection(dir, side, bounds) {
  const data = side.appData;
  if (data.length === 0) return [];
  const buffer = `http/${dir}`;
  const timeAt = (pos) => plaintextTime(side, bounds, pos);
  try {
    return messageEvents(parseHttpMessage(data), dir, buffer, timeAt);
  } catch (err) {
    return [event({
      at: timeAt(data.length - 1), layer: 'http', kind: 'message', dir, buffer, length: data.length,
      summary: 'damaged HTTP message', ...damage(err.message),
    })];
  }
}

function httpPart(decrypted, bounds) {
  if (decrypted.error) return { buffers: [], events: [] };
  return {
    buffers: [['http/out', decrypted.client.appData], ['http/in', decrypted.server.appData]],
    events: [...httpDirection('out', decrypted.client, bounds.out), ...httpDirection('in', decrypted.server, bounds.in)],
  };
}

// ---- assembly --------------------------------------------------------------------------------

const roundUs = (ms) => Math.round(ms * 1000) / 1000;

function decryptOrExplain(tls) {
  try {
    return decryptSession({ raw: tls.raw, keylog: tls.keylog });
  } catch (err) {
    return { error: err.message };
  }
}

/** session: as returned by loadSession(). */
export function buildTimeline(session) {
  const decrypted = decryptOrExplain(session.tls);
  const bounds = { out: chunkBounds(session.tls.raw, 'out'), in: chunkBounds(session.tls.raw, 'in') };
  const parts = [dnsPart(session.dns), tcpPart(session.tls, bounds), tlsPart(session.tls, decrypted, bounds), httpPart(decrypted, bounds)];
  const all = parts.flatMap((p) => p.events);
  const missing = all.find((e) => !Number.isFinite(e.at));
  if (missing) throw new Error(`${missing.layer}/${missing.kind} has no timestamp in this recording`);

  const origin = all.reduce((min, e) => Math.min(min, e.at), Infinity); // no spread: sessions can have 100k+ events
  // Single choke point: every summary/problem/detail string is made printable here.
  const events = all
    .map((e, index) => ({
      t: roundUs(e.at - origin), ...e, index,
      summary: printable(e.summary), problem: e.problem === null ? null : printable(e.problem), detail: printableDeep(e.detail),
    }))
    .sort((a, b) => a.t - b.t || LAYER_ORDER[a.layer] - LAYER_ORDER[b.layer] || a.index - b.index)
    .map(({ index, ...e }) => e);
  return { origin, buffers: Object.fromEntries(parts.flatMap((p) => p.buffers)), events };
}
