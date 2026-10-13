// One timeline for a recorded session: DNS -> TCP -> TLS -> HTTP.
// Every event points at bytes we recorded: { buffer, offset, length }. Events with no bytes we
// could see (TCP connect/close, a lost datagram) say so with buffer null and length 0.
// Nothing broken is hidden: what cannot be parsed or decrypted becomes an event with
// damaged: true and a problem, over the bytes it occupies; the other layers stay intact.
import { parseResponse, TYPE } from './dns/packet.js';
import { decryptSession } from './tls/decrypt.js';
import { parseHttpMessage, parseHttpResponses, headerValue } from './http/message.js';
import { decodeHttpBody } from './http/body.js';
import { field } from './fields.js';
import { httpFields, httpResponseFields } from './http/fields.js';
import { recordFields } from './tls/record-fields.js';
import { parseHandshake } from './tls/handshake-fields.js';
import { handshakeChecks } from './tls/certificates.js';
import { printable, printableDeep } from './text.js';

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

// fields: the parsed field tree of exactly this event's bytes, or null when nothing was parsed.
// checks: results of our own verifications about this event (see serverChecks), or null.
// capture: data about a packet from an optional pcapng capture (see capturePart), or null.
const event = (props) => ({ dir: null, buffer: null, offset: 0, length: 0, detail: {}, fields: null, checks: null, capture: null, damaged: false, problem: null, ...props });
const CERTIFICATE_MESSAGE = 11;
const CERTIFICATE_VERIFY_MESSAGE = 15;
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

// A DNS event whose time was never recorded keeps at: null and says so (see buildTimeline).
const untimed = (at) => (at === null || at === undefined ? '; no time recorded' : '');

function dnsPart(dns) {
  const parts = dns.map((e, i) => {
    const qId = `dns/${i}/query`;
    const asked = `A? ${e.qname} -> ${e.server.name} (${e.server.ip})`;
    const detail = { server: e.server, localPort: e.localPort, id: e.query.readUInt16BE(0) };
    if (e.sentAt === null && !e.response) {
      // Failed before the socket was bound: the query was built but never sent.
      const at = e.failedAt ?? null;
      const notSent = bytesEvent(qId, e.query, { at, layer: 'dns', kind: 'not-sent', dir: 'out', summary: `${asked} not sent: ${e.error}${untimed(at)}`, detail });
      return { buffers: [[qId, e.query]], events: [notSent] };
    }
    const query = bytesEvent(qId, e.query, { at: e.sentAt, layer: 'dns', kind: 'query', dir: 'out', summary: asked, detail });
    if (!e.response) {
      const at = e.failedAt ?? null;
      const lost = event({ at, layer: 'dns', kind: 'lost', summary: `no answer from ${e.server.name}: ${e.error}${untimed(at)}`, detail: { server: e.server, localPort: e.localPort } });
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

function tcpPart(tls, bounds, streams) {
  const remote = `${tls.ip}:${tls.port}`;
  const chunks = ['out', 'in'].flatMap((dir) =>
    bounds[dir].map((b) => event({
      at: b.at, layer: 'tcp', kind: dir === 'out' ? 'write' : 'read', dir, buffer: `tcp/${dir}`,
      offset: b.start, length: b.bytes.length, summary: `${dir === 'out' ? 'sent' : 'received'} ${b.bytes.length} B`,
    })),
  );
  const t = tls.times;
  return {
    buffers: ['out', 'in'].map((dir) => [`tcp/${dir}`, streams[dir]]),
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

function recordEvent(dir, r, bounds, streams) {
  return event({
    at: timeAtByte(bounds[dir], recordEnd(r)), layer: 'tls', kind: 'record', dir, buffer: `tcp/${dir}`,
    offset: r.offset, length: RECORD_HEADER_LEN + r.length, summary: describeRecord(r),
    fields: recordFields(streams[dir], r.offset, RECORD_HEADER_LEN + r.length),
    detail: {
      epoch: r.epoch, seq: r.seq ?? null, outerType: r.outerType, contentType: r.contentType,
      handshakeTypes: r.handshakeTypes ?? [], plaintextLength: r.content?.length ?? 0, appDataOffset: r.appDataOffset ?? null,
    },
    ...(r.damaged ? damage(r.problem) : {}),
  });
}

/**
 * Bytes after the last whole record, shown and flagged: the stream ended mid-record, or (problem)
 * a record header that cannot be valid, after which records cannot be found again.
 */
function incompleteRecordEvent(dir, streamLength, trailing, bounds, problem) {
  return event({
    at: timeAtByte(bounds[dir], streamLength - 1), layer: 'tls', kind: 'record', dir, buffer: `tcp/${dir}`,
    offset: streamLength - trailing, length: trailing, summary: problem ? 'invalid record' : 'incomplete record',
    ...damage(problem ? `invalid record: ${problem}; the remaining ${trailing} bytes are not split into records`
      : `incomplete record: ${trailing} bytes, the stream ended mid-record`),
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

/**
 * One event per handshake message, over the direction's handshake stream (buffer tls-hs/<dir>),
 * timed by the record that delivered its last byte.
 */
function handshakeMessageEvents(dir, side, bounds, checksFor = () => null) {
  return side.messages.map((m) => {
    const last = m.offset + m.length - 1;
    const r = side.records.find((rec) => rec.handshakeOffset !== undefined && last < rec.handshakeOffset + rec.content.length);
    const fields = parseHandshake(side.handshake, m);
    return event({
      at: timeAtByte(bounds[dir], recordEnd(r)), layer: 'tls', kind: 'handshake-message', dir, buffer: `tls-hs/${dir}`,
      offset: m.offset, length: m.length, summary: fields.name, detail: { type: m.type }, fields, checks: checksFor(m),
      ...(fields.problem ? damage(fields.problem) : {}),
    });
  });
}

/**
 * Our own checks, attached to the server's Certificate and CertificateVerify messages. They are
 * computed results, not traffic: no bytes or time of their own. A failure to compute them is
 * reported as "unavailable", never as success, and never breaks the timeline.
 */
function serverChecks(decrypted) {
  let checks;
  try {
    checks = handshakeChecks(decrypted);
  } catch (err) {
    const unavailable = (id, title) => ({ id, title, status: 'unavailable', explanation: '', reason: `could not run the check: ${err.message}`, steps: [], notCovered: [] });
    checks = { chain: unavailable('certificate-chain', 'Certificate chain signatures'), certificateVerify: unavailable('certificate-verify', 'CertificateVerify signature') };
  }
  return (m) => (m.type === CERTIFICATE_MESSAGE ? [checks.chain] : m.type === CERTIFICATE_VERIFY_MESSAGE ? [checks.certificateVerify] : null);
}

function tlsPart(tls, decrypted, bounds, streams) {
  if (decrypted.error) return undecodableStreams(tls, bounds, decrypted.error);
  const sides = [['out', decrypted.client, 'client'], ['in', decrypted.server, 'server']];
  const checksFor = serverChecks(decrypted);
  const records = sides.flatMap(([dir, side, name]) => {
    const trailing = decrypted.trailingBytes[name];
    const streamLength = bounds[dir].at(-1)?.end ?? 0;
    const tail = trailing > 0 ? [incompleteRecordEvent(dir, streamLength, trailing, bounds, decrypted.trailingProblems[name])] : [];
    const messages = handshakeMessageEvents(dir, side, bounds, dir === 'in' ? checksFor : undefined);
    return [...side.records.map((r) => recordEvent(dir, r, bounds, streams)), ...tail, ...messages];
  });
  const { protocol, cipher, alpn } = tls.info;
  const secure = event({ at: tls.times.secureAt, layer: 'tls', kind: 'secure', summary: `${protocol} ${cipher.standardName}, ALPN ${alpn}` });
  return { buffers: [['tls-hs/out', decrypted.client.handshake], ['tls-hs/in', decrypted.server.handshake]], events: [...records, secure] };
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

const headEnd = (msg) => msg.head.offset + msg.head.length; // absolute, in the direction's stream

function messageEvents(msg, tree, dir, buffer, timeAt) {
  const kinds = HTTP_KINDS[dir];
  const part = (name) => tree.children.find((f) => f.name === name) ?? null;
  const detail = msg.kind === 'request'
    ? { headers: msg.headers.length, host: headerValue(msg, 'host') ?? null }
    : { status: msg.startLine.status, headers: msg.headers.length };
  const head = event({
    at: timeAt(headEnd(msg) - 1), layer: 'http', kind: kinds.head, dir, buffer, ...msg.head, summary: headSummary(msg), detail, fields: part('head'),
  });
  const { body, extra, problems } = msg;
  const bodyProblem = problems.filter((p) => !/bytes after/.test(p)).join('; ') || null;
  const events = [head];
  if (body.length > 0 || bodyProblem) {
    events.push(event({
      at: timeAt(Math.max(body.offset + body.length, headEnd(msg)) - 1), layer: 'http', kind: kinds.body, dir, buffer,
      offset: body.offset, length: body.length, summary: `body ${body.length} B (${body.framing})`,
      detail: { framing: body.framing, declaredLength: body.declaredLength, complete: body.complete },
      fields: part('body'), // null for a zero-length body flagged only for its problem
      ...(bodyProblem ? damage(bodyProblem) : {}),
    }));
  }
  if (extra) {
    events.push(event({
      at: timeAt(extra.offset + extra.length - 1), layer: 'http', kind: 'extra-bytes', dir, buffer, ...extra,
      summary: `${extra.length} B after the message`, fields: part('extra'), ...damage(problems.at(-1)),
    }));
  }
  return events;
}

/** Events of one complete message (head, body, extra) plus its decoded body, if any. */
function fullMessageEvents(data, msg, tree, dir, timeAt, buffers) {
  const buffer = `http/${dir}`;
  const events = messageEvents(msg, tree, dir, buffer, timeAt);
  const decoded = decodeHttpBody(data, msg);
  const bodyEvent = events.find((e) => e.kind === HTTP_KINDS[dir].body);
  if (decoded.problem && bodyEvent && !bodyEvent.damaged) {
    Object.assign(bodyEvent, damage(decoded.problem));
  }
  if (decoded.problem && !bodyEvent) {
    events.push(event({
      at: timeAt(headEnd(msg) - 1), layer: 'http', kind: HTTP_KINDS[dir].body,
      dir, buffer, offset: msg.body.offset, length: msg.body.length,
      summary: 'body decoding unavailable', ...damage(decoded.problem),
    }));
  }
  if (decoded.transformed) {
    const id = `http-decoded/${dir}`;
    buffers.push([id, decoded.bytes]);
    events.push(event({
      at: timeAt(Math.max(msg.body.offset + msg.body.length, headEnd(msg)) - 1),
      layer: 'http', kind: 'decoded-body', dir, buffer: id, length: decoded.bytes.length,
      summary: `decoded body ${decoded.bytes.length} B (chunked/gzip removed; derived bytes)`,
      fields: field('decoded_body', 0, decoded.bytes.length),
    }));
  }
  return events;
}

/** Our request: one message in http/out. */
function requestEvents(side, bounds, buffers) {
  const data = side.appData;
  if (data.length === 0) return [];
  const timeAt = (pos) => plaintextTime(side, bounds, pos);
  const tree = httpFields(data); // never throws: a broken message is one field with a problem
  if (tree.problem) {
    return [event({
      at: timeAt(data.length - 1), layer: 'http', kind: 'message', dir: 'out', buffer: 'http/out', length: data.length,
      summary: 'damaged HTTP message', fields: tree, ...damage(tree.problem),
    })];
  }
  return fullMessageEvents(data, parseHttpMessage(data), tree, 'out', timeAt, buffers);
}

/** A head-only response (1xx): one event over its head. */
function headOnlyEvent(msg, node, kind, summary, timeAt, extra = {}) {
  return event({
    at: timeAt(headEnd(msg) - 1), layer: 'http', kind, dir: 'in', buffer: 'http/in', ...msg.head, summary,
    detail: { status: msg.startLine.status, headers: msg.headers.length }, fields: node.children[0], ...extra,
  });
}

/** Bytes after the last parsed response that could not be parsed (or an empty marker at the end). */
function unparsedEvent(rest, node, dataLength, timeAt) {
  return event({
    at: timeAt(Math.min(rest.offset + rest.length, dataLength) - 1), layer: 'http', kind: 'message', dir: 'in',
    buffer: 'http/in', offset: rest.offset, length: rest.length, fields: node ?? null,
    summary: rest.length > 0 ? `${rest.length} B not parsed as HTTP` : 'no final response', ...damage(rest.problem),
  });
}

/**
 * The server's side: interim (1xx) heads, then the final response with body and decoded body;
 * a 101 is shown and not followed. Earlier responses survive a broken or truncated later one.
 */
function responseEvents(side, bounds, buffers) {
  const data = side.appData;
  if (data.length === 0) return [];
  const timeAt = (pos) => plaintextTime(side, bounds, pos);
  const seq = parseHttpResponses(data);
  const tree = httpResponseFields(data, seq);
  const nodes = new Map(tree.children.map((n) => [n.offset, n]));
  const events = seq.interim.map((m) => headOnlyEvent(m, nodes.get(m.head.offset), 'interim-response',
    `${m.startLine.status} ${m.startLine.reason} (interim response, no body)`, timeAt));
  if (seq.switched) {
    const m = seq.switched;
    events.push(headOnlyEvent(m, nodes.get(m.head.offset), 'protocol-switch', `${m.startLine.status} ${m.startLine.reason}`, timeAt,
      damage('101 Switching Protocols: switching to another protocol is not supported')));
  }
  if (seq.final) {
    const node = nodes.get(seq.final.head.offset);
    events.push(...fullMessageEvents(data, seq.final, node, 'in', timeAt, buffers));
  }
  if (seq.rest) events.push(unparsedEvent(seq.rest, seq.rest.length > 0 ? nodes.get(seq.rest.offset) : null, data.length, timeAt));
  return events;
}

function httpPart(decrypted, bounds) {
  if (decrypted.error) return { buffers: [], events: [] };
  const buffers = [['http/out', decrypted.client.appData], ['http/in', decrypted.server.appData]];
  const events = [...requestEvents(decrypted.client, bounds.out, buffers), ...responseEvents(decrypted.server, bounds.in, buffers)];
  return { buffers, events };
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
// ---- TCP segments from an optional capture ------------------------------------------------------

function segmentSummary(s) {
  const seq = s.flags.includes('SYN') ? `ISN=${s.rawSeq}` : `seq=${s.seq ?? `raw ${s.rawSeq}`}`;
  const ack = s.ack !== null ? ` ack=${s.ack}` : s.rawAck !== null ? ` ack=raw ${s.rawAck}` : '';
  const check = s.mapping.status === 'matches' || s.mapping.status === 'none' ? '' : ` — ${s.mapping.status}`;
  return `captured packet #${s.frame}: ${s.flags.join(', ') || 'no flags'} ${seq}${ack} len=${s.payloadLength} win=${s.window}${check}`;
}

/**
 * Real TCP segments of our connection, from analyzeCapture(...) (src/pcap/connection.js). Only
 * verified payload ranges point into tcp/out|in; SYN/ACK/FIN without payload get no bytes.
 */
function capturePart(capture, tls) {
  if (!capture) return { buffers: [], events: [] };
  const { segments, alignment: align } = capture;
  const incomplete = capture.source?.complete === false ? 'INCOMPLETE ' : '';
  const summary = capture.status === 'matched'
    ? `${incomplete}capture: ${segments.length} TCP segments of ${capture.reason}; time ${align.status === 'aligned' ? `aligned by frame ${align.anchorFrame}` : 'not aligned'}`
    : `${incomplete}capture not used (${capture.status}): ${capture.reason}`;
  // Without a reliable clock alignment, capture events get no place on the shared time axis
  // (at: null): they are listed after the recording, in capture order, never at an invented time.
  const aligned = align?.status === 'aligned';
  const overview = event({
    at: aligned ? segments[0].timeMs : null, layer: 'tcp', kind: 'capture', summary,
    capture: { status: capture.status, reason: capture.reason, alignment: align, reader: capture.reader, connection: capture.connection ?? null, counts: capture.counts ?? null, source: capture.source ?? null },
  });
  const events = segments.map((s) => {
    const mapped = s.mapping.status === 'matches';
    const { timeMs, ...data } = s;
    return event({
      at: aligned ? timeMs : null, layer: 'tcp', kind: 'segment', dir: s.dir, summary: segmentSummary(s), capture: data,
      ...(mapped ? { buffer: `tcp/${s.dir}`, offset: s.mapping.offset, length: s.mapping.length } : {}),
    });
  });
  return { buffers: [], events: [overview, ...events] };
}

/** session: loadSession(...) output; capture: optional analyzeCapture(...) result for this session. */
export function buildTimeline(session, { capture = null } = {}) {
  const decrypted = decryptOrExplain(session.tls);
  const bounds = { out: chunkBounds(session.tls.raw, 'out'), in: chunkBounds(session.tls.raw, 'in') };
  // Parts are listed in layer order; with the index tie-break, equal times keep DNS < TCP < TLS < HTTP.
  const streams = { out: Buffer.concat(bounds.out.map((b) => b.bytes)), in: Buffer.concat(bounds.in.map((b) => b.bytes)) };
  const parts = [
    dnsPart(session.dns), tcpPart(session.tls, bounds, streams), capturePart(capture, session.tls), tlsPart(session.tls, decrypted, bounds, streams), httpPart(decrypted, bounds),
  ];
  const all = parts.flatMap((p) => p.events);
  // Only events from an unaligned capture (capturePart) and DNS failures recorded without a time
  // (dnsPart) may lack a time; anything else must have one.
  const untimedAllowed = (e) => e.at === null && (e.capture !== null || (e.layer === 'dns' && (e.kind === 'not-sent' || e.kind === 'lost')));
  const missing = all.find((e) => !Number.isFinite(e.at) && !untimedAllowed(e));
  if (missing) throw new Error(`${missing.layer}/${missing.kind} has no timestamp in this recording`);

  const origin = all.reduce((min, e) => (e.at === null ? min : Math.min(min, e.at)), Infinity); // no spread: sessions can have 100k+ events
  // Single choke point: every summary/problem/detail string is made printable here.
  const prepared = all.map((e, index) => ({
    t: e.at === null ? null : roundUs(e.at - origin), ...e, index,
    summary: printable(e.summary), problem: e.problem === null ? null : printable(e.problem), detail: printableDeep(e.detail), fields: printableDeep(e.fields), checks: printableDeep(e.checks), capture: printableDeep(e.capture),
  }));
  // Timed events in time order, then untimed ones (unaligned capture, DNS without a time) in their own order.
  const events = [
    ...prepared.filter((e) => e.t !== null).sort((a, b) => a.t - b.t || a.index - b.index),
    ...prepared.filter((e) => e.t === null),
  ].map(({ index, ...e }) => e);
  return { origin, buffers: Object.fromEntries(parts.flatMap((p) => p.buffers)), events };
}
