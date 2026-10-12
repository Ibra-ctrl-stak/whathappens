// A pcapng capture of our own connection, matched against a recording: real TCP segments with
// their flags/seq/ack, payload tied to the recorded tcp/out|in bytes only where it verifiably
// matches, cautious diagnostics, and an explicit rule for aligning the two clocks.
import { readPcapng } from './pcapng.js';
import { decodeTcp } from './ipv4-tcp.js';

const MOD = 2 ** 32;
const HALF = 2 ** 31;
const LARGE_CLOCK_GAP_MS = 10 * 60 * 1000;
const MAX_LISTED = 5;

const endpoint = (e) => `${e.address}:${e.port}`;
const sameEnd = (a, b) => a.address === b.address && a.port === b.port;
const rel32 = (seq, base) => (seq - base + MOD) % MOD;

function recordedStreams(raw) {
  const join = (dir) => Buffer.concat(raw.filter((c) => c.dir === dir).map((c) => c.bytes));
  return { out: join('out'), in: join('in') };
}

/** Connections on one address/port pair, split at client SYNs with a new ISN. */
function splitConnections(packets, local) {
  const connections = [];
  let current = null;
  for (const p of packets) {
    const clientSyn = sameEnd(p.src, local) && p.flags.includes('SYN') && !p.flags.includes('ACK');
    if (!current || (clientSyn && current.clientIsn !== p.seq)) {
      current = { clientIsn: clientSyn ? p.seq : null, packets: [] };
      connections.push(current);
    }
    current.packets.push(p);
  }
  return connections;
}

/** First data byte's sequence number for one direction: from its SYN, else from a unique payload match. */
function anchorFor(packets, stream) {
  const syn = packets.find((p) => p.flags.includes('SYN'));
  if (syn) return { base: (syn.seq + 1) % MOD, source: 'SYN' };
  const first = packets.find((p) => p.payload.length > 0);
  if (!first) return { base: null, reason: 'no SYN and no payload in this direction' };
  const at = stream.indexOf(first.payload);
  if (at < 0) return { base: null, reason: 'no SYN, and the first captured payload is not found in the recording' };
  if (stream.indexOf(first.payload, at + 1) >= 0) return { base: null, reason: 'no SYN, and the first captured payload occurs more than once in the recording' };
  return { base: (first.seq - at + MOD) % MOD, source: 'payload match (capture started mid-connection)' };
}

function mappingFor(p, rel, stream) {
  const len = p.payloadLength;
  if (len === 0) return { status: 'none' };
  if (rel === null) return { status: 'unverified', reason: 'no sequence anchor for this direction' };
  if (p.payloadTruncated) return { status: 'partly captured', reason: `only ${p.payload.length} of ${len} payload bytes were captured` };
  if (rel >= HALF || rel + len > stream.length) {
    return { status: 'outside the recording', reason: `bytes ${rel >= HALF ? rel - MOD : rel}..${(rel >= HALF ? rel - MOD : rel) + len} lie outside the ${stream.length} recorded bytes` };
  }
  return stream.subarray(rel, rel + len).equals(p.payload)
    ? { status: 'matches', offset: rel, length: len }
    : { status: 'does not match the recorded stream', reason: 'the captured payload differs from the recorded bytes at this offset' };
}

/** Observations about one payload range against what this direction showed before (capture order). */
function observe(state, start, end) {
  const notes = [];
  const overlap = state.intervals.reduce((n, [a, b]) => n + Math.max(0, Math.min(b, end) - Math.max(a, start)), 0);
  const length = end - start;
  if (state.seenEnd !== null && start > state.seenEnd) {
    notes.push(`gap: bytes ${state.seenEnd}..${start} of this direction have not appeared in the capture before this segment (not by itself proof of loss)`);
  }
  if (overlap === length) notes.push('every byte of this range already appeared in the capture: repeated range, likely a retransmission (inferred)');
  else if (overlap > 0) notes.push(`${overlap} of its ${length} bytes already appeared in the capture: overlaps an earlier segment`);
  else if (state.seenEnd !== null && start < state.seenEnd) notes.push('arrived out of order: it fills bytes below the highest sequence already seen');
  state.intervals = [...state.intervals, [start, end]].sort((a, b) => a[0] - b[0]).reduce((acc, [a, b]) => {
    const last = acc.at(-1);
    if (last && a <= last[1]) last[1] = Math.max(last[1], b);
    else acc.push([a, b]);
    return acc;
  }, []);
  state.seenEnd = Math.max(state.seenEnd ?? 0, end);
  return notes;
}

function analyzeConnection(connection, local, streams) {
  const dirOf = (p) => (sameEnd(p.src, local) ? 'out' : 'in');
  const anchors = Object.fromEntries(['out', 'in'].map((dir) => [dir, anchorFor(connection.packets.filter((p) => dirOf(p) === dir), streams[dir])]));
  const state = { out: { seenEnd: null, intervals: [] }, in: { seenEnd: null, intervals: [] } };
  const flagSeqs = { out: new Set(), in: new Set() };
  const segments = connection.packets.map((p) => {
    const dir = dirOf(p);
    const other = dir === 'out' ? 'in' : 'out';
    const { base } = anchors[dir];
    const rel = base === null ? null : rel32(p.seq, base);
    const notes = [];
    for (const flag of ['SYN', 'FIN']) {
      if (!p.flags.includes(flag)) continue;
      const key = `${flag}:${p.seq}`;
      if (flagSeqs[dir].has(key)) notes.push(`repeated ${flag} with the same sequence number: likely a retransmission (inferred)`);
      flagSeqs[dir].add(key);
    }
    if (rel !== null && rel < HALF && p.payloadLength > 0) notes.push(...observe(state[dir], rel, rel + p.payloadLength));
    const ackBase = anchors[other].base;
    return {
      frame: p.frame, dir, timeMs: p.timeMs, captureTime: p.captureTime, flags: p.flags,
      seq: rel === null ? null : rel >= HALF ? rel - MOD : rel, rawSeq: p.seq,
      ack: p.flags.includes('ACK') && ackBase !== null ? rel32(p.ack, ackBase) : null, rawAck: p.flags.includes('ACK') ? p.ack : null,
      window: p.window, options: p.options, payloadLength: p.payloadLength,
      mapping: mappingFor(p, rel, streams[dir]), notes,
    };
  });
  return { segments, anchors };
}

function alignment(segments, raw) {
  const firstWrite = raw.find((c) => c.dir === 'out')?.at;
  const anchor = segments.find((s) => s.dir === 'out' && s.mapping.status === 'matches' && s.mapping.offset === 0);
  if (!anchor || !Number.isFinite(firstWrite)) {
    return {
      status: 'unaligned', offsetMs: 0,
      rule: 'No captured segment carries the verified first byte of the ClientHello, so the capture clock is used as is; it may differ from the recording clock.',
    };
  }
  const offsetMs = firstWrite - anchor.timeMs;
  return {
    status: 'aligned', offsetMs, anchorFrame: anchor.frame,
    rule: `Capture times are shifted by ${offsetMs.toFixed(3)} ms so that frame ${anchor.frame} (the first byte of the ClientHello) `
      + 'coincides with the moment Node handed those bytes to the socket. The packet leaves somewhat later, so times near the '
      + 'start are approximate; the shift is one constant and does not correct clock drift.',
    ...(Math.abs(offsetMs) > LARGE_CLOCK_GAP_MS ? { warning: 'the clocks differ by more than 10 minutes: check that this capture belongs to this recording' } : {}),
  };
}

function counts(segments) {
  const has = (re) => segments.filter((s) => s.notes.some((n) => re.test(n))).length;
  return {
    segments: segments.length,
    matched: segments.filter((s) => s.mapping.status === 'matches').length,
    notMatching: segments.filter((s) => s.mapping.status === 'does not match the recorded stream').length,
    repeated: has(/likely a retransmission/), outOfOrder: has(/out of order/), overlapping: has(/overlaps/), gaps: has(/^gap/),
  };
}

/**
 * buf: a pcapng file; session: loadSession(...) output. Never throws: returns
 * { status: 'matched' | 'no-match' | 'ambiguous' | 'unreadable', reason, segments, alignment, reader, ... }.
 */
export function analyzeCapture(buf, session, { limits } = {}) {
  let read;
  try {
    read = readPcapng(buf, limits);
  } catch (err) {
    return { status: 'unreadable', reason: err.message, segments: [], alignment: null, reader: null };
  }
  const skipped = {};
  const tcps = [];
  for (const p of read.packets) {
    const decoded = decodeTcp(p);
    if (decoded.skip) skipped[decoded.skip] = (skipped[decoded.skip] ?? 0) + 1;
    else tcps.push({ ...decoded.tcp, frame: p.frame, timeMs: p.timeMs, captureTime: p.captureTime });
  }
  const reader = { packets: read.packets.length, truncated: read.truncated, problems: read.problems.slice(0, 20), skipped };
  const local = session.tls?.local;
  const remote = { address: session.tls?.ip, port: session.tls?.port ?? 443 };
  const fail = (status, reason, extra = {}) => ({ status, reason, segments: [], alignment: null, reader, ...extra });
  if (!local?.address || !local?.port || !remote.address) return fail('no-match', 'the recording has no local and remote address to match');

  const pair = `${endpoint(local)} <-> ${endpoint(remote)}`;
  const ours = tcps.filter((t) => (sameEnd(t.src, local) && sameEnd(t.dst, remote)) || (sameEnd(t.src, remote) && sameEnd(t.dst, local)));
  if (ours.length === 0) {
    const elsewhere = [...new Set(tcps.filter((t) => sameEnd(t.dst, remote)).map((t) => endpoint(t.src)))];
    return fail('no-match', elsewhere.length
      ? `no TCP packets between ${pair}; ${remote.address}:${remote.port} is reached from ${elsewhere.slice(0, MAX_LISTED).join(', ')} instead — the capture may come from another interface (VPN, NAT) or another connection`
      : `no TCP packets between ${pair} in this capture`);
  }
  const streams = recordedStreams(session.tls.raw);
  const candidates = splitConnections(ours, local).map((c) => ({ ...c, ...analyzeConnection(c, local, streams) }));
  const evidence = (c) => c.segments.filter((s) => s.dir === 'out' && s.mapping.status === 'matches').length;
  let chosen;
  let reason;
  if (candidates.length === 1) {
    [chosen] = candidates;
    reason = `the only connection between ${pair} in the capture`;
  } else {
    const verified = candidates.filter((c) => evidence(c) > 0);
    const list = candidates.slice(0, MAX_LISTED).map((c) => `from frame ${c.packets[0].frame} (${c.packets.length} packets)`).join(', ');
    if (verified.length !== 1) {
      return fail('ambiguous', `${candidates.length} connections use ${pair} (${list}); ${verified.length === 0 ? 'none' : verified.length} of them carry client bytes matching the recording, so none is chosen`);
    }
    [chosen] = verified;
    reason = `${candidates.length} connections use ${pair}; chosen the one from frame ${chosen.packets[0].frame}, whose client payload matches the recorded stream`;
  }
  const align = alignment(chosen.segments, session.tls.raw);
  const segments = chosen.segments.map((s) => ({ ...s, timeMs: s.timeMs + align.offsetMs, offsetMs: align.offsetMs }));
  const anchorNotes = Object.entries(chosen.anchors).map(([dir, a]) => `${dir}: sequence anchor ${a.base === null ? `missing (${a.reason})` : `from ${a.source}`}`);
  return {
    status: 'matched', reason, local, remote, segments, alignment: align, reader,
    connection: { firstFrame: chosen.packets[0].frame, packets: chosen.packets.length, candidates: candidates.length, anchors: anchorNotes },
    counts: counts(segments),
  };
}
