// TCP segments from a pcapng capture of our own connection: matched, tied to recorded bytes only
// where verified, diagnosed cautiously, with an explicit clock-alignment rule.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { analyzeCapture } from '../src/pcap/connection.js';
import { buildTimeline } from '../src/timeline.js';
import { flowFromSession, toPcapng, ipv4Tcp } from './helpers/tcp-capture-build.mjs';

const fixture = (name) => readFileSync(new URL(`./fixtures/github-robots/${name}`, import.meta.url));
const session = loadSession(JSON.parse(fixture('session.json')));
const oracle = JSON.parse(fixture('expected-capture.json'));
const FLAG_BITS = { FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16, URG: 32, ECE: 64, CWR: 128 };
const flagBits = (flags) => flags.reduce((n, f) => n + FLAG_BITS[f], 0);
const analyze = (packets, opts) => analyzeCapture(toPcapng(packets, opts), session);
const notesOf = (a) => a.segments.flatMap((s) => s.notes);

// ---- the real capture of the reference connection, against tshark ---------------------------

const real = analyzeCapture(fixture('capture.pcapng'), session);

test('real capture: our connection matched; every frame read; no reader problems', () => {
  assert.equal(real.status, 'matched', real.reason);
  assert.deepEqual([real.segments.length, real.reader.packets, real.reader.problems, real.reader.truncated], [oracle.frames.length, oracle.frames.length, [], false]);
});

test('real capture: frame, addresses, raw seq/ack, flags, window, length, options and time match tshark', () => {
  real.segments.forEach((s, i) => {
    const o = oracle.frames[i];
    const ends = s.dir === 'out' ? [`${session.tls.local.address}:${session.tls.local.port}`, `${session.tls.ip}:443`] : [`${session.tls.ip}:443`, `${session.tls.local.address}:${session.tls.local.port}`];
    assert.deepEqual([s.frame, ...ends, s.rawSeq, s.rawAck ?? 0, flagBits(s.flags), s.window, s.payloadLength], [o.frame, o.src, o.dst, o.seq, o.ack, o.flags, o.window, o.len], `frame ${o.frame}`);
    assert.equal(s.options.mss ?? null, o.mss);
    assert.equal(s.options.windowScale ?? null, o.windowScale);
    assert.equal(s.captureTime, new Date(Number(o.timeEpoch.split('.')[0]) * 1000).toISOString().replace(/\.000Z$/, `.${o.timeEpoch.split('.')[1]}Z`));
  });
});

test('real capture: every payload byte verifies against the recording; the clock is aligned by the ClientHello', () => {
  const payload = real.segments.filter((s) => s.payloadLength > 0);
  assert.ok(payload.every((s) => s.mapping.status === 'matches'));
  assert.equal(real.alignment.status, 'aligned');
  assert.match(real.alignment.rule, /first byte of the ClientHello/);
  const hello = real.segments.find((s) => s.frame === real.alignment.anchorFrame);
  assert.equal(hello.timeMs, session.tls.raw.find((c) => c.dir === 'out').at);
});

// ---- synthetic captures built from the recorded streams -------------------------------------

const flow = flowFromSession(session);
const covered = (a, dir) => a.segments.filter((s) => s.dir === dir && s.mapping.status === 'matches').map((s) => [s.mapping.offset, s.mapping.offset + s.mapping.length]);

test('clean flow: mapped payload covers both recorded streams exactly; SYN/ACK/FIN carry no bytes', () => {
  const a = analyze(flow.packets);
  assert.equal(a.status, 'matched');
  for (const dir of ['out', 'in']) {
    let pos = 0;
    for (const [from, to] of covered(a, dir)) { assert.equal(from, pos); pos = to; }
    assert.equal(pos, flow.streams[dir].length);
  }
  assert.ok(a.segments.filter((s) => s.payloadLength === 0).every((s) => s.mapping.status === 'none'));
  assert.deepEqual(notesOf(a), []);
});

test('sequence numbers wrapping past 2^32 still map to the right offsets', () => {
  const wrapped = flowFromSession(session, { clientIsn: 2 ** 32 - 5, serverIsn: 2 ** 32 - 1000 });
  const a = analyze(wrapped.packets);
  assert.ok(a.segments.filter((s) => s.payloadLength > 0).every((s) => s.mapping.status === 'matches'));
  assert.ok(a.segments.some((s) => s.rawSeq < 1000) && a.segments.some((s) => s.rawSeq > 2 ** 32 - 1000), 'raw seq did wrap');
  assert.deepEqual(covered(a, 'in').at(-1)[1], flow.streams.in.length);
});

const serverData = flow.packets.map((p, i) => [p, i]).filter(([p]) => p.dir === 'in' && p.payloadFrom !== undefined).map(([, i]) => i);

test('a repeated range is reported as a likely retransmission (inferred), still verified', () => {
  const packets = [...flow.packets];
  packets.splice(serverData[3] + 1, 0, { ...packets[serverData[1]], timeMs: packets[serverData[3]].timeMs + 0.5 });
  const a = analyze(packets);
  assert.equal(a.counts.repeated, 1);
  assert.match(notesOf(a).join(), /likely a retransmission \(inferred\)/);
  assert.equal(a.counts.notMatching, 0);
});

test('swapped segments: a gap (not proof of loss) then an out-of-order arrival', () => {
  const packets = [...flow.packets];
  [packets[serverData[1]], packets[serverData[2]]] = [packets[serverData[2]], packets[serverData[1]]];
  const notes = notesOf(analyze(packets)).join('\n');
  assert.match(notes, /gap: .*not by itself proof of loss/);
  assert.match(notes, /arrived out of order/);
  assert.doesNotMatch(notes, /\blost\b/);
});

test('a segment starting inside an earlier one and reaching past it is reported as a partial overlap', () => {
  const next = flow.packets[serverData[2]]; // its range starts right where serverData[1] ends
  const extra = ipv4Tcp({ src: flow.remote, dst: flow.local, seq: 500000 + 1 + next.payloadFrom - 10, ack: 0, flags: ['ACK'], payload: flow.streams.in.subarray(next.payloadFrom - 10, next.payloadFrom + 30) });
  const packets = [...flow.packets];
  packets.splice(serverData[1] + 1, 0, { dir: 'in', data: extra, timeMs: flow.packets[serverData[1]].timeMs + 0.1 });
  const a = analyze(packets);
  assert.match(notesOf(a).join('\n'), /10 of its 40 bytes already appeared in the capture: overlaps an earlier segment/);
  assert.equal(a.counts.repeated, 0, 'a partial overlap is not called a retransmission');
  assert.equal(a.counts.notMatching, 0);
});

test('a payload that differs from the recording is named so, gets no bytes, and is not called damaged', () => {
  const packets = flow.packets.map((p, i) => {
    if (i !== serverData[1]) return p;
    const data = Buffer.from(p.data);
    data[data.length - 5] ^= 0xff;
    return { ...p, data };
  });
  const a = analyze(packets);
  const bad = a.segments.find((s) => s.mapping.status !== 'matches' && s.payloadLength > 0);
  assert.equal(bad.mapping.status, 'does not match the recorded stream');
  const t = buildTimeline(session, { capture: a });
  const event = t.events.find((e) => e.kind === 'segment' && e.capture.frame === bad.frame);
  assert.deepEqual([event.buffer, event.length, event.damaged], [null, 0, false]);
  assert.match(event.summary, /does not match the recorded stream/);
});

test('a capture that started mid-connection anchors by payload; without the ClientHello the clock stays unaligned', () => {
  const packets = flow.packets.filter((p, i) => i > 3 && i !== serverData[0]); // no handshake, no first segments
  const a = analyze(packets);
  assert.equal(a.status, 'matched');
  assert.ok(a.segments.filter((s) => s.payloadLength > 0).every((s) => s.mapping.status === 'matches'));
  assert.match(a.connection.anchors.join(), /payload match \(capture started mid-connection\)/);
  assert.equal(a.alignment.status, 'unaligned');
  assert.match(a.alignment.rule, /capture clock is used as is/);
});

test('two connections on the same address pair: chosen only by matching payload, otherwise ambiguous', () => {
  const other = flowFromSession({ ...session, tls: { ...session.tls, raw: session.tls.raw.map((c) => ({ ...c, bytes: Buffer.alloc(c.bytes.length, 0x41) })) } }, { clientIsn: 77777 });
  const later = (ps, ms) => ps.map((p) => ({ ...p, timeMs: p.timeMs + ms }));
  const chosen = analyze([...later(other.packets, -5000), ...flow.packets]);
  assert.equal(chosen.status, 'matched');
  assert.match(chosen.reason, /2 connections use .*whose client payload matches/);
  const twin = flowFromSession(session, { clientIsn: 88888 });
  const ambiguous = analyze([...later(twin.packets, -5000), ...flow.packets]);
  assert.equal(ambiguous.status, 'ambiguous');
  assert.match(ambiguous.reason, /2 connections use .*none is chosen/);
});

test('packets to the server from another local address are not matched, with a hint', () => {
  const elsewhere = { ...flow.local, address: '192.168.1.189' };
  const packets = [{ dir: 'out', timeMs: 1, data: ipv4Tcp({ src: elsewhere, dst: flow.remote, seq: 1, flags: ['SYN'] }) }];
  const a = analyze(packets);
  assert.equal(a.status, 'no-match');
  assert.match(a.reason, /192\.168\.1\.189:\d+ instead .*another interface/);
});

test('microsecond, nanosecond and binary resolutions give the same aligned times; raw capture times are kept', () => {
  const runs = [6, 9, 0x80 | 30].map((tsresol) => analyze(flow.packets, { tsresol }));
  for (const a of runs) assert.equal(a.alignment.status, 'aligned');
  const times = runs.map((a) => a.segments.map((s) => s.timeMs));
  for (const t of times.slice(1)) t.forEach((ms, i) => assert.ok(Math.abs(ms - times[0][i]) < 0.002, `${ms} vs ${times[0][i]}`));
  assert.ok(runs.every((a) => a.segments.every((s) => typeof s.captureTime === 'string' && Number.isFinite(s.offsetMs))));
});

test('a file cut inside its last block: segments read so far are kept, truncation is reported', () => {
  const file = toPcapng(flow.packets);
  const a = analyzeCapture(file.subarray(0, file.length - 20), session);
  assert.equal(a.reader.truncated, true);
  assert.equal(a.segments.length, flow.packets.length - 1);
});

test('IP fragments and payloads cut by snaplen are not taken as verified TCP data', () => {
  const p = flow.packets[serverData[1]];
  const fragment = { ...p, data: (() => { const d = Buffer.from(p.data); d.writeUInt16BE(0x2000, 6); return d; })() };
  const shortened = { ...flow.packets[serverData[2]], data: flow.packets[serverData[2]].data.subarray(0, 100) };
  const packets = flow.packets.map((x, i) => (i === serverData[1] ? fragment : i === serverData[2] ? shortened : x));
  const a = analyze(packets);
  assert.equal(a.reader.skipped['IPv4 fragment (fragments are not reassembled)'], 1);
  assert.equal(a.segments.find((s) => s.payloadLength > 0 && s.mapping.status === 'partly captured').mapping.status, 'partly captured');
});

test('Ethernet and loopback (NULL) link types decode the same flow', () => {
  for (const link of ['ETHERNET', 'NULL']) {
    const a = analyze(flow.packets, { link });
    assert.equal(a.counts.matched, flow.packets.filter((p) => p.payloadFrom !== undefined).length, link);
  }
});

test('an unreadable file is reported, not thrown', () => {
  const a = analyzeCapture(Buffer.from('nope'), session);
  assert.deepEqual([a.status, a.segments], ['unreadable', []]);
});

// ---- on the timeline ----------------------------------------------------------------------------

test('without a capture the timeline is unchanged: no segment or capture events', () => {
  const t = buildTimeline(session);
  assert.equal(t.events.length, 48);
  assert.ok(!t.events.some((e) => e.kind === 'segment' || e.kind === 'capture'));
});

test('with the real capture: segments are separate from socket reads/writes, and only verified ranges have bytes', () => {
  const t = buildTimeline(session, { capture: real });
  const segments = t.events.filter((e) => e.kind === 'segment');
  assert.equal(segments.length, oracle.frames.length);
  assert.ok(segments.every((e) => e.layer === 'tcp' && /^captured packet #\d+/.test(e.summary)));
  assert.ok(segments.filter((e) => e.capture.payloadLength === 0).every((e) => e.buffer === null && e.length === 0));
  for (const e of segments.filter((x) => x.buffer)) {
    assert.deepEqual(t.buffers[e.buffer].subarray(e.offset, e.offset + e.length).length, e.capture.payloadLength);
  }
  assert.equal(t.events.filter((e) => e.kind === 'read' || e.kind === 'write').length, buildTimeline(session).events.filter((e) => e.kind === 'read' || e.kind === 'write').length);
  const [overview] = t.events.filter((e) => e.kind === 'capture');
  assert.match(overview.summary, /^capture: 34 TCP segments/);
  assert.equal(overview.capture.alignment.status, 'aligned');
});

// ---- API and CLI --------------------------------------------------------------------------------

test('API: timeline.json carries only the chosen connection, allow-listed, without payload bytes', async (t) => {
  const { openViewer } = await import('../src/viewer.js');
  const foreign = { dir: 'out', timeMs: flow.packets[0].timeMs, data: ipv4Tcp({ src: { address: '10.9.9.9', port: 5555 }, dst: { address: '10.8.8.8', port: 443 }, seq: 1, flags: ['ACK'], payload: Buffer.from('FOREIGN-PAYLOAD') }) };
  const viewer = await openViewer(JSON.parse(fixture('session.json')), { capture: toPcapng([foreign, ...flow.packets]) });
  t.after(() => viewer.close());
  const body = await (await fetch(new URL('timeline.json', viewer.url))).text();
  const view = JSON.parse(body);
  const segments = view.events.filter((e) => e.kind === 'segment');
  assert.equal(segments.length, flow.packets.length);
  assert.deepEqual(Object.keys(segments[0].capture).sort(), ['ack', 'captureTime', 'flags', 'frame', 'mapping', 'notes', 'offsetMs', 'options', 'payloadLength', 'rawAck', 'rawSeq', 'seq', 'window']);
  assert.ok(!body.includes('10.9.9.9') && !body.includes('FOREIGN'), 'nothing of other connections');
  assert.ok(!/"payload"/.test(body), 'no payload field');
  assert.equal(view.events.find((e) => e.kind === 'capture').capture.status, 'matched');
});

test('CLI: --demo --pcap shows the capture result; --pcap with a URL is refused', async () => {
  const { spawn, execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const cli = new URL('../cli.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const pcap = new URL('./fixtures/github-robots/capture.pcapng', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const child = spawn(process.execPath, [cli, '--demo', '--pcap', pcap], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no URL: ${out}`)), 10000);
    child.stdout.on('data', (d) => { out += d; if (/Open http/.test(out)) { clearTimeout(timer); resolve(); } });
    child.once('exit', () => reject(new Error(`exited: ${out}`)));
  });
  child.kill();
  assert.match(out, /Capture: 34 TCP segments .*aligned by the ClientHello/);
  await assert.rejects(promisify(execFile)(process.execPath, [cli, 'github.com', '--pcap', pcap]), /--pcap applies to --session or --demo/);
});

// ---- no invented time, no ambiguous anchor ----------------------------------------------------

test('unaligned capture: segments get no time on the shared timeline; they follow the recording, in frame order', () => {
  const midway = flow.packets.filter((p, i) => i > 3 && i !== serverData[0]);
  const a = analyzeCapture(toPcapng(midway.map((p) => ({ ...p, timeMs: p.timeMs - 3_600_000 }))), session); // another clock
  assert.equal(a.alignment.status, 'unaligned');
  const t = buildTimeline(session, { capture: a });
  const fromCapture = t.events.filter((e) => e.kind === 'segment' || e.kind === 'capture');
  assert.ok(fromCapture.every((e) => e.t === null), 'no time relative to DNS is invented');
  assert.deepEqual([t.events[0].layer, t.events[0].kind, t.events[0].t], ['dns', 'query', 0], 'the timeline still starts at the first DNS query');
  const firstUnaligned = t.events.findIndex((e) => e.t === null);
  assert.ok(t.events.slice(firstUnaligned).every((e) => e.t === null), 'unaligned events come after every timed event');
  const frames = t.events.filter((e) => e.kind === 'segment').map((e) => e.capture.frame);
  assert.deepEqual(frames, [...frames].sort((x, y) => x - y), 'in capture (frame) order');
  assert.ok(t.events.filter((e) => e.kind === 'segment').every((e) => typeof e.capture.captureTime === 'string'), 'the capture time itself is kept');
});

test('mid-connection capture: a payload that occurs more than once in the recording is not used as an anchor', () => {
  const block = Buffer.alloc(1200, 0x41);
  const raw = [...session.tls.raw.filter((c) => c.dir === 'out'), { dir: 'in', at: session.tls.raw.find((c) => c.dir === 'in').at, bytes: Buffer.concat([block, block, Buffer.from('unique tail')]) }];
  const repeated = { ...session, tls: { ...session.tls, raw } };
  const built = flowFromSession(repeated, { mss: 1200 });
  const firstIn = built.packets.findIndex((p) => p.dir === 'in' && p.payloadFrom === 0);
  const packets = built.packets.filter((p, i) => i > 2 && i !== firstIn); // no SYNs; the server's first captured payload is the second "AAAA…" block
  const a = analyzeCapture(toPcapng(packets), repeated);
  assert.match(a.connection.anchors.join(), /in: sequence anchor missing \(no SYN, and the first captured payload occurs more than once in the recording\)/);
  const inbound = a.segments.filter((s) => s.dir === 'in' && s.payloadLength > 0);
  assert.ok(inbound.length > 0 && inbound.every((s) => s.mapping.status === 'unverified' && s.seq === null));
  const t = buildTimeline(repeated, { capture: a });
  assert.ok(t.events.filter((e) => e.kind === 'segment' && e.dir === 'in').every((e) => e.buffer === null && e.length === 0), 'no tcp/in range is given');
});

// ---- a live capture's source (slice 2: --capture) ----------------------------------------------

test('API: a live capture names its run; its dumpcap warnings and the packet checks are both shown', async (t) => {
  const { openViewer } = await import('../src/viewer.js');
  const warnings = ['dumpcap was stopped before the end of the connection (FIN from both sides, or RST) appeared in the capture'];
  const viewer = await openViewer(JSON.parse(fixture('session.json')), {
    capture: fixture('capture.pcapng'), captureRun: { status: 'live', iface: 'Ethernet 2', stopReason: 'wait-timeout', warnings },
  });
  t.after(() => viewer.close());
  assert.equal(viewer.capture.complete, false);
  const overview = (await (await fetch(new URL('timeline.json', viewer.url))).json()).events.find((e) => e.kind === 'capture');
  assert.match(overview.summary, /^INCOMPLETE capture: 34 TCP segments/);
  const { checked, ...source } = overview.capture.source;
  assert.equal(checked.length, 4);
  assert.deepEqual(source, { metadata: 'live', metadataProblem: null, iface: 'Ethernet 2', stopReason: 'wait-timeout', complete: false, packetWarnings: [], dumpcapWarnings: warnings });
  const fromFile = await openViewer(JSON.parse(fixture('session.json')), { capture: fixture('capture.pcapng') });
  t.after(() => fromFile.close());
  assert.deepEqual([fromFile.capture.metadata, fromFile.capture.complete], ['missing', null], 'the Wireshark fixture: packets clean, run unknown');
});

test('CLI: --capture is for live requests; --dumpcap needs --capture; a missing dumpcap is named', async () => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const run = (...args) => promisify(execFile)(process.execPath, [new URL('../cli.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'), ...args]);
  await assert.rejects(run('--demo', '--capture', '1'), /--capture apply only to live requests/);
  await assert.rejects(run('example.com', '--dumpcap', 'x'), /--dumpcap applies only with --capture/);
  await assert.rejects(run('example.com', '--capture', '1', '--dumpcap', 'no-such-dir/dumpcap.exe'), /dumpcap not found at no-such-dir\/dumpcap\.exe/);
});
