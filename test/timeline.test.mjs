// One timeline for the whole session; every event points at bytes we recorded.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession, sha256 } from '../src/session.js';
import { buildTimeline } from '../src/timeline.js';

const fixtureJson = (name) => JSON.parse(readFileSync(new URL(`./fixtures/github-robots/${name}`, import.meta.url), 'utf8'));
const sessionJson = fixtureJson('session.json');
const expected = fixtureJson('expected.json');
const timeline = buildTimeline(loadSession(sessionJson));
const { events, buffers } = timeline;

const bytesOf = (e) => buffers[e.buffer].subarray(e.offset, e.offset + e.length);
const ofKind = (layer, kind) => events.filter((e) => e.layer === layer && e.kind === kind);
const LAYERS = ['dns', 'tcp', 'tls', 'http'];

test('t is each event\'s own recorded time, counted from the first DNS query', () => {
  assert.equal(timeline.origin, sessionJson.dns[0].sentAt);
  assert.deepEqual([events[0].layer, events[0].kind, events[0].t], ['dns', 'query', 0]);
  for (const e of events) assert.equal(e.t, Math.round((e.at - sessionJson.dns[0].sentAt) * 1000) / 1000);
});

test('at the same instant: the TCP chunk, then the TLS records it completed, then HTTP', () => {
  const request = ofKind('http', 'request')[0];
  const sameInstant = events.filter((e) => e.t === request.t).map((e) => e.layer);
  assert.deepEqual([...new Set(sameInstant)], ['tcp', 'tls', 'http']);
  assert.deepEqual(sameInstant, [...sameInstant].sort((a, b) => LAYERS.indexOf(a) - LAYERS.indexOf(b)));
});

test('layers first appear in the order DNS -> TCP -> TLS -> HTTP', () => {
  const firstSeen = [...new Set(events.map((e) => e.layer))];
  assert.deepEqual(firstSeen, LAYERS);
});

test('every event has a byte range inside a recorded buffer, or an explicit empty one', () => {
  for (const e of events) {
    assert.ok(Number.isInteger(e.offset) && Number.isInteger(e.length), `${e.layer}/${e.kind} range`);
    if (e.buffer === null) {
      assert.equal(e.length, 0, `${e.layer}/${e.kind} has no buffer but claims bytes`);
    } else {
      assert.ok(buffers[e.buffer], `unknown buffer ${e.buffer}`);
      assert.ok(e.offset + e.length <= buffers[e.buffer].length, `${e.layer}/${e.kind} runs past ${e.buffer}`);
    }
  }
});

const assertTiles = (evs, buffer) => {
  let pos = 0;
  for (const e of evs) {
    assert.equal(e.buffer, buffer);
    assert.equal(e.offset, pos, `gap or overlap at ${pos} in ${buffer}`);
    pos += e.length;
  }
  assert.equal(pos, buffers[buffer].length);
};

for (const dir of ['out', 'in']) {
  test(`TCP chunks tile tcp/${dir} exactly`, () => {
    assertTiles(events.filter((e) => e.layer === 'tcp' && e.dir === dir && e.length > 0), `tcp/${dir}`);
  });

  test(`TLS records tile tcp/${dir} exactly, each starting with its record header`, () => {
    const records = ofKind('tls', 'record').filter((e) => e.dir === dir);
    assertTiles(records, `tcp/${dir}`);
    for (const r of records) {
      const bytes = bytesOf(r);
      assert.equal(bytes[0], r.detail.outerType);
      assert.equal(bytes.readUInt16BE(3), r.length - 5);
    }
  });

  test(`each TLS record (${dir}) is timed by the TCP chunk that completed it`, () => {
    const chunks = events.filter((e) => e.layer === 'tcp' && e.dir === dir && e.length > 0);
    for (const r of ofKind('tls', 'record').filter((e) => e.dir === dir)) {
      const last = r.offset + r.length - 1;
      const chunk = chunks.find((c) => c.offset <= last && last < c.offset + c.length);
      assert.equal(r.t, chunk.t);
    }
  });
}

test('DNS: one query and one response event per answered exchange, carrying the recorded bytes', () => {
  const queries = ofKind('dns', 'query');
  const responses = ofKind('dns', 'response');
  assert.equal(queries.length, sessionJson.dns.length);
  assert.equal(responses.length, sessionJson.dns.filter((e) => e.responseHex).length);
  const recordedOn = (e) => sessionJson.dns.find((d) => d.localPort === e.detail.localPort);
  for (const q of queries) assert.equal(bytesOf(q).toString('hex'), recordedOn(q).queryHex);
  for (const r of responses) assert.equal(bytesOf(r).toString('hex'), recordedOn(r).responseHex);
  assert.match(responses.at(-1).summary, /140\.82\.121\.3/);
});

test('HTTP: request head and response body point at the decrypted bytes', () => {
  const [request] = ofKind('http', 'request');
  assert.match(bytesOf(request).toString('latin1'), /^GET \/robots\.txt HTTP\/1\.1\r\n[\s\S]*\r\n\r\n$/);
  const [head] = ofKind('http', 'response-head');
  assert.match(bytesOf(head).toString('latin1'), /^HTTP\/1\.1 200 OK\r\n/);
  const [body] = ofKind('http', 'response-body');
  assert.equal(sha256(bytesOf(body)), expected.http.response.bodySha256);
});

test('causality: TLS waits for TCP, the request waits for TLS, the body arrives before close', () => {
  const at = (layer, kind) => ofKind(layer, kind)[0].t;
  assert.ok(at('tcp', 'established') >= at('dns', 'response'));
  assert.ok(ofKind('tls', 'record')[0].t >= at('tcp', 'established'));
  assert.ok(at('http', 'request') >= at('tls', 'secure'));
  assert.ok(at('http', 'response-body') <= at('tcp', 'close'));
});

test('a lost DNS datagram shows up as its query plus a "lost" event with no bytes', () => {
  const lost = {
    ...sessionJson.dns[2],
    localPort: 50000,
    responseHex: null,
    receivedAt: null,
    failedAt: sessionJson.dns[2].sentAt + 2500,
    error: 'timeout 2500ms',
  };
  const withLoss = { ...sessionJson, dns: [...sessionJson.dns.slice(0, 2), lost, sessionJson.dns[2]] };
  const t = buildTimeline(loadSession(withLoss));
  const [lostEvent] = t.events.filter((e) => e.kind === 'lost');
  assert.equal(lostEvent.layer, 'dns');
  assert.equal(lostEvent.buffer, null);
  assert.equal(lostEvent.length, 0);
  assert.equal(lostEvent.t, Math.round((lost.failedAt - t.origin) * 1000) / 1000);
  assert.match(lostEvent.summary, /no answer from ns-421\.awsdns-52\.com: timeout 2500ms/);
  assert.equal(lostEvent.detail.localPort, 50000);
  const dnsQueries = t.events.filter((e) => e.layer === 'dns' && e.kind === 'query');
  assert.equal(dnsQueries.length, 4);
  const position = (e) => t.events.indexOf(e);
  const lostQuery = dnsQueries.find((q) => q.detail.localPort === 50000);
  assert.ok(position(lostQuery) < position(lostEvent), 'the lost query is sent before it is declared lost');
});

test('a session read in 1-byte TCP chunks yields the same TLS records and HTTP ranges', () => {
  const oneByte = {
    ...sessionJson,
    tls: {
      ...sessionJson.tls,
      raw: sessionJson.tls.raw.flatMap((c) => c.hex.match(/../g).map((byte, i) => ({ ...c, at: c.at + i * 1e-4, hex: byte }))),
    },
  };
  const t = buildTimeline(loadSession(oneByte));
  const shape = (tl, layer) => tl.events.filter((e) => e.layer === layer).map((e) => [e.kind, e.dir, e.buffer, e.offset, e.length, e.summary]);
  assert.deepEqual(shape(t, 'tls').filter(([kind]) => kind === 'record'), shape(timeline, 'tls').filter(([kind]) => kind === 'record'));
  assert.deepEqual(shape(t, 'http'), shape(timeline, 'http'));
  assert.equal(t.events.filter((e) => e.layer === 'tcp' && e.length === 1).length, t.buffers['tcp/out'].length + t.buffers['tcp/in'].length);
});
