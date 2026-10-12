// Integration over real local TLS 1.3: 103 Early Hints, then a chunked gzip 200, written in
// fragments whose boundaries cut through the HTTP heads. Events must keep absolute offsets in
// http/in and be timed by the TLS record that delivered their last byte.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import { setTimeout as sleep } from 'node:timers/promises';
import { gzipSync } from 'node:zlib';
import { recordHttpsGet } from '../src/tls/recorder.js';
import { serializeSession, loadSession } from '../src/session.js';
import { buildTimeline } from '../src/timeline.js';
import { cert, key, listen } from './helpers/local-tls.mjs';

const GAP_MS = 15; // separate writes -> separate TLS records with distinct arrival times

test('103 -> chunked gzip 200 over local TLS, fragments cut through the heads', async (t) => {
  const original = Buffer.from('early hints, then a compressed body\n');
  const zipped = gzipSync(original);
  const hints = 'HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n';
  const finalHead = 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\n';
  const stream = Buffer.concat([
    Buffer.from(hints + finalHead, 'latin1'),
    Buffer.from(`${zipped.length.toString(16)}\r\n`), zipped, Buffer.from('\r\n0\r\n\r\n'),
  ]);
  // Cut inside "103 Ear|ly", inside "HTTP/1.1 2|00 OK", and inside the chunked body.
  const cuts = [16, hints.length + 10, hints.length + finalHead.length + 6];
  const fragments = [0, ...cuts].map((from, i) => stream.subarray(from, cuts[i] ?? stream.length));

  const options = await listen(t, tls.createServer({ cert, key, minVersion: 'TLSv1.3' }, (socket) => {
    socket.on('error', () => {});
    let request = '';
    socket.on('data', async (part) => {
      request += part.toString('latin1');
      if (!request.endsWith('\r\n\r\n')) return;
      for (const fragment of fragments) {
        socket.write(fragment);
        await sleep(GAP_MS);
      }
      socket.end();
    });
  }));

  const recorded = await recordHttpsGet(options);
  const timeline = buildTimeline(loadSession(serializeSession({ startedAt: Date.now(), host: 'localhost', path: '/', dns: [], tls: recorded })));
  assert.deepEqual(timeline.buffers['http/in'], stream, 'http/in holds the original bytes, unchanged');

  const http = timeline.events.filter((e) => e.layer === 'http' && e.dir === 'in');
  assert.deepEqual(http.map((e) => e.kind), ['interim-response', 'response-head', 'response-body', 'decoded-body']);
  const [interim, head, body, decoded] = http;
  assert.deepEqual([interim.offset, interim.length], [0, hints.length]);
  assert.deepEqual([head.offset, head.length], [hints.length, finalHead.length]);
  assert.equal(body.offset, hints.length + finalHead.length);
  assert.ok(!http.some((e) => e.damaged), http.filter((e) => e.damaged).map((e) => e.problem).join('; '));
  assert.deepEqual(timeline.buffers[decoded.buffer], original);

  const records = timeline.events.filter((e) => e.kind === 'record' && e.dir === 'in' && e.detail.appDataOffset !== null);
  const holding = (pos) => records.find((r) => r.detail.appDataOffset <= pos && pos < r.detail.appDataOffset + r.detail.plaintextLength);
  for (const e of [interim, head, body]) {
    const last = e.offset + e.length - 1;
    assert.equal(e.t, holding(last).t, `${e.kind} is timed by the record holding its last byte`);
    assert.notEqual(holding(e.offset), holding(last), `${e.kind} spans a record boundary`);
  }
});
