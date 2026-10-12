import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { readFileSync } from 'node:fs';
import { once } from 'node:events';
import { recordHttpsGet } from '../src/tls/recorder.js';
import { decryptSession } from '../src/tls/decrypt.js';

// Public, localhost-only test credentials. Never used for a real site.
const cert = readFileSync(new URL('fixtures/localhost-tls/cert.pem', import.meta.url));
const key = readFileSync(new URL('fixtures/localhost-tls/key.pem', import.meta.url));

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
  });
  server.on('tlsClientError', () => {});
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    server.close();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { ip: '127.0.0.1', servername: 'localhost', port: server.address().port, ca: cert };
}

test('records and independently decrypts a real local TLS 1.3 request', async (t) => {
  let request = '';
  let sni;
  const server = tls.createServer({ cert, key, minVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'] }, (socket) => {
    sni = socket.servername;
    socket.on('data', (data) => {
      request += data.toString('ascii');
      if (request.endsWith('\r\n\r\n')) socket.end('HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello');
    });
  });
  const options = await listen(t, server);
  const session = await recordHttpsGet({ ...options, path: '/a?x=1' });
  assert.match(request, /^GET \/a\?x=1 HTTP\/1.1\r\n/);
  assert.ok(request.includes(`\r\nHost: localhost:${options.port}\r\n`));
  assert.equal(sni, 'localhost');
  assert.equal(session.port, options.port);
  assert.equal(session.tls.authorized, true);
  const dec = decryptSession(session);
  assert.deepEqual(dec.client.appData, session.plaintext.sent);
  assert.deepEqual(dec.server.appData, session.plaintext.received);
  assert.ok(dec.server.appData.toString().endsWith('hello'));
});

test('rejects an untrusted certificate', async (t) => {
  const options = await listen(t, tls.createServer({ cert, key }));
  await assert.rejects(recordHttpsGet({ ...options, ca: undefined }), /certificate|self.signed/i);
});

test('the recorder deadline also covers a TCP connection that never opens', { timeout: 1000 }, async (t) => {
  const socket = new net.Socket();
  t.mock.method(net, 'connect', () => socket);
  await assert.rejects(recordHttpsGet({ ip: '192.0.2.1', servername: 'example.com', timeoutMs: 25 }), /timed out/);
  assert.equal(socket.destroyed, true);
});

test('a stalled TLS handshake times out and closes its TCP socket', { timeout: 3000 }, async (t) => {
  const server = net.createServer();
  const options = await listen(t, server);
  const connected = once(server, 'connection');
  const recording = recordHttpsGet({ ...options, timeoutMs: 150 });
  const [socket] = await connected;
  socket.resume();
  const closed = once(socket, 'close');
  await assert.rejects(recording, /timed out|timeout/i);
  await closed;
});

test('cancellation stops a live TLS attempt and closes the socket', { timeout: 3000 }, async (t) => {
  const server = net.createServer();
  const options = await listen(t, server);
  const controller = new AbortController();
  const connected = once(server, 'connection');
  const recording = recordHttpsGet({ ...options, signal: controller.signal });
  const [socket] = await connected;
  socket.resume();
  const closed = once(socket, 'close');
  controller.abort(new Error('cancelled by test'));
  await assert.rejects(recording, /cancelled by test/);
  await closed;
});

test('a response that exceeds the byte budget fails instead of buffering indefinitely', async (t) => {
  const options = await listen(t, tls.createServer({ cert, key }, (socket) => {
    socket.once('data', () => socket.end(Buffer.alloc(64 * 1024, 65)));
    socket.on('error', () => {});
  }));
  await assert.rejects(recordHttpsGet({ ...options, maxBytes: 16 * 1024 }), /byte limit/i);
});

test('invalid paths and Host values are rejected before connecting', async () => {
  for (const path of ['/\r\nX-Evil: yes', '/has space', 'https://evil.test/', '/\n', '/abc\r']) {
    await assert.rejects(recordHttpsGet({ ip: '127.0.0.1', servername: 'localhost', path }), /path/i);
  }
  await assert.rejects(recordHttpsGet({ ip: '127.0.0.1', servername: 'localhost\r\nX-Evil: yes' }), /host/i);
  await assert.rejects(recordHttpsGet({ ip: '127.0.0.1', servername: 'localhost\n' }), /host/i);
});

import { gzipSync } from 'node:zlib';
import { serializeSession, loadSession } from '../src/session.js';
import { buildTimeline } from '../src/timeline.js';
import { openViewer } from '../src/viewer.js';

for (const broken of [false, true]) {
  test(`chunked gzip through real TLS and viewer API (${broken ? 'damaged' : 'valid'})`, async (t) => {
    const original = Buffer.from('whathappens: compressed HTTP body\n');
    const zipped = gzipSync(original);
    if (broken) zipped[zipped.length - 8] ^= 1;
    const chunks = [zipped.subarray(0, 7), zipped.subarray(7)];
    const wire = Buffer.concat([
      Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\n'),
      ...chunks.flatMap((part) => [Buffer.from(`${part.length.toString(16)}\r\n`), part, Buffer.from('\r\n')]),
      Buffer.from('0\r\nX-Test: complete\r\n\r\n'),
    ]);
    const options = await listen(t, tls.createServer({ cert, key, minVersion: 'TLSv1.3' }, (socket) => {
      socket.on('error', () => {});
      let request = '';
      socket.on('data', (part) => {
        request += part.toString();
        if (request.endsWith('\r\n\r\n')) {
          assert.match(request, /Accept-Encoding: gzip\r\n/);
          socket.end(wire);
        }
      });
    }));
    const recorded = await recordHttpsGet(options);
    const session = serializeSession({ startedAt: Date.now(), host: 'localhost', path: '/', dns: [], tls: recorded });
    const timeline = buildTimeline(loadSession(session));
    assert.deepEqual(timeline.buffers['http/in'], wire);
    const body = timeline.events.find((e) => e.kind === 'response-body');
    assert.equal(body.damaged, broken);
    const decoded = timeline.events.find((e) => e.kind === 'decoded-body');
    if (broken) {
      assert.equal(decoded, undefined);
      assert.match(body.problem, /gzip decoding failed/);
      return;
    }
    assert.ok(body.fields.children.some((f) => f.name === 'chunk_size'));
    assert.ok(body.fields.children.some((f) => f.name === 'trailer'));
    assert.equal(decoded.offset, 0);
    assert.deepEqual(timeline.buffers[decoded.buffer], original);
    const viewer = await openViewer(session);
    t.after(() => viewer.close());
    const view = await (await fetch(new URL('timeline.json', viewer.url))).json();
    const index = view.events.findIndex((e) => e.kind === 'decoded-body');
    const bytes = await (await fetch(new URL(`events/${index}/bytes`, viewer.url))).arrayBuffer();
    assert.deepEqual(Buffer.from(bytes), original);
    const fields = await (await fetch(new URL(`events/${index}/fields`, viewer.url))).json();
    assert.equal(fields.fields.name, 'decoded_body');
    assert.equal(fields.fields.length, original.length);
  });
}
