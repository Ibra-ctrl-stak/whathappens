// HTTP/1.1 message heads with byte ranges: fixture values come from Wireshark (expected.json).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession, sha256 } from '../src/session.js';
import { decryptSession } from '../src/tls/decrypt.js';
import { parseHttpMessage, headerValue } from '../src/http/message.js';

const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/github-robots/${name}`, import.meta.url), 'utf8'));
const session = loadSession(fixture('session.json'));
const expected = fixture('expected.json').http;
const { client, server } = decryptSession({ raw: session.tls.raw, keylog: session.tls.keylog });

const slice = (buf, range) => buf.subarray(range.offset, range.offset + range.length).toString('latin1');

test('request line and headers match Wireshark', () => {
  const req = parseHttpMessage(client.appData);
  assert.equal(req.kind, 'request');
  assert.equal(req.startLine.method, expected.request.method);
  assert.equal(req.startLine.target, expected.request.uri);
  assert.equal(req.startLine.version, 'HTTP/1.1');
  assert.equal(headerValue(req, 'host'), expected.request.host);
  assert.equal(headerValue(req, 'User-Agent'), expected.request.userAgent);
  assert.deepEqual(req.body, { offset: req.head.length, length: 0, framing: 'none', declaredLength: 0 });
});

test('status line, headers and body match Wireshark', () => {
  const res = parseHttpMessage(server.appData);
  assert.equal(res.kind, 'response');
  assert.equal(res.startLine.status, expected.response.code);
  assert.equal(res.startLine.reason, expected.response.phrase);
  assert.equal(headerValue(res, 'content-type'), expected.response.contentType);
  assert.equal(res.body.framing, 'content-length');
  assert.equal(res.body.declaredLength, expected.response.contentLength);
  assert.equal(res.body.length, expected.response.contentLength);
  assert.equal(sha256(server.appData.subarray(res.body.offset, res.body.offset + res.body.length)), expected.response.bodySha256);
});

test('every range points at exactly its own bytes', () => {
  for (const buf of [client.appData, server.appData]) {
    const msg = parseHttpMessage(buf);
    assert.equal(slice(buf, msg.startLine), slice(buf, msg.startLine).split('\r\n')[0]);
    for (const h of msg.headers) assert.equal(slice(buf, h), `${h.name}: ${h.value}`);
    assert.ok(slice(buf, msg.head).endsWith('\r\n\r\n'));
    assert.equal(msg.head.offset + msg.head.length, msg.body.offset);
    assert.equal(msg.body.offset + msg.body.length, buf.length);
  }
});

test('chunked bodies are framed as chunked and span the rest of the stream', () => {
  const buf = Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n', 'latin1');
  const res = parseHttpMessage(buf);
  assert.equal(res.body.framing, 'chunked');
  assert.equal(res.body.declaredLength, null);
  assert.equal(slice(buf, res.body), '5\r\nhello\r\n0\r\n\r\n');
});

test('header values are trimmed and names keep their wire spelling', () => {
  const buf = Buffer.from('GET / HTTP/1.1\r\nX-Odd-Case:   spaced value  \r\n\r\n', 'latin1');
  const [h] = parseHttpMessage(buf).headers;
  assert.equal(h.name, 'X-Odd-Case');
  assert.equal(h.value, 'spaced value');
});

test('an incomplete head is an error, not a guess', () => {
  assert.throws(() => parseHttpMessage(Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 3\r\n')), /incomplete/);
});

test('a malformed start line is an error', () => {
  assert.throws(() => parseHttpMessage(Buffer.from('HELLO\r\n\r\n')), /start line/);
});
