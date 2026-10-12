import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { parseHttpMessage } from '../src/http/message.js';
import { decodeHttpBody } from '../src/http/body.js';
import { httpFields } from '../src/http/fields.js';
import { walk } from '../src/fields.js';

const response = (headers, body) => Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\n${headers}\r\n\r\n`), Buffer.from(body)]);
const chunk = (bytes) => Buffer.concat([Buffer.from(`${bytes.length.toString(16)}\r\n`), bytes, Buffer.from('\r\n0\r\n\r\n')]);
const decode = (buf, options) => decodeHttpBody(buf, parseHttpMessage(buf), options);
function tiled(buf) {
  walk(httpFields(buf), (f) => {
    if (!f.children.length) return;
    let end = f.offset;
    for (const child of f.children) {
      assert.equal(child.offset, end, child.name);
      end += child.length;
    }
    assert.equal(end, f.offset + f.length, f.name);
  });
}

test('RFC-style chunks, quoted extensions, trailers and surplus keep exact ranges', () => {
  const buf = response('Transfer-Encoding: Chunked', '4;foo="a;b"\r\nWiki\r\n5\r\npedia\r\n0\r\nX-End: yes\r\n\r\nNEXT');
  const msg = parseHttpMessage(buf);
  assert.equal(msg.body.complete, true);
  assert.equal(buf.subarray(msg.extra.offset).toString(), 'NEXT');
  assert.equal(decode(buf).bytes.toString(), 'Wikipedia');
  assert.equal(msg.chunks.fields.find((f) => f.name === 'trailer').value, 'X-End: yes');
  tiled(buf);
});

test('binary chunks do not interpret CRLF inside their data', () => {
  const bytes = Buffer.from([0, 13, 10, 255, 128]);
  const buf = response('Transfer-Encoding: chunked', chunk(bytes));
  assert.deepEqual(decode(buf).bytes, bytes);
  tiled(buf);
});

for (const [body, problem] of [
  ['Z\r\n', /invalid chunk size/], ['+1\r\na\r\n0\r\n\r\n', /invalid/],
  ['1;=oops\r\na\r\n0\r\n\r\n', /extensions/],
  ['FFFFFFFFFFFFFFFF\r\n', /safe integer/], ['3\r\nab', /data truncated/],
  ['1\r\naX', /terminator truncated/], ['1\r\naXX', /invalid chunk data terminator/],
  ['0\r\n', /trailers truncated/], ['0\r\nBad\r\n\r\n', /invalid chunk trailer/],
]) {
  test(`damaged chunked body: ${JSON.stringify(body)}`, () => {
    const buf = response('Transfer-Encoding: chunked', body);
    const msg = parseHttpMessage(buf);
    assert.equal(msg.body.complete, false);
    assert.match(msg.problems.join(), problem);
    assert.equal(decode(buf).bytes, null);
    tiled(buf);
  });
}

test('every truncated prefix remains incomplete and byte-covered', () => {
  const complete = '3\r\nabc\r\n0\r\nX: y\r\n\r\n';
  for (let i = 0; i < complete.length; i++) {
    const buf = response('Transfer-Encoding: chunked', complete.slice(0, i));
    assert.equal(parseHttpMessage(buf).body.complete, false, `prefix ${i}`);
    assert.equal(decode(buf).bytes, null);
    tiled(buf);
  }
});

test('gzip alone and inside chunks restores bytes without changing the source', () => {
  const original = Buffer.from('Привет!\nThis is the original body.');
  const zipped = gzipSync(original);
  for (const buf of [response(`Content-Length: ${zipped.length}\r\nContent-Encoding: gzip`, zipped),
    response('Transfer-Encoding: chunked\r\nContent-Encoding: gzip', chunk(zipped))]) {
    const copy = Buffer.from(buf);
    assert.deepEqual(decode(buf).bytes, original);
    assert.deepEqual(buf, copy);
    tiled(buf);
  }
});

test('gzip corruption, truncation and decompression limits return no derived bytes', () => {
  const zipped = gzipSync(Buffer.alloc(10000, 65));
  const corrupt = Buffer.from(zipped); corrupt[corrupt.length - 8] ^= 1;
  for (const body of [corrupt, zipped.subarray(0, zipped.length - 1)]) {
    const result = decode(response('Content-Encoding: gzip', body));
    assert.equal(result.bytes, null);
    assert.match(result.problem, /gzip decoding failed/);
  }
  assert.match(decode(response('Content-Encoding: gzip', zipped), { maxOutputLength: 100 }).problem, /over 100 bytes/);
});

test('unknown encodings and ambiguous framing never produce decoded content', () => {
  for (const headers of [
    'Transfer-Encoding: xchunked', 'Transfer-Encoding: chunked, gzip',
    'Transfer-Encoding: chunked, chunked', 'Transfer-Encoding: gzip, chunked',
    'Transfer-Encoding: chunked\r\nContent-Length: 1',
    'Content-Length: 1\r\nContent-Length: 2', 'Content-Encoding: br',
  ]) {
    const result = decode(response(headers, '1\r\na\r\n0\r\n\r\n'));
    assert.equal(result.bytes, null, headers);
    assert.ok(result.problem, headers);
  }
});

test('bodyless status codes ignore length/encoding metadata', () => {
  for (const status of [100, 204, 304]) {
    const buf = Buffer.from(`HTTP/1.1 ${status} Status\r\nContent-Length: 123\r\nContent-Encoding: gzip\r\n\r\n`);
    const msg = parseHttpMessage(buf);
    assert.equal(msg.body.length, 0);
    assert.deepEqual(msg.problems, []);
    assert.equal(decode(buf).problem, null);
  }
});

test('chunk count and decoded size limits are enforced', () => {
  const many = response('Transfer-Encoding: chunked', '1\r\na\r\n'.repeat(10001) + '0\r\n\r\n');
  assert.match(parseHttpMessage(many).problems.join(), /count exceeds limit/);
  assert.match(decode(response('Transfer-Encoding: chunked', chunk(Buffer.alloc(11))), { maxOutputLength: 10 }).problem, /limit/);
});
