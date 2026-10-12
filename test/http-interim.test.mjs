// Interim (1xx) HTTP responses before the final response to our GET (RFC 9110 §15.2):
// each response parsed at its absolute offset in http/in; no bodies on 1xx; 101 is not followed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { parseHttpResponses, MAX_INTERIM_RESPONSES } from '../src/http/message.js';
import { httpResponseFields } from '../src/http/fields.js';
import { decodeHttpBody } from '../src/http/body.js';
import { walk } from '../src/fields.js';

const head = (status, reason, headers = []) => `HTTP/1.1 ${status} ${reason}\r\n${headers.map((h) => `${h}\r\n`).join('')}\r\n`;
const EARLY_HINTS = head(103, 'Early Hints', ['Link: </style.css>; rel=preload; as=style']);
const CONTINUE = head(100, 'Continue');
const ok = (body) => `${head(200, 'OK', [`Content-Length: ${body.length}`])}${body}`;
const bytes = (...parts) => Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p, 'latin1'))));
const text = (buf, r) => buf.toString('latin1', r.offset, r.offset + r.length);

/** Every byte of buf belongs to exactly one leaf of the response-stream field tree. */
function assertTiled(buf, tree) {
  assert.deepEqual([tree.offset, tree.length], [0, buf.length]);
  const owners = new Array(buf.length).fill(0);
  walk(tree, (f) => {
    if (f.children.length) {
      let pos = f.offset;
      for (const c of f.children) {
        assert.equal(c.offset, pos, `${f.name} > ${c.name}`);
        pos += c.length;
      }
      assert.equal(pos, f.offset + f.length, f.name);
      return;
    }
    for (let i = f.offset; i < f.offset + f.length; i += 1) owners[i] += 1;
  });
  assert.ok(owners.every((n) => n === 1), `byte ${owners.findIndex((n) => n !== 1)}`);
}

test('a plain 200 is the final response with no interim ones', () => {
  const buf = bytes(ok('hello'));
  const seq = parseHttpResponses(buf);
  assert.deepEqual(seq.interim, []);
  assert.equal(seq.final.startLine.status, 200);
  assert.equal(text(buf, seq.final.body), 'hello');
  assert.equal(seq.rest, null);
  assertTiled(buf, httpResponseFields(buf, seq));
});

test('103 Early Hints then 200: two heads at absolute offsets, the 103 has no body', () => {
  const buf = bytes(EARLY_HINTS, ok('hello'));
  const seq = parseHttpResponses(buf);
  assert.equal(seq.interim.length, 1);
  const [hints] = seq.interim;
  assert.deepEqual([hints.startLine.status, hints.head.offset, hints.head.length], [103, 0, EARLY_HINTS.length]);
  assert.equal(text(buf, hints.headers[0]), 'Link: </style.css>; rel=preload; as=style');
  assert.equal(seq.final.head.offset, EARLY_HINTS.length);
  assert.equal(seq.final.startLine.offset, EARLY_HINTS.length);
  assert.equal(text(buf, seq.final.headers[0]), 'Content-Length: 5');
  assert.equal(text(buf, seq.final.body), 'hello');
  assert.equal(seq.final.extra, null);
  assert.equal(seq.rest, null);
  const tree = httpResponseFields(buf, seq);
  assert.deepEqual(tree.children.map((f) => f.name), ['interim_response', 'response']);
  assertTiled(buf, tree);
});

test('100 then 103 then a chunked gzip 200: absolute chunk ranges and decoded bytes', () => {
  const original = Buffer.from('whathappens: interim then compressed\n');
  const zipped = gzipSync(original);
  const finalHead = head(200, 'OK', ['Transfer-Encoding: chunked', 'Content-Encoding: gzip']);
  const chunked = bytes(`${(9).toString(16)}\r\n`, zipped.subarray(0, 9), '\r\n',
    `${(zipped.length - 9).toString(16)}\r\n`, zipped.subarray(9), '\r\n', '0\r\n\r\n');
  const buf = bytes(CONTINUE, EARLY_HINTS, finalHead, chunked);
  const seq = parseHttpResponses(buf);
  assert.deepEqual(seq.interim.map((m) => m.startLine.status), [100, 103]);
  const finalAt = CONTINUE.length + EARLY_HINTS.length;
  assert.equal(seq.final.head.offset, finalAt);
  assert.equal(seq.final.body.framing, 'chunked');
  assert.equal(seq.final.body.offset, finalAt + finalHead.length);
  assert.equal(seq.final.chunks.data[0].offset, finalAt + finalHead.length + 3); // after "9\r\n"
  assert.deepEqual(decodeHttpBody(buf, seq.final).bytes, original);
  assertTiled(buf, httpResponseFields(buf, seq));
});

for (const status of [204, 304]) {
  test(`${status} has no body even with length metadata`, () => {
    const buf = bytes(head(status, status === 204 ? 'No Content' : 'Not Modified', ['Content-Length: 1234']));
    const seq = parseHttpResponses(buf);
    assert.equal(seq.final.startLine.status, status);
    assert.deepEqual([seq.final.body.length, seq.final.body.framing, seq.final.extra], [0, 'none', null]);
    assert.equal(seq.rest, null);
    assertTiled(buf, httpResponseFields(buf, seq));
  });
}

test('101 Switching Protocols: no final response; following bytes are not parsed as HTTP', () => {
  const upgrade = head(101, 'Switching Protocols', ['Upgrade: websocket', 'Connection: Upgrade']);
  const buf = bytes(upgrade, Buffer.from([0x81, 0x05, 0x48, 0x54, 0x54, 0x50, 0x2f]));
  const seq = parseHttpResponses(buf);
  assert.equal(seq.switched.startLine.status, 101);
  assert.equal(seq.final, null);
  assert.deepEqual([seq.rest.offset, seq.rest.length], [upgrade.length, 7]);
  assert.match(seq.rest.problem, /101/);
  assertTiled(buf, httpResponseFields(buf, seq));
});

test('the stream ends right after a 103: the 103 is kept, the missing final response is reported', () => {
  const buf = bytes(EARLY_HINTS);
  const seq = parseHttpResponses(buf);
  assert.equal(seq.interim.length, 1);
  assert.equal(seq.final, null);
  assert.deepEqual([seq.rest.offset, seq.rest.length], [buf.length, 0]);
  assert.match(seq.rest.problem, /ended before the final response/);
  assertTiled(buf, httpResponseFields(buf, seq));
});

test('the stream ends inside the final head: earlier responses kept, the rest flagged', () => {
  const buf = bytes(EARLY_HINTS, 'HTTP/1.1 200 OK\r\nContent-Ty');
  const seq = parseHttpResponses(buf);
  assert.equal(seq.interim.length, 1);
  assert.deepEqual([seq.rest.offset, seq.rest.length], [EARLY_HINTS.length, buf.length - EARLY_HINTS.length]);
  assert.match(seq.rest.problem, /incomplete/);
  assertTiled(buf, httpResponseFields(buf, seq));
});

test('damaged headers in the final response: the 103 stays parsed, the error covers the rest', () => {
  const buf = bytes(EARLY_HINTS, 'HTTP/1.1 200 OK\r\nno-colon-here\r\n\r\nbody');
  const seq = parseHttpResponses(buf);
  assert.equal(seq.interim.length, 1);
  assert.equal(seq.final, null);
  assert.deepEqual([seq.rest.offset, seq.rest.length], [EARLY_HINTS.length, buf.length - EARLY_HINTS.length]);
  assert.match(seq.rest.problem, /malformed header/);
  assertTiled(buf, httpResponseFields(buf, seq));
});

test(`more than ${MAX_INTERIM_RESPONSES} interim responses stop parsing at the limit`, () => {
  const buf = bytes(...Array.from({ length: MAX_INTERIM_RESPONSES + 1 }, () => EARLY_HINTS), ok('x'));
  const seq = parseHttpResponses(buf);
  assert.equal(seq.interim.length, MAX_INTERIM_RESPONSES);
  assert.equal(seq.final, null);
  assert.equal(seq.rest.offset, MAX_INTERIM_RESPONSES * EARLY_HINTS.length);
  assert.match(seq.rest.problem, new RegExp(`more than ${MAX_INTERIM_RESPONSES} interim`));
  assertTiled(buf, httpResponseFields(buf, seq));
});

test('a request line where a response is expected is an error on those bytes', () => {
  const buf = bytes('GET / HTTP/1.1\r\n\r\n');
  const seq = parseHttpResponses(buf);
  assert.deepEqual([seq.rest.offset, seq.rest.length], [0, buf.length]);
  assert.match(seq.rest.problem, /response/);
});
