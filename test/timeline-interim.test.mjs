// Interim (1xx) responses on the timeline: one head event per response, absolute offsets in
// http/in, each event timed by the TLS record that delivered its last byte.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { loadSession } from '../src/session.js';
import { buildTimeline } from '../src/timeline.js';
import { MAX_INTERIM_RESPONSES } from '../src/http/message.js';
import { withServerResponse } from './helpers/server-http.mjs';

const golden = JSON.parse(readFileSync(new URL('./fixtures/github-robots/session.json', import.meta.url), 'utf8'));
const timelineFor = (fragments) => buildTimeline(loadSession(withServerResponse(golden, fragments)));
const httpIn = (t) => t.events.filter((e) => e.layer === 'http' && e.dir === 'in');
const kinds = (t) => httpIn(t).map((e) => e.kind);
const head = (status, reason, headers = []) => `HTTP/1.1 ${status} ${reason}\r\n${headers.map((h) => `${h}\r\n`).join('')}\r\n`;
const EARLY_HINTS = head(103, 'Early Hints', ['Link: </s.css>; rel=preload']);

/** The server TLS record (as a timeline event) whose plaintext holds http/in byte `pos`. */
function recordHolding(t, pos) {
  return t.events.find((e) => e.kind === 'record' && e.dir === 'in' && e.detail.appDataOffset !== null
    && e.detail.appDataOffset <= pos && pos < e.detail.appDataOffset + e.detail.plaintextLength);
}

const lastByte = (e) => e.offset + e.length - 1;

test('103 -> 200 with record boundaries inside the heads: events, offsets and timing', () => {
  const stream = `${EARLY_HINTS}${head(200, 'OK', ['Content-Length: 5'])}hello`;
  const cut = [16, EARLY_HINTS.length + 10, EARLY_HINTS.length + 40]; // inside "103 Ear|ly", "HTTP/1.1 2|00", the 200 head
  const fragments = [0, ...cut].map((from, i) => stream.slice(from, cut[i] ?? stream.length));
  const t = timelineFor(fragments);
  assert.deepEqual(kinds(t), ['interim-response', 'response-head', 'response-body']);
  const [hints, final, body] = httpIn(t);
  assert.deepEqual([hints.offset, hints.length], [0, EARLY_HINTS.length]);
  assert.equal(final.offset, EARLY_HINTS.length);
  assert.equal(t.buffers['http/in'].toString('latin1', body.offset, body.offset + body.length), 'hello');
  for (const e of [hints, final, body]) assert.equal(e.t, recordHolding(t, lastByte(e)).t, e.kind);
  assert.notEqual(hints.t, recordHolding(t, 0).t, 'the 103 completes in the second record, not the first');
  assert.match(hints.summary, /^103 Early Hints/);
  assert.equal(hints.fields.name, 'head');
  const status = hints.fields.children[0].children.find((f) => f.name === 'status_code');
  assert.deepEqual([status.value, status.offset], [103, 9]);
  assert.equal(final.fields.children[0].offset, EARLY_HINTS.length, 'final start line at its absolute offset');
});

test('100 -> 103 -> chunked gzip 200: both interim heads, decoded body stays its own byte space', () => {
  const original = Buffer.from('decoded after two interim responses\n');
  const zipped = gzipSync(original);
  const body = Buffer.concat([Buffer.from(`${zipped.length.toString(16)}\r\n`), zipped, Buffer.from('\r\n0\r\n\r\n')]);
  const t = timelineFor([head(100, 'Continue'), EARLY_HINTS,
    Buffer.concat([Buffer.from(head(200, 'OK', ['Transfer-Encoding: chunked', 'Content-Encoding: gzip']), 'latin1'), body])]);
  assert.deepEqual(kinds(t), ['interim-response', 'interim-response', 'response-head', 'response-body', 'decoded-body']);
  const decoded = httpIn(t).find((e) => e.kind === 'decoded-body');
  assert.equal(decoded.buffer, 'http-decoded/in');
  assert.equal(decoded.offset, 0);
  assert.deepEqual(t.buffers[decoded.buffer], original);
  const responseBody = httpIn(t).find((e) => e.kind === 'response-body');
  assert.ok(responseBody.fields.children.some((f) => f.name === 'chunk_size'));
});

for (const [status, reason] of [[204, 'No Content'], [304, 'Not Modified']]) {
  test(`${status}: a head event and no body event`, () => {
    const t = timelineFor([head(status, reason, ['Content-Length: 99'])]);
    assert.deepEqual(kinds(t), ['response-head']);
    assert.ok(httpIn(t).every((e) => !e.damaged));
  });
}

test('101: the switch is shown as unsupported and the following bytes are not parsed as HTTP', () => {
  const t = timelineFor([head(101, 'Switching Protocols', ['Upgrade: websocket']), Buffer.from([0x81, 0x02, 0x68, 0x69])]);
  assert.deepEqual(kinds(t), ['protocol-switch', 'message']);
  const [switched, rest] = httpIn(t);
  assert.equal(switched.damaged, true);
  assert.match(switched.problem, /not supported/);
  assert.deepEqual([rest.length, rest.damaged, rest.fields.name], [4, true, 'unparsed']);
});

test('the connection ends right after a 103: the 103 stays, an empty damaged event reports the missing response', () => {
  const t = timelineFor([EARLY_HINTS]);
  assert.deepEqual(kinds(t), ['interim-response', 'message']);
  const missing = httpIn(t)[1];
  assert.deepEqual([missing.offset, missing.length, missing.fields], [EARLY_HINTS.length, 0, null]);
  assert.match(missing.problem, /ended before the final response/);
});

test('damaged final headers: the 103 event is kept, the error covers the remaining bytes', () => {
  const t = timelineFor([EARLY_HINTS, 'HTTP/1.1 200 OK\r\nno colon\r\n\r\nbody']);
  assert.deepEqual(kinds(t), ['interim-response', 'message']);
  const rest = httpIn(t)[1];
  assert.equal(rest.offset, EARLY_HINTS.length);
  assert.equal(rest.offset + rest.length, t.buffers['http/in'].length);
  assert.match(rest.problem, /malformed header/);
});

test(`more than ${MAX_INTERIM_RESPONSES} interim responses: the first ${MAX_INTERIM_RESPONSES} are events, the rest is flagged`, () => {
  const t = timelineFor([EARLY_HINTS.repeat(MAX_INTERIM_RESPONSES + 1), head(200, 'OK', ['Content-Length: 0'])]);
  assert.equal(kinds(t).filter((k) => k === 'interim-response').length, MAX_INTERIM_RESPONSES);
  const rest = httpIn(t).at(-1);
  assert.equal(rest.kind, 'message');
  assert.match(rest.problem, /more than 16 interim/);
});

test('http/in events tile the server stream exactly in every case above', () => {
  for (const fragments of [[EARLY_HINTS, head(200, 'OK', ['Content-Length: 2']), 'ok'], [EARLY_HINTS, 'HTTP/1.1 2'], [head(101, 'Switching Protocols'), 'xyz']]) {
    const t = timelineFor(fragments);
    let pos = 0;
    for (const e of httpIn(t).filter((ev) => ev.buffer === 'http/in' && ev.length > 0).sort((a, b) => a.offset - b.offset)) {
      assert.equal(e.offset, pos, `${e.kind} at ${e.offset}`);
      pos += e.length;
    }
    assert.equal(pos, t.buffers['http/in'].length);
  }
});

// Empty bodies and Content-Encoding: the "body cannot be decoded, but there is no body event"
// branch of the timeline. An empty gzip stream is not valid gzip.
const GZIP_EMPTY = head(200, 'OK', ['Content-Length: 0', 'Content-Encoding: gzip']);

function assertEmptyGzipError(t, finalAt) {
  const events = httpIn(t);
  assert.deepEqual(events.map((e) => e.kind).filter((k) => k !== 'interim-response'), ['response-head', 'response-body']);
  assert.ok(!events.some((e) => e.kind === 'decoded-body'), 'no decoded body');
  const headEvent = events.find((e) => e.kind === 'response-head');
  assert.equal(headEvent.offset, finalAt);
  assert.deepEqual(headEvent.fields.children.filter((f) => f.name === 'header').map((f) => f.label), ['Content-Length', 'Content-Encoding']);
  const error = events.find((e) => e.kind === 'response-body');
  const headEndAt = headEvent.offset + headEvent.length;
  assert.deepEqual([error.buffer, error.offset, error.length], ['http/in', headEndAt, 0], 'empty range right after the final head');
  assert.equal(headEndAt, t.buffers['http/in'].length);
  assert.equal(error.damaged, true);
  assert.match(error.problem, /gzip decoding failed/);
  assert.equal(error.t, recordHolding(t, headEndAt - 1).t, 'timed by the record with the last head byte');
  assert.equal(error.t, headEvent.t);
}

test('200 with Content-Length: 0 and Content-Encoding: gzip: headers kept, an empty-range decoding error', () => {
  const t = timelineFor([GZIP_EMPTY.slice(0, 25), GZIP_EMPTY.slice(25)]); // record boundary inside the head
  assertEmptyGzipError(t, 0);
  assert.notEqual(recordHolding(t, 0).t, recordHolding(t, GZIP_EMPTY.length - 1).t);
});

test('the same empty gzip 200 after a 103: error placed and timed after the final head', () => {
  const stream = EARLY_HINTS + GZIP_EMPTY;
  const cut = EARLY_HINTS.length + 14; // inside "HTTP/1.1 200 O|K"
  const t = timelineFor([stream.slice(0, cut), stream.slice(cut)]);
  assert.equal(httpIn(t)[0].kind, 'interim-response');
  assertEmptyGzipError(t, EARLY_HINTS.length);
});

test('control: 200 with Content-Length: 0 and no encoding is a correct empty body', () => {
  const t = timelineFor([head(200, 'OK', ['Content-Length: 0'])]);
  assert.deepEqual(kinds(t), ['response-head']);
  assert.ok(httpIn(t).every((e) => !e.damaged));
});

test('control: 304 with Content-Encoding: gzip has no body, so nothing is decoded and nothing fails', () => {
  const t = timelineFor([head(304, 'Not Modified', ['Content-Encoding: gzip'])]);
  assert.deepEqual(kinds(t), ['response-head']);
  assert.ok(httpIn(t).every((e) => !e.damaged));
});
