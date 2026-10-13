// DNS packet parsing: answer matching (anti-spoofing) and safe presentation of names.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { buildQuery, parseResponse, isAnswerTo, TYPE } from '../src/dns/packet.js';

const session = loadSession(JSON.parse(readFileSync(new URL('./fixtures/github-robots/session.json', import.meta.url), 'utf8')));
const QR_BIT = 0x80; // high bit of header byte 2

/** A minimal response: the query echoed back with QR set (valid header, question, no answers). */
const echoAsResponse = (query) => {
  const r = Buffer.from(query);
  r[2] |= QR_BIT;
  return r;
};

test('recorded fixture responses are answers to their own queries', () => {
  for (const e of session.dns) assert.equal(isAnswerTo(e.query, e.response), true);
});

test('a response is not accepted for a different query', () => {
  const [a, b] = session.dns;
  assert.equal(isAnswerTo(b.query, a.response), false);
});

const query = buildQuery({ id: 0x1234, name: 'github.com', type: TYPE.A });

for (const [label, response] of [
  ['another transaction id', echoAsResponse(buildQuery({ id: 0x4321, name: 'github.com' }))],
  ['QR bit clear (a query, not a response)', Buffer.from(query)],
  ['another name in the question', echoAsResponse(buildQuery({ id: 0x1234, name: 'evil.example' }))],
  ['another type in the question', echoAsResponse(buildQuery({ id: 0x1234, name: 'github.com', type: TYPE.AAAA }))],
  ['a datagram shorter than a header', Buffer.from([0x12, 0x34, 0x80])],
  ['a header whose question runs off the end', echoAsResponse(query).subarray(0, 16)],
]) {
  test(`rejects ${label}`, () => assert.equal(isAnswerTo(query, response), false));
}

test('question names match case-insensitively (DNS 0x20 randomization)', () => {
  assert.equal(isAnswerTo(query, echoAsResponse(buildQuery({ id: 0x1234, name: 'GitHub.COM' }))), true);
});

/** Response with one A answer whose owner name is given as raw label bytes. */
function responseWithOwner(labels) {
  const header = Buffer.from([0x00, 0x01, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]); // QR+AA, 0 questions, 1 answer
  const name = Buffer.concat([...labels.map((l) => Buffer.concat([Buffer.from([l.length]), l])), Buffer.from([0])]);
  const rr = Buffer.from([0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1]); // A IN ttl=60 10.0.0.1
  return Buffer.concat([header, name, rr]);
}

test('control bytes in a DNS label are escaped as \\DDD, not passed through', () => {
  const msg = parseResponse(responseWithOwner([Buffer.from([0x61, 0x1b, 0x5b, 0x32, 0x4a]), Buffer.from('example')]));
  assert.equal(msg.answers[0].name, 'a\\027[2j.example'); // names are lowercased; ESC escaped
  assert.doesNotMatch(msg.answers[0].name, /[\x00-\x1f\x7f-\xff]/);
});

test('a dot or backslash inside a label is escaped so the name is unambiguous', () => {
  const msg = parseResponse(responseWithOwner([Buffer.from('a.b'), Buffer.from('c\\d'), Buffer.from('example')]));
  assert.equal(msg.answers[0].name, 'a\\.b.c\\\\d.example');
});

test('bytes above 0x7e are escaped, not folded into 7-bit ASCII', () => {
  const msg = parseResponse(responseWithOwner([Buffer.from([0xe9]), Buffer.from('example')]));
  assert.equal(msg.answers[0].name, '\\233.example');
});

// ---- limits of names from the network ------------------------------------------------------------

test('a compression pointer cut off at the end of the packet is an error, not a jump to offset 0', () => {
  const header = Buffer.from([0x00, 0x00, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]); // id 0: offset 0 reads as an empty name
  const owner = Buffer.from([7, ...Buffer.from('example'), 0]);
  const rr = Buffer.from([0, 5, 0, 1, 0, 0, 0, 60, 0, 1, 0xc0]); // CNAME, rdlength 1: only the first pointer byte
  assert.throws(() => parseResponse(Buffer.concat([header, owner, rr])), /DNS compression pointer runs past end of packet/);
});

test('a DNS name longer than 255 bytes on the wire is refused; exactly 255 is accepted', () => {
  const label = (n) => Buffer.alloc(n, 0x61);
  assert.throws(() => parseResponse(responseWithOwner([label(63), label(63), label(63), label(63), label(10)])),
    /DNS name longer than 255 bytes/);
  const longest = parseResponse(responseWithOwner([label(63), label(63), label(63), label(61)])); // 3*64 + 62 + 1 = 255
  assert.equal(longest.answers[0].name.length, 63 * 3 + 61 + 3);
});
