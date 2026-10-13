// Broken sessions still produce a timeline: what cannot be read shows up as a damaged event
// over its bytes, and the layers that are fine stay intact.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { buildTimeline } from '../src/timeline.js';
import { decryptSession, parseKeylog, trafficKeys, SUITES } from '../src/tls/decrypt.js';
import { respond, CNAME } from './helpers/dns-build.mjs';
import { sealRecord } from './helpers/tls-seal.mjs';
import { editStream, replaceBytes, flipByte, dropTail, withDnsResponse } from './helpers/session-edit.mjs';

const json = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const golden = json('./fixtures/github-robots/session.json');
const rfc = json('./vectors/rfc8448-simple-1rtt.json');
const loaded = loadSession(golden);
const decrypted = decryptSession({ raw: loaded.tls.raw, keylog: loaded.tls.keylog });
const SUITE = SUITES[decrypted.suite.id];
const { secrets } = parseKeylog(golden.tls.keylog);
const CONTENT = { ALERT: 21, HANDSHAKE: 22, APP_DATA: 23 };
const HEADER = 5;

const timelineOf = (sessionJson) => buildTimeline(loadSession(sessionJson));
const appRecords = (side) => side.records.filter((r) => r.epoch === 'application' && r.contentType === CONTENT.APP_DATA);
const ofKind = (t, layer, kind) => t.events.filter((e) => e.layer === layer && e.kind === kind);
const damaged = (t) => t.events.filter((e) => e.damaged);

test('test helper sealRecord reproduces an RFC 8448 record byte for byte', () => {
  const v = rfc.records.clientApplicationData;
  const keys = trafficKeys(SUITES[0x1301], Buffer.from(rfc.keys.clientApplication.secret, 'hex'));
  const sealed = sealRecord(SUITES[0x1301], keys, v.seq, CONTENT.APP_DATA, Buffer.from(v.payload, 'hex'));
  assert.equal(sealed.toString('hex'), v.record);
});

test('the golden session has no damaged events, and every event says so explicitly', () => {
  const t = timelineOf(golden);
  assert.ok(t.events.every((e) => e.damaged === false && e.problem === null));
});

test('a record failing authentication is damaged, so is everything after it in that direction; other layers survive', () => {
  const target = appRecords(decrypted.server)[0]; // carries the HTTP response head
  const t = timelineOf(editStream(golden, 'in', flipByte(target.offset + HEADER + 10)));
  const serverRecords = ofKind(t, 'tls', 'record').filter((e) => e.dir === 'in');
  const hit = serverRecords.findIndex((e) => e.offset === target.offset);
  assert.match(serverRecords[hit].problem, /cannot decrypt/);
  assert.ok(serverRecords.slice(hit + 1).every((e) => e.damaged && /earlier record/.test(e.problem)));
  assert.ok(serverRecords.slice(0, hit).every((e) => !e.damaged), 'records before the damage are fine');
  assert.ok(ofKind(t, 'tls', 'record').filter((e) => e.dir === 'out').every((e) => !e.damaged));
  assert.equal(ofKind(t, 'dns', 'response').length, golden.dns.length);
  assert.equal(ofKind(t, 'http', 'request').length, 1);
  assert.equal(ofKind(t, 'http', 'response-head').length, 0, 'no plaintext, no HTTP response to show');
});

test('a stream cut mid-record ends in a damaged incomplete record, and the truncated body is flagged', () => {
  const t = timelineOf(editStream(golden, 'in', dropTail(400)));
  const last = ofKind(t, 'tls', 'record').filter((e) => e.dir === 'in').at(-1);
  assert.equal(last.damaged, true);
  assert.match(last.problem, /incomplete record/);
  assert.equal(last.offset + last.length, t.buffers['tcp/in'].length, 'records still tile the stream');
  const [body] = ofKind(t, 'http', 'response-body');
  assert.equal(body.damaged, true);
  assert.match(body.problem, /truncated/);
});

test('an HTTP request that does not parse becomes one damaged HTTP event over its bytes', () => {
  const [record] = appRecords(decrypted.client);
  const keys = trafficKeys(SUITE, secrets.CLIENT_TRAFFIC_SECRET_0);
  const junk = Buffer.from('HELLO\r\n\r\n');
  const sealed = sealRecord(SUITE, keys, record.seq, CONTENT.APP_DATA, junk);
  const t = timelineOf(editStream(golden, 'out', replaceBytes(record.offset, HEADER + record.length, sealed)));
  const [bad] = t.events.filter((e) => e.layer === 'http' && e.dir === 'out');
  assert.equal(bad.kind, 'message');
  assert.equal(bad.damaged, true);
  assert.match(bad.problem, /start line/);
  assert.deepEqual([bad.buffer, bad.offset, bad.length], ['http/out', 0, junk.length]);
  assert.equal(ofKind(t, 'http', 'response-head').length, 1, 'the response side is unaffected');
});

test('bytes after the declared response body are their own damaged event', () => {
  const last = appRecords(decrypted.server).at(-1);
  const keys = trafficKeys(SUITE, secrets.SERVER_TRAFFIC_SECRET_0);
  const sealed = sealRecord(SUITE, keys, last.seq, CONTENT.APP_DATA, Buffer.concat([last.content, Buffer.from('JUNK')]));
  const t = timelineOf(editStream(golden, 'in', replaceBytes(last.offset, HEADER + last.length, sealed)));
  const [body] = ofKind(t, 'http', 'response-body');
  assert.equal(body.damaged, false);
  const [extra] = ofKind(t, 'http', 'extra-bytes');
  assert.equal(extra.damaged, true);
  assert.equal(extra.length, 4);
  assert.equal(t.buffers['http/in'].subarray(extra.offset, extra.offset + extra.length).toString(), 'JUNK');
});

const lastQuery = loaded.dns.at(-1).query;
const lastIndex = golden.dns.length - 1;
const dnsSummary = (response) => ofKind(timelineOf(withDnsResponse(golden, lastIndex, response)), 'dns', 'response').at(-1);

test('DNS: NXDOMAIN is named as such, not as a referral', () => {
  const e = dnsSummary(respond(lastQuery, { aa: true, rcode: 3 }));
  assert.match(e.summary, /NXDOMAIN/);
  assert.equal(e.damaged, false);
});

test('DNS: an empty NOERROR answer says there are no records', () => {
  assert.match(dnsSummary(respond(lastQuery, { aa: true })).summary, /no records/);
});

test('DNS: a CNAME-only answer shows the alias target', () => {
  assert.match(dnsSummary(respond(lastQuery, { aa: true, answers: [CNAME('github.com', 'gh.example.test')] })).summary, /CNAME gh\.example\.test/);
});

test('DNS: an undecodable response is a damaged event over its bytes', () => {
  const bad = respond(lastQuery, {});
  bad.writeUInt16BE(1, 6); // one answer promised, none present
  const e = dnsSummary(bad);
  assert.equal(e.damaged, true);
  assert.match(e.problem, /runs past end|malformed/);
  assert.equal(e.length, bad.length);
});

// ---- DNS exchanges that failed before the query went out -------------------------------------------

const notSentFirst = (failedAt) => {
  const first = golden.dns[0];
  return { ...first, localPort: null, sentAt: null, receivedAt: null, responseHex: null, failedAt, error: 'bind EACCES' };
};

test('DNS: a query that failed before bind is not shown as sent; its real failure time is kept', () => {
  const t = timelineOf({ ...golden, dns: [notSentFirst(golden.dns[0].sentAt - 3), ...golden.dns] });
  const [e] = t.events.filter((ev) => ev.buffer === 'dns/0/query');
  assert.deepEqual([e.layer, e.kind, e.t], ['dns', 'not-sent', 0]);
  assert.match(e.summary, /^A\? github\.com -> .+ not sent: bind EACCES$/);
  assert.equal(e.length, Buffer.from(golden.dns[0].queryHex, 'hex').length, 'the bytes that would have been sent');
  assert.equal(ofKind(t, 'dns', 'query').length, golden.dns.length, 'only queries that went out are queries');
  assert.equal(ofKind(t, 'tls', 'record').length, ofKind(timelineOf(golden), 'tls', 'record').length, 'other layers intact');
});

test('DNS: an exchange with no recorded time is listed after the timed events, never at an invented time', () => {
  const lostNoTime = { ...golden.dns[1], responseHex: null, receivedAt: null, failedAt: null, error: 'timeout' };
  const t = timelineOf({ ...golden, dns: [notSentFirst(null), lostNoTime, ...golden.dns.slice(2)] });
  const untimed = t.events.filter((e) => e.t === null);
  assert.deepEqual(untimed.map((e) => [e.kind, e.buffer]), [['not-sent', 'dns/0/query'], ['lost', null]]);
  assert.ok(untimed.every((e) => /no time recorded/.test(e.summary)));
  assert.deepEqual(t.events.slice(-2), untimed, 'after every timed event');
  assert.equal(ofKind(t, 'dns', 'query').filter((e) => e.buffer === 'dns/1/query')[0].t !== null, true, 'its query did go out, with a time');
});

// ---- TLS record and hello lengths --------------------------------------------------------------------

test('a record header with a length above the TLS limit is named, not decrypted; earlier records survive', () => {
  const tooLong = Buffer.concat([Buffer.from([0x17, 0x03, 0x03, 0x41, 0x01]), Buffer.alloc(0x4101)]); // 16641 > 2^14 + 256
  const t = timelineOf(editStream(golden, 'in', (s) => Buffer.concat([s, tooLong])));
  const last = ofKind(t, 'tls', 'record').filter((e) => e.dir === 'in').at(-1);
  assert.equal(last.damaged, true);
  assert.match(last.problem, /record length 16641 exceeds the TLS limit of 16640 bytes/);
  assert.equal(last.length, tooLong.length);
  assert.equal(last.offset + last.length, t.buffers['tcp/in'].length);
  assert.equal(damaged(t).length, 1, 'everything before it still decrypts');
});

test('an encrypted record body shorter than the AEAD tag is named so; a forged 17-byte body still fails authentication', async () => {
  const { decryptRecord } = await import('../src/tls/decrypt.js');
  const keys = trafficKeys(SUITE, secrets.SERVER_TRAFFIC_SECRET_0);
  const record = (n) => ({ header: Buffer.from([0x17, 0x03, 0x03, 0, n]), body: Buffer.alloc(n, 7) });
  assert.throws(() => decryptRecord(SUITE, keys, 0, record(10)), /record body of 10 bytes is shorter than the 16-byte AEAD tag plus a content type/);
  assert.throws(() => decryptRecord(SUITE, keys, 0, record(16)), /shorter than the 16-byte AEAD tag plus a content type/);
  assert.throws(() => decryptRecord(SUITE, keys, 0, record(17)), /unable to authenticate/);
});

test('a ClientHello or ServerHello too short for its fixed fields is named, not read past its end', () => {
  const handshakeRecord = (type, body) => Buffer.concat([Buffer.from([0x16, 0x03, 0x03, 0, body.length + 4, type, 0, 0, body.length]), body]);
  const shortServer = editStream(golden, 'in', () => handshakeRecord(2, Buffer.from([0x03, 0x03, 1, 2, 3, 4])));
  assert.throws(() => decryptSession(loadSession(shortServer).tls), /ServerHello is too short \(6 bytes\)/);
  const t = timelineOf(shortServer);
  assert.match(ofKind(t, 'tls', 'stream')[0].problem, /ServerHello is too short/);
  assert.equal(ofKind(t, 'dns', 'query').length, golden.dns.length, 'DNS and TCP events stay');
  const shortClient = editStream(golden, 'out', () => handshakeRecord(1, Buffer.from([0x03, 0x03, 9, 9])));
  assert.throws(() => decryptSession(loadSession(shortClient).tls), /ClientHello is too short \(4 bytes\)/);
});
