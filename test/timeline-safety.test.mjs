// Strings that came from the network must reach the timeline without control characters:
// no terminal escapes today (timeline.mjs), no surprises for the Day 5 page either.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { buildTimeline } from '../src/timeline.js';
import { decryptSession, parseKeylog, trafficKeys, SUITES } from '../src/tls/decrypt.js';
import { sealRecord } from './helpers/tls-seal.mjs';
import { editStream, replaceBytes } from './helpers/session-edit.mjs';

const golden = JSON.parse(readFileSync(new URL('./fixtures/github-robots/session.json', import.meta.url), 'utf8'));
const loaded = loadSession(golden);
const decrypted = decryptSession({ raw: loaded.tls.raw, keylog: loaded.tls.keylog });
const SUITE = SUITES[decrypted.suite.id];
const { secrets } = parseKeylog(golden.tls.keylog);
const APP_DATA = 23;
const HEADER = 5;
const CONTROL = /[\x00-\x1f\x7f-\x9f]/;

const firstAppRecord = (side) => side.records.find((r) => r.epoch === 'application' && r.contentType === APP_DATA);

function reseal(sessionJson, dir, side, secret, content) {
  const record = firstAppRecord(side);
  const sealed = sealRecord(SUITE, trafficKeys(SUITE, secret), record.seq, APP_DATA, Buffer.from(content, 'latin1'));
  return editStream(sessionJson, dir, replaceBytes(record.offset, HEADER + record.length, sealed));
}

const hostileRequest = 'GET /\x1b[2J HTTP/1.1\r\nHost: a\x1b]0;pwned\x07\r\n\r\n';
const head = firstAppRecord(decrypted.server).content.toString('latin1');
const hostileHead = head
  .replace('HTTP/1.1 200 OK', 'HTTP/1.1 200 O\x1b[31mK')
  .replace('Content-Type: text/plain', 'Content-Type: text/\x9bplain');

const hostile = reseal(
  reseal(golden, 'out', decrypted.client, secrets.CLIENT_TRAFFIC_SECRET_0, hostileRequest),
  'in', decrypted.server, secrets.SERVER_TRAFFIC_SECRET_0, hostileHead,
);
const { events } = buildTimeline(loadSession(hostile));

const strings = (value) =>
  typeof value === 'string' ? [value]
    : value && typeof value === 'object' ? Object.values(value).flatMap(strings)
      : [];

test('the hostile session still parses into request and response events', () => {
  assert.ok(events.some((e) => e.kind === 'request'));
  assert.ok(events.some((e) => e.kind === 'response-head'));
});

test('no summary, problem, detail or field-tree string carries a control character', () => {
  assert.ok(events.some((e) => e.layer === 'http' && e.fields), 'HTTP field trees are part of the check');
  for (const e of events) {
    for (const s of strings({ summary: e.summary, problem: e.problem, detail: e.detail, fields: e.fields })) {
      assert.doesNotMatch(s, CONTROL, `${e.layer}/${e.kind}: ${JSON.stringify(s)}`);
    }
  }
});

test('control characters are shown as visible \\xNN escapes, not deleted', () => {
  const request = events.find((e) => e.kind === 'request');
  assert.match(request.summary, /GET \/\\x1b\[2J/);
  assert.equal(request.detail.host, 'a\\x1b]0;pwned\\x07');
  const response = events.find((e) => e.kind === 'response-head');
  assert.match(response.summary, /200 O\\x1b\[31mK, text\/\\x9bplain/);
});
