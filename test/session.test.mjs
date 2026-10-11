// session.json round trip: what we load is exactly what we would save.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession, serializeSession, SESSION_FORMAT } from '../src/session.js';
import { decryptSession } from '../src/tls/decrypt.js';

const fixtureJson = JSON.parse(readFileSync(new URL('./fixtures/github-robots/session.json', import.meta.url), 'utf8'));

/** Rebuild the recorder-shaped input serializeSession expects from a loaded session. */
function asRecorded(loaded) {
  const { client, server } = decryptSession({ raw: loaded.tls.raw, keylog: loaded.tls.keylog });
  return {
    startedAt: Date.parse(loaded.startedAt),
    host: loaded.host,
    path: loaded.path,
    dns: loaded.dns,
    tls: { ...loaded.tls, tls: loaded.tls.info, plaintext: { sent: client.appData, received: server.appData } },
  };
}

test('load -> serialize reproduces the fixture JSON exactly', () => {
  assert.deepEqual(serializeSession(asRecorded(loadSession(fixtureJson))), fixtureJson);
});

test('a lost DNS exchange survives the round trip with its reason', () => {
  const recorded = asRecorded(loadSession(fixtureJson));
  const lost = { ...recorded.dns[0], response: null, receivedAt: null, failedAt: recorded.dns[0].sentAt + 2500, error: 'timeout' };
  const saved = serializeSession({ ...recorded, dns: [lost] });
  assert.equal(saved.dns[0].responseHex, null);
  assert.equal(saved.dns[0].error, 'timeout');
  const reloaded = loadSession(JSON.parse(JSON.stringify(saved)));
  assert.equal(reloaded.dns[0].response, null);
  assert.deepEqual(reloaded.dns[0].query, lost.query);
});

test('recordings in another format are refused, not misread', () => {
  const { format, ...v1 } = fixtureJson;
  assert.equal(format, SESSION_FORMAT);
  assert.throws(() => loadSession(v1), /format 1 is not supported/);
});
