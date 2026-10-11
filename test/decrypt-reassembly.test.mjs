// Handshake messages are a stream of their own: one message may span records, one record may
// hold several messages. Re-encrypt the golden server handshake with different record cuts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession, sha256 } from '../src/session.js';
import { buildTimeline } from '../src/timeline.js';
import { decryptSession, parseKeylog, trafficKeys, SUITES } from '../src/tls/decrypt.js';
import { sealRecord } from './helpers/tls-seal.mjs';
import { editStream, replaceBytes } from './helpers/session-edit.mjs';

const golden = JSON.parse(readFileSync(new URL('./fixtures/github-robots/session.json', import.meta.url), 'utf8'));
const original = decryptSession(loadSession(golden).tls);
const SUITE = SUITES[original.suite.id];
const keys = trafficKeys(SUITE, parseKeylog(golden.tls.keylog).secrets.SERVER_HANDSHAKE_TRAFFIC_SECRET);
const HANDSHAKE = 22;
const HEADER = 5;
const CUT = 1000; // bytes of the Certificate message that go into its own record

const hsRecords = original.server.records.filter((r) => r.epoch === 'handshake');
const transcript = Buffer.concat(hsRecords.map((r) => r.content)); // EE, Certificate, CertificateVerify, Finished
const eeLength = hsRecords[0].content.length;
const pieces = [
  transcript.subarray(0, eeLength), // EncryptedExtensions alone
  transcript.subarray(eeLength, eeLength + CUT), // first part of Certificate: no complete message
  transcript.subarray(eeLength + CUT), // rest of Certificate + CertificateVerify + Finished
];
const resealed = Buffer.concat(pieces.map((p, seq) => sealRecord(SUITE, keys, seq, HANDSHAKE, p)));
const start = hsRecords[0].offset;
const end = hsRecords.at(-1).offset + HEADER + hsRecords.at(-1).length;
const recut = editStream(golden, 'in', replaceBytes(start, end - start, resealed));
const session = loadSession(recut);
const decrypted = decryptSession(session.tls);
const recutHs = decrypted.server.records.filter((r) => r.epoch === 'handshake');

test('handshake messages are reassembled across record boundaries', () => {
  assert.deepEqual(recutHs.map((r) => r.handshakeTypes), [[8], [], [11, 15, 20]]);
});

test('the epoch switches after the Finished that closed a multi-message record', () => {
  const app = decrypted.server.records.filter((r) => r.epoch === 'application');
  assert.equal(app[0].seq, 0);
  assert.ok(app.every((r) => !r.damaged));
  assert.equal(sha256(decrypted.server.appData), golden.plaintext.receivedSha256);
});

test('the timeline names a record that holds only part of a message', () => {
  const summaries = buildTimeline(session).events
    .filter((e) => e.layer === 'tls' && e.kind === 'record' && e.dir === 'in' && e.detail.epoch === 'handshake')
    .map((e) => e.summary);
  assert.deepEqual(summaries, [
    'encrypted (handshake #0): EncryptedExtensions',
    'encrypted (handshake #1): Handshake fragment',
    'encrypted (handshake #2): Certificate + CertificateVerify + Finished',
  ]);
});
