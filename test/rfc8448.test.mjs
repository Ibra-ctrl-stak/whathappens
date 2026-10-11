// HKDF-Expand-Label, traffic keys and record decryption against the official RFC 8448 §3 trace.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hkdfExpandLabel, trafficKeys, decryptRecord, splitRecords, SUITES } from '../src/tls/decrypt.js';

const vectors = JSON.parse(readFileSync(new URL('./vectors/rfc8448-simple-1rtt.json', import.meta.url), 'utf8'));
const hex = (s) => Buffer.from(s, 'hex');
const SUITE = SUITES[0x1301]; // RFC 8448 traces use TLS_AES_128_GCM_SHA256
const CONTENT = { ALERT: 21, HANDSHAKE: 22, APP_DATA: 23 };

// Which keys protect which record, and what the inner content type must be.
const RECORD_CASES = [
  ['serverHandshake', 'serverHandshake', CONTENT.HANDSHAKE],
  ['clientFinished', 'clientHandshake', CONTENT.HANDSHAKE],
  ['serverNewSessionTicket', 'serverApplication', CONTENT.HANDSHAKE],
  ['clientApplicationData', 'clientApplication', CONTENT.APP_DATA],
  ['serverApplicationData', 'serverApplication', CONTENT.APP_DATA],
  ['clientAlert', 'clientApplication', CONTENT.ALERT],
  ['serverAlert', 'serverApplication', CONTENT.ALERT],
];

const keysFor = (name) => {
  const k = vectors.keys[name];
  return trafficKeys(SUITE, hex(k.secret));
};

const onlyRecord = (recordHex) => {
  const { records, trailing } = splitRecords(hex(recordHex));
  assert.equal(records.length, 1);
  assert.equal(trailing, 0);
  return records[0];
};

test('HKDF-Expand-Label with a transcript-hash context derives "s hs traffic"', () => {
  const v = vectors.expandLabel;
  const out = hkdfExpandLabel('sha256', hex(v.secret), v.label, hex(v.context), 32);
  assert.equal(out.toString('hex'), v.expanded);
});

for (const [name, k] of Object.entries(vectors.keys)) {
  test(`traffic key and iv for ${name} (RFC line ${k.rfcLine})`, () => {
    const keys = trafficKeys(SUITE, hex(k.secret));
    assert.equal(keys.key.toString('hex'), k.key);
    assert.equal(keys.iv.toString('hex'), k.iv);
  });
}

for (const [recordName, keysName, contentType] of RECORD_CASES) {
  const v = vectors.records[recordName];
  test(`decrypts ${recordName} (seq ${v.seq}, RFC line ${v.rfcLine})`, () => {
    const out = decryptRecord(SUITE, keysFor(keysName), v.seq, onlyRecord(v.record));
    assert.equal(out.contentType, contentType);
    assert.equal(out.content.toString('hex'), v.payload);
  });
}

test('rejects a record whose auth tag was altered', () => {
  const v = vectors.records.clientApplicationData;
  const tampered = hex(v.record);
  tampered[tampered.length - 1] ^= 0x01;
  const [record] = splitRecords(tampered).records;
  assert.throws(() => decryptRecord(SUITE, keysFor('clientApplication'), v.seq, record));
});

test('rejects a record decrypted with the wrong sequence number', () => {
  const v = vectors.records.serverApplicationData;
  assert.throws(() => decryptRecord(SUITE, keysFor('serverApplication'), v.seq + 1, onlyRecord(v.record)));
});

test('rejects a record whose header (AAD) was altered', () => {
  const v = vectors.records.clientFinished;
  const record = onlyRecord(v.record);
  const header = Buffer.from(record.header);
  header[2] = 0x01; // legacy_record_version 0x0303 -> 0x0301
  assert.throws(() => decryptRecord(SUITE, keysFor('clientHandshake'), v.seq, { ...record, header }));
});
