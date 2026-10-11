// Golden session: a real github.com/robots.txt run, byte-for-byte verified against a Wireshark capture.
// expected.json was produced by tshark (tools/extract-expected.mjs), not by our code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession, sha256 } from '../src/session.js';
import { buildQuery, parseResponse, TYPE } from '../src/dns/packet.js';
import { decryptSession } from '../src/tls/decrypt.js';

const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/github-robots/${name}`, import.meta.url), 'utf8'));
const session = loadSession(fixture('session.json'));
const expected = fixture('expected.json');
const decrypted = decryptSession({ raw: session.tls.raw, keylog: session.tls.keylog });

const exchangeOn = (port) => session.dns.find((e) => e.localPort === port);
const rdata = (msg, type) =>
  [...msg.answers, ...msg.authority, ...msg.additional].filter((r) => r.type === type).map((r) => r.data).sort();

for (const want of expected.dns) {
  test(`DNS response on :${want.localPort} parses to what Wireshark saw`, () => {
    const msg = parseResponse(exchangeOn(want.localPort).response);
    assert.equal(msg.id, want.id);
    assert.equal(msg.questions[0].name, want.qname);
    assert.equal(msg.authoritative, want.authoritative);
    assert.equal(msg.truncated, want.truncated);
    assert.equal(msg.rcode, want.rcode);
    assert.deepEqual(
      { answers: msg.answers.length, authority: msg.authority.length, additional: msg.additional.length },
      want.counts,
    );
    assert.deepEqual(rdata(msg, TYPE.A), want.a);
    assert.deepEqual(rdata(msg, TYPE.NS), want.ns);
  });

  test(`DNS query on :${want.localPort} is rebuilt byte-for-byte from its id and name`, () => {
    const e = exchangeOn(want.localPort);
    const rebuilt = buildQuery({ id: e.query.readUInt16BE(0), name: e.qname, type: TYPE.A });
    assert.deepEqual(rebuilt, e.query);
  });
}

test('TLS: randoms and cipher suite match Wireshark', () => {
  assert.equal(decrypted.clientRandom, expected.tls.clientRandom);
  assert.equal(decrypted.serverRandom, expected.tls.serverRandom);
  assert.equal(decrypted.suite.id, expected.tls.cipherSuite);
});

// Plaintext records report their outer type; decrypted ones their inner type, as Wireshark does.
const recordShape = (records) =>
  records.map((r) => [r.epoch === 'plaintext' ? r.outerType : r.contentType, r.length]);

for (const dir of ['client', 'server']) {
  test(`TLS: ${dir} record sequence (type, length) matches Wireshark`, () => {
    assert.deepEqual(recordShape(decrypted[dir].records), expected.tls.records[dir]);
  });

  test(`TLS: ${dir} handshake message types match Wireshark`, () => {
    assert.deepEqual(decrypted[dir].records.flatMap((r) => r.handshakeTypes ?? []), expected.tls.handshakeTypes[dir]);
  });
}

test('TLS: our decryption equals what Node delivered (sha256 recorded at capture time)', () => {
  assert.equal(sha256(decrypted.client.appData), session.plaintext.sentSha256);
  assert.equal(sha256(decrypted.server.appData), session.plaintext.receivedSha256);
});

test('TLS: records tile each stream with no gaps or leftovers', () => {
  assert.deepEqual(decrypted.trailingBytes, { client: 0, server: 0 });
});

test.todo('TLS: SNI and ALPN from ClientHello/EncryptedExtensions match Wireshark (Day 4 field parsers)');
