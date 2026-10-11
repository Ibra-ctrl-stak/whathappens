// Per direction, the handshake is a byte stream of its own (plaintext hellos + decrypted
// handshake records). Field offsets in Day 4 parsers are positions in this stream.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { decryptSession } from '../src/tls/decrypt.js';

const json = (name) => JSON.parse(readFileSync(new URL(`./fixtures/github-robots/${name}`, import.meta.url), 'utf8'));
const expected = json('expected.json');
const decrypted = decryptSession(loadSession(json('session.json')).tls);
const HANDSHAKE = 22;

for (const dir of ['client', 'server']) {
  const side = decrypted[dir];

  test(`${dir}: message index matches Wireshark's handshake types`, () => {
    assert.deepEqual(side.messages.map((m) => m.type), expected.tls.handshakeTypes[dir]);
  });

  test(`${dir}: messages tile the handshake stream, each starting with its own type and length`, () => {
    let pos = 0;
    for (const m of side.messages) {
      assert.equal(m.offset, pos);
      assert.equal(side.handshake[m.offset], m.type);
      assert.equal(side.handshake.readUIntBE(m.offset + 1, 3), m.length - 4);
      pos += m.length;
    }
    assert.equal(pos, side.handshake.length);
  });

  test(`${dir}: the handshake stream is exactly the handshake content of its records, in order`, () => {
    const content = side.records.filter((r) => r.contentType === HANDSHAKE).map((r) => r.content);
    assert.deepEqual(side.handshake, Buffer.concat(content));
    const offsets = side.records.filter((r) => r.contentType === HANDSHAKE).map((r) => r.handshakeOffset);
    assert.deepEqual(offsets, content.map((_, i) => content.slice(0, i).reduce((n, c) => n + c.length, 0)));
  });
}
