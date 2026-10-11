// ClientHello / ServerHello / EncryptedExtensions as field trees: every field points at its
// own bytes in the direction's handshake stream; values checked against Wireshark.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { decryptSession } from '../src/tls/decrypt.js';
import { parseHandshake } from '../src/tls/handshake-fields.js';
import { find, findAll, walk } from '../src/fields.js';

const json = (name) => JSON.parse(readFileSync(new URL(`./fixtures/github-robots/${name}`, import.meta.url), 'utf8'));
const expected = json('expected.json').tls;
const decrypted = decryptSession(loadSession(json('session.json')).tls);
const TYPE = { CLIENT_HELLO: 1, SERVER_HELLO: 2, ENCRYPTED_EXTENSIONS: 8 };

const messageTree = (dir, type) => {
  const side = decrypted[dir];
  return parseHandshake(side.handshake, side.messages.find((m) => m.type === type));
};
const bytesOf = (dir, f) => decrypted[dir].handshake.subarray(f.offset, f.offset + f.length);

const ch = messageTree('client', TYPE.CLIENT_HELLO);
const sh = messageTree('server', TYPE.SERVER_HELLO);
const ee = messageTree('server', TYPE.ENCRYPTED_EXTENSIONS);

test('every field\'s children tile its bytes exactly (no gaps, no overlaps)', () => {
  for (const [dir, side] of Object.entries({ client: decrypted.client, server: decrypted.server })) {
    for (const message of side.messages) {
      walk(parseHandshake(side.handshake, message), (f) => {
        if (f.children.length === 0) return;
        let pos = f.offset;
        for (const c of f.children) {
          assert.equal(c.offset, pos, `${dir} ${f.name} > ${c.name} starts at ${c.offset}, expected ${pos}`);
          pos += c.length;
        }
        assert.equal(pos, f.offset + f.length, `${dir} ${f.name}: children end at ${pos}`);
      });
    }
  }
});

test('ClientHello: the message node covers exactly the indexed message', () => {
  const m = decrypted.client.messages[0];
  assert.deepEqual([ch.name, ch.offset, ch.length], ['ClientHello', m.offset, m.length]);
});

test('ClientHello: random and offered cipher suites', () => {
  assert.equal(find(ch, 'random').value, decrypted.clientRandom);
  assert.ok(findAll(find(ch, 'cipher_suites'), 'cipher_suite').some((f) => f.value === expected.cipherSuite));
});

test('ClientHello: extension types in wire order match Wireshark', () => {
  const types = find(ch, 'extensions').children.slice(1).map((ext) => find(ext, 'extension_type').value);
  assert.deepEqual(types, expected.clientHello.extensionTypes);
});

test('ClientHello: SNI host_name, value and bytes', () => {
  const host = find(ch, 'host_name');
  assert.equal(host.value, expected.clientHello.sni);
  assert.equal(bytesOf('client', host).subarray(2).toString('ascii'), expected.clientHello.sni); // after the u16 length
});

test('ClientHello: ALPN protocol names offered', () => {
  assert.deepEqual(findAll(find(ch, 'application_layer_protocol_negotiation'), 'protocol_name').map((f) => f.value), expected.clientHello.alpn);
});

test('ClientHello: supported_versions', () => {
  assert.deepEqual(findAll(find(ch, 'supported_versions'), 'version').map((f) => f.value), expected.clientHello.supportedVersions);
  assert.equal(find(find(ch, 'supported_versions'), 'version').label, 'TLS 1.3');
});

test('ClientHello: key_share groups and key sizes, with group names', () => {
  const entries = findAll(find(ch, 'key_share'), 'key_share_entry');
  assert.deepEqual(entries.map((e) => ({ group: find(e, 'group').value, keyLength: find(e, 'key_exchange').length - 2 })), expected.clientHello.keyShare);
  assert.deepEqual(entries.map((e) => find(e, 'group').label), ['X25519MLKEM768', 'x25519']);
});

test('ServerHello: random, chosen suite, selected version and key share', () => {
  assert.equal(find(sh, 'random').value, decrypted.serverRandom);
  assert.equal(find(sh, 'cipher_suite').value, expected.cipherSuite);
  assert.equal(find(sh, 'cipher_suite').label, 'TLS_AES_128_GCM_SHA256');
  assert.equal(find(sh, 'selected_version').value, expected.serverHello.supportedVersion);
  const share = find(sh, 'server_share');
  assert.deepEqual({ group: find(share, 'group').value, keyLength: find(share, 'key_exchange').length - 2 }, expected.serverHello.keyShare);
});

test('EncryptedExtensions: ALPN selected by the server', () => {
  assert.equal(find(ee, 'protocol_name').value, expected.encryptedExtensions.alpn);
});

test('a corrupted extension length gives a field tree with a problem, not an exception', () => {
  const m = decrypted.client.messages[0];
  const stream = Buffer.from(decrypted.client.handshake);
  const sni = find(ch, 'server_name');
  stream.writeUInt16BE(0xffff, sni.offset + 2); // extension length far past the message end
  const tree = parseHandshake(stream, m);
  assert.equal(tree.name, 'ClientHello');
  assert.match(tree.problem, /past|needs/);
});

test('a broken body inside one extension flags only that extension; the rest still parse', () => {
  const m = decrypted.client.messages[0];
  const stream = Buffer.from(decrypted.client.handshake);
  const list = find(find(ch, 'server_name'), 'server_name_list');
  stream.writeUInt16BE(list.length, list.offset); // inner list claims 2 more bytes than the extension holds
  const tree = parseHandshake(stream, m);
  assert.equal(tree.problem, undefined);
  const sni = find(tree, 'server_name');
  assert.match(sni.problem, /server_name_list/);
  assert.equal(find(sni, 'data').length, find(find(ch, 'server_name'), 'extension_data').length - 2, 'kept as raw bytes');
  assert.deepEqual(findAll(find(tree, 'key_share'), 'group').map((g) => g.label), ['X25519MLKEM768', 'x25519']);
});
