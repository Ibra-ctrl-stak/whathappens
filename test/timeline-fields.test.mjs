// Every timeline event links to the field tree of its own bytes, or says null explicitly.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { buildTimeline } from '../src/timeline.js';
import { walk } from '../src/fields.js';
import { editStream, dropTail } from './helpers/session-edit.mjs';

const json = (name) => JSON.parse(readFileSync(new URL(`./fixtures/github-robots/${name}`, import.meta.url), 'utf8'));
const golden = json('session.json');
const expected = json('expected.json');
const { events, buffers } = buildTimeline(loadSession(golden));
const ofKind = (layer, kind) => events.filter((e) => e.layer === layer && e.kind === kind);
const childNames = (f) => f.children.map((c) => c.name);

test('every event has a fields property: a tree or an explicit null', () => {
  for (const e of events) {
    assert.ok(Object.hasOwn(e, 'fields'), `${e.layer}/${e.kind}`);
    if (e.fields !== null) assert.ok(typeof e.fields.name === 'string' && Array.isArray(e.fields.children));
  }
});

test('a field tree covers exactly its event\'s bytes, in the event\'s buffer', () => {
  for (const e of events.filter((ev) => ev.fields)) {
    assert.deepEqual([e.fields.offset, e.fields.length], [e.offset, e.length], `${e.layer}/${e.kind} ${e.summary}`);
    walk(e.fields, (f) => assert.ok(f.offset >= e.offset && f.offset + f.length <= e.offset + e.length, f.name));
    assert.ok(e.offset + e.length <= buffers[e.buffer].length);
  }
});

test('TLS records: header fields, then plaintext fragment or ciphertext + auth tag', () => {
  for (const r of ofKind('tls', 'record')) {
    const [type] = r.fields.children;
    assert.equal(type.value, r.detail.outerType);
    if (r.detail.epoch === 'plaintext') {
      assert.deepEqual(childNames(r.fields), ['content_type', 'legacy_record_version', 'length', 'fragment']);
    } else {
      assert.deepEqual(childNames(r.fields), ['content_type', 'legacy_record_version', 'length', 'encrypted_record']);
      assert.deepEqual(childNames(r.fields.children[3]), ['ciphertext', 'auth_tag']);
      assert.equal(r.fields.children[3].children[1].length, 16);
    }
  }
});

test('one handshake-message event per message, with its parsed tree, in the handshake stream buffer', () => {
  for (const [dir, name] of [['out', 'client'], ['in', 'server']]) {
    const messages = ofKind('tls', 'handshake-message').filter((e) => e.dir === dir);
    assert.deepEqual(messages.map((m) => m.detail.type), expected.tls.handshakeTypes[name]);
    assert.ok(messages.every((m) => m.buffer === `tls-hs/${dir}` && m.fields.name === m.summary));
  }
  const [clientHello] = ofKind('tls', 'handshake-message');
  assert.equal(clientHello.fields.name, 'ClientHello');
});

test('HTTP events point at their part of the message tree', () => {
  assert.equal(ofKind('http', 'request')[0].fields.name, 'head');
  assert.ok(childNames(ofKind('http', 'request')[0].fields).includes('start_line'));
  assert.equal(ofKind('http', 'response-head')[0].fields.name, 'head');
  assert.equal(ofKind('http', 'response-body')[0].fields.name, 'body');
});

test('events with nothing parsed carry null, not a placeholder', () => {
  for (const e of events.filter((ev) => ev.layer === 'dns' || ev.layer === 'tcp' || ev.kind === 'secure')) {
    assert.equal(e.fields, null, `${e.layer}/${e.kind}`);
  }
  const cut = buildTimeline(loadSession(editStream(golden, 'in', dropTail(10))));
  const incomplete = cut.events.find((e) => e.kind === 'record' && e.damaged && /incomplete/.test(e.problem));
  assert.equal(incomplete.fields, null);
});

test('every byte of an event belongs to exactly one leaf field', () => {
  let checked = 0;
  for (const e of events.filter((ev) => ev.fields)) {
    const owners = new Array(e.length).fill(0);
    walk(e.fields, (f) => {
      if (f.children.length > 0) return;
      for (let i = f.offset; i < f.offset + f.length; i += 1) owners[i - e.offset] += 1;
    });
    assert.ok(owners.every((n) => n === 1), `${e.layer}/${e.kind} ${e.summary}: ${owners.findIndex((n) => n !== 1)}`);
    checked += 1;
  }
  assert.ok(checked > 20, `${checked} events with fields`);
});
