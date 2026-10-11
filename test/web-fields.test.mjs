// Page-side helpers over a field tree (web/fields.js): indexing, byte -> owning leaf, display text.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { buildTimeline } from '../src/timeline.js';
import { eventFields } from '../src/server/view-model.js';
import { indexTree, ownerOf, ancestors, describe } from '../web/fields.js';

const golden = JSON.parse(readFileSync(new URL('./fixtures/github-robots/session.json', import.meta.url), 'utf8'));
const timeline = buildTimeline(loadSession(golden));
const fieldsOf = eventFields(timeline);
const treeOf = (predicate) => {
  const i = timeline.events.findIndex(predicate);
  return { event: timeline.events[i], tree: fieldsOf(i).fields };
};

const { event: chEvent, tree: ch } = treeOf((e) => e.kind === 'handshake-message' && e.summary === 'ClientHello');
const index = indexTree(ch);

test('indexTree numbers nodes in pre-order with parent links and depth', () => {
  assert.equal(index.nodes[0].node, ch);
  assert.equal(index.nodes[0].parent, null);
  assert.equal(index.nodes[0].depth, 0);
  index.nodes.forEach((n, id) => {
    assert.equal(n.id, id);
    if (n.parent !== null) assert.equal(index.nodes[n.parent].depth, n.depth - 1);
  });
});

test('ownerOf: every byte of the event maps to the one leaf that covers it', () => {
  for (let pos = chEvent.offset; pos < chEvent.offset + chEvent.length; pos += 1) {
    const leaf = index.nodes[ownerOf(index, pos)].node;
    assert.equal(leaf.children.length, 0);
    assert.ok(leaf.offset <= pos && pos < leaf.offset + leaf.length);
  }
  assert.equal(ownerOf(index, chEvent.offset + chEvent.length), null);
  assert.equal(ownerOf(index, chEvent.offset - 1), null);
});

test('a byte of the SNI name belongs to host_name > data, inside server_name', () => {
  const host = index.nodes.find((n) => n.node.name === 'host_name').node;
  const id = ownerOf(index, host.offset + 2); // first byte after the u16 length
  const path = ancestors(index, id).map((n) => n.node.name);
  assert.deepEqual(path.slice(-3), ['server_name', 'host_name', 'data']);
  assert.equal(path[0], 'ClientHello');
});

test('describe: label first, then value; long strings are shortened; certificates show CN', () => {
  const group = index.nodes.find((n) => n.node.name === 'group').node;
  assert.equal(describe(group), `${group.label} (${group.value})`);
  assert.equal(describe({ name: 'x', value: 'a'.repeat(100), label: null, children: [] }), `${'a'.repeat(63)}…`);
  assert.equal(describe({ name: 'length', value: 5, label: null, children: [] }), '5');
  assert.equal(describe({ name: 'fragment', value: null, label: null, children: [] }), '');
  const { tree: certMsg } = treeOf((e) => e.kind === 'handshake-message' && e.summary === 'Certificate');
  const certData = indexTree(certMsg).nodes.find((n) => n.node.x509).node;
  assert.match(describe(certData), /CN=github\.com, до 2026-11-29/);
});
