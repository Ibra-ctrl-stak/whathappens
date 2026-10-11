// HTTP/1.1 messages as byte-exact field trees: start line tokens, each header's name and value,
// separators, body. Header lines checked against Wireshark.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { decryptSession } from '../src/tls/decrypt.js';
import { httpFields } from '../src/http/fields.js';
import { find, findAll, walk } from '../src/fields.js';

const json = (name) => JSON.parse(readFileSync(new URL(`./fixtures/github-robots/${name}`, import.meta.url), 'utf8'));
const expected = json('expected.json').http;
const { client, server } = decryptSession(loadSession(json('session.json')).tls);
const request = httpFields(client.appData);
const response = httpFields(server.appData);
const text = (buf, f) => buf.subarray(f.offset, f.offset + f.length).toString('latin1');

test('the tree covers every byte of the message, children tiling each parent', () => {
  for (const [buf, tree] of [[client.appData, request], [server.appData, response]]) {
    assert.deepEqual([tree.offset, tree.length], [0, buf.length]);
    walk(tree, (f) => {
      if (f.children.length === 0) return;
      let pos = f.offset;
      for (const c of f.children) {
        assert.equal(c.offset, pos, `${f.name} > ${c.name}`);
        pos += c.length;
      }
      assert.equal(pos, f.offset + f.length, f.name);
    });
  }
});

test('request line tokens', () => {
  assert.equal(find(request, 'method').value, 'GET');
  assert.equal(find(request, 'request_target').value, expected.request.uri);
  assert.equal(find(request, 'http_version').value, 'HTTP/1.1');
});

test('status line tokens', () => {
  assert.equal(find(response, 'status_code').value, expected.response.code);
  assert.equal(find(response, 'reason_phrase').value, expected.response.phrase);
});

for (const [label, buf, tree, lines] of [
  ['request', client.appData, request, expected.headerLines.request],
  ['response', server.appData, response, expected.headerLines.response],
]) {
  test(`${label} header lines match Wireshark, name and value each on their own bytes`, () => {
    const headers = findAll(tree, 'header');
    assert.deepEqual(headers.map((h) => `${find(h, 'field_name').value}: ${find(h, 'field_value').value}`), lines);
    for (const h of headers) {
      assert.equal(text(buf, find(h, 'field_name')), find(h, 'field_name').value);
      assert.equal(text(buf, find(h, 'field_value')), find(h, 'field_value').value);
      assert.equal(h.label, find(h, 'field_name').value);
    }
  });
}

test('response body is a field over exactly the body bytes', () => {
  const body = find(response, 'body');
  assert.equal(body.length, expected.response.contentLength);
  assert.equal(body.offset + body.length, server.appData.length);
});

test('optional whitespace around a value gets its own fields; none when absent', () => {
  const spaced = httpFields(Buffer.from('GET / HTTP/1.1\r\nX:   v  \r\nY:w\r\n\r\n', 'latin1'));
  const [x, y] = findAll(spaced, 'header');
  assert.deepEqual(x.children.map((f) => [f.name, f.length]), [['field_name', 1], ['colon', 1], ['ows', 3], ['field_value', 1], ['ows', 2], ['crlf', 2]]);
  assert.deepEqual(y.children.map((f) => f.name), ['field_name', 'colon', 'field_value', 'crlf']);
});

test('a message that does not parse is one field with a problem', () => {
  const tree = httpFields(Buffer.from('HELLO\r\n\r\n'));
  assert.equal(tree.children.length, 0);
  assert.match(tree.problem, /start line/);
});
