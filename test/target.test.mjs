import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseTarget } from '../src/target.js';

test('a domain becomes an HTTPS request to /', () => {
  assert.deepEqual(parseTarget('GitHub.com'), {
    host: 'github.com', port: 443, path: '/', url: 'https://github.com/',
  });
});

test('path, query and custom port are preserved; a fragment is not sent', () => {
  assert.deepEqual(parseTarget('https://example.com:8443/a%20b?q=one%26two#local'), {
    host: 'example.com', port: 8443, path: '/a%20b?q=one%26two',
    url: 'https://example.com:8443/a%20b?q=one%26two',
  });
});

test('Unicode domains and paths are encoded and a trailing DNS dot is normalized', () => {
  assert.equal(parseTarget('пример.рф/путь').host, 'xn--e1afmkfd.xn--p1ai');
  assert.equal(parseTarget('пример.рф/путь').path, '/%D0%BF%D1%83%D1%82%D1%8C');
  assert.equal(parseTarget('EXAMPLE.COM./robots.txt').url, 'https://example.com/robots.txt');
});

for (const input of [
  '', 'http://example.com', 'ftp://example.com', 'https://user:pass@example.com',
  'https://127.0.0.1', 'https://[::1]', 'https://example.com:0',
  'https://example..com', `https://${'a'.repeat(64)}.com`,
  `https://${Array(5).fill('a'.repeat(60)).join('.')}`,
  'https://example.com/\r\nX-Evil:yes', 'https://example.com/has space',
  'https://example.com\\evil', '/robots.txt',
]) {
  test(`rejects unsupported or malformed target ${JSON.stringify(input)}`, () => {
    assert.throws(() => parseTarget(input));
  });
}
