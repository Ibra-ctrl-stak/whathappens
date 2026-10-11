// Hex dump rows for the page's hex panel (web/hex.js runs in the browser and in Node).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hexRows, BYTES_PER_ROW } from '../web/hex.js';

const bytes = (...values) => Uint8Array.from(values);

test('16 bytes per row, the last row may be short', () => {
  const rows = hexRows(new Uint8Array(40), 0);
  assert.equal(BYTES_PER_ROW, 16);
  assert.deepEqual(rows.map((r) => r.hex.length), [16, 16, 8]);
});

test('offsets are absolute positions in the buffer, 8 hex digits', () => {
  const rows = hexRows(new Uint8Array(20), 0x1f0);
  assert.deepEqual(rows.map((r) => r.offset), ['000001f0', '00000200']);
});

test('bytes are two lowercase hex digits', () => {
  const [row] = hexRows(bytes(0x00, 0x0a, 0xff, 0x16), 0);
  assert.deepEqual(row.hex, ['00', '0a', 'ff', '16']);
});

test('ASCII column shows printable bytes only (0x20..0x7e), a dot otherwise', () => {
  const [row] = hexRows(bytes(0x47, 0x45, 0x54, 0x20, 0x2f, 0x1b, 0x0d, 0x0a, 0x7f, 0x80, 0xe9, 0x7e), 0);
  assert.equal(row.ascii, 'GET /......~');
});

test('ASCII never contains a character that could act as markup or control', () => {
  const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  for (const row of hexRows(all, 0)) assert.match(row.ascii, /^[\x20-\x7e]*$/);
});

test('no bytes, no rows', () => {
  assert.deepEqual(hexRows(new Uint8Array(0), 100), []);
});
