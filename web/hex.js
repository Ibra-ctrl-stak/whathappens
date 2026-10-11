// Hex dump rows: offset | 16 bytes in hex | printable ASCII. Pure; used by the page and by tests.
export const BYTES_PER_ROW = 16;
const PRINTABLE_FIRST = 0x20;
const PRINTABLE_LAST = 0x7e;

const hex2 = (b) => b.toString(16).padStart(2, '0');
const asciiOf = (b) => (b >= PRINTABLE_FIRST && b <= PRINTABLE_LAST ? String.fromCharCode(b) : '.');

/** bytes: Uint8Array of the event; baseOffset: where it starts in its buffer. */
export function hexRows(bytes, baseOffset) {
  const rows = [];
  for (let i = 0; i < bytes.length; i += BYTES_PER_ROW) {
    const chunk = Array.from(bytes.subarray(i, i + BYTES_PER_ROW));
    rows.push({
      offset: (baseOffset + i).toString(16).padStart(8, '0'),
      hex: chunk.map(hex2),
      ascii: chunk.map(asciiOf).join(''),
    });
  }
  return rows;
}
