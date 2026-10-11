// Make text that came off the wire safe to show: C0/C1 control characters and DEL become
// visible \xNN escapes (no terminal escape sequences, nothing invisible). Display only.
const CONTROL = /[\x00-\x1f\x7f-\x9f]/g;

export const printable = (text) =>
  text.replace(CONTROL, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);

/** printable() applied to every string inside plain objects/arrays; other values untouched. */
export function printableDeep(value) {
  if (typeof value === 'string') return printable(value);
  if (Array.isArray(value)) return value.map(printableDeep);
  if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, printableDeep(v)]));
  }
  return value;
}
