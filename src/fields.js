// Field trees: every parsed piece of a protocol message knows its own bytes.
// A field is { name, offset, length, value, label, children }; offsets are absolute positions in
// the buffer being parsed. When a field has children, they tile its bytes exactly.

export const field = (name, offset, length, { value = null, label = null, children = [], ...extra } = {}) => ({
  name, offset, length, value, label, children, ...extra,
});

/**
 * Sequential reader over buf[start, end) that produces fields with absolute offsets.
 * Reading past `end` throws with the field name, so a broken length is reported where it bites.
 */
export function cursor(buf, start = 0, end = buf.length) {
  let pos = start;
  const take = (name, size) => {
    if (size < 0 || pos + size > end) {
      throw new Error(`${name}: needs ${size} bytes at offset ${pos}, only ${end - pos} left (runs past the end)`);
    }
    const at = pos;
    pos += size;
    return at;
  };
  const self = {
    get pos() { return pos; },
    get left() { return end - pos; },
    /** Go back to an earlier position of this cursor (to re-read a part differently). */
    seek(to) {
      if (to < start || to > end) throw new Error(`seek to ${to} outside [${start}, ${end}]`);
      pos = to;
    },
    /** Unsigned big-endian integer of `size` bytes; `labels` maps values to names. */
    uint(name, size, labels = null) {
      const at = take(name, size);
      const value = buf.readUIntBE(at, size);
      return field(name, at, size, { value, label: labels?.[value] ?? null });
    },
    /** Raw bytes; `toValue(bytes)` decides the value (default: lowercase hex). */
    bytes(name, size, toValue = (b) => b.toString('hex')) {
      const at = take(name, size);
      return field(name, at, size, { value: toValue(buf.subarray(at, at + size)) });
    },
    /** Length-prefixed vector: children are [length, ...items]; parseItems(sub) reads the body. */
    vector(name, lengthSize, parseItems, extra = {}) {
      const at = pos;
      const length = self.uint('length', lengthSize);
      const body = cursor(buf, take(name, length.value), pos);
      const items = parseItems(body, buf);
      if (body.left !== 0) throw new Error(`${name}: ${body.left} unparsed bytes at offset ${body.pos}`);
      return field(name, at, pos - at, { children: [length, ...items], ...extra });
    },
    /** Vector whose body is one opaque value (string or hex), e.g. host_name. */
    opaque(name, lengthSize, toValue = (b) => b.toString('hex')) {
      const at = pos;
      const length = self.uint('length', lengthSize);
      const bodyAt = take(name, length.value);
      const value = toValue(buf.subarray(bodyAt, bodyAt + length.value));
      return field(name, at, pos - at, { value, children: [length, field('data', bodyAt, length.value)] });
    },
    /** Repeat read() until this cursor is exhausted. */
    many(read) {
      const items = [];
      while (self.left > 0) items.push(read(self));
      return items;
    },
    /** Group already-read consecutive fields under one parent. */
    group(name, children, extra = {}) {
      const first = children[0];
      const last = children.at(-1);
      return field(name, first.offset, last.offset + last.length - first.offset, { children, ...extra });
    },
  };
  return self;
}

export function walk(tree, visit) {
  visit(tree);
  for (const child of tree.children) walk(child, visit);
}

export function findAll(tree, name) {
  const found = [];
  walk(tree, (f) => {
    if (f.name === name) found.push(f);
  });
  return found;
}

export const find = (tree, name) => findAll(tree, name)[0];
