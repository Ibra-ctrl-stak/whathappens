// RFC 9112 §7.1. Offsets always refer to the original HTTP stream.
const TOKEN = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
const EXTENSIONS = new RegExp(`^(?:[ \\t]*;[ \\t]*${TOKEN}(?:[ \\t]*=[ \\t]*(?:${TOKEN}|"(?:[\\t !#-\\[\\]-~\\x80-\\xff]|\\\\[\\t !-~\\x80-\\xff])*"))?)*$`);
const TRAILER = new RegExp(`^${TOKEN}:[\\t \\x21-\\x7e\\x80-\\xff]*$`);
export function parseChunked(buf, offset) {
  let pos = offset;
  const fields = [], data = [];
  const add = (name, at, length, value = null) => fields.push({ name, offset: at, length, value, children: [] });
  const fail = (problem) => {
    if (pos < buf.length) add('unparsed', pos, buf.length - pos);
    return { length: buf.length - offset, complete: false, fields, data, problem };
  };
  for (let count = 0; count < 10000; count++) {
    const end = buf.indexOf('\r\n', pos);
    if (end < 0) return fail('chunk size line truncated');
    const line = buf.toString('latin1', pos, end);
    const match = /^([0-9a-fA-F]+)(.*)$/.exec(line);
    if (!match || !EXTENSIONS.test(match[2])) return fail('invalid chunk size or extensions');
    const size = Number.parseInt(match[1], 16);
    if (!Number.isSafeInteger(size)) return fail('chunk size exceeds safe integer range');
    add('chunk_size', pos, match[1].length, size);
    if (match[2]) add('chunk_extensions', pos + match[1].length, match[2].length, match[2]);
    add('crlf', end, 2);
    pos = end + 2;
    if (size === 0) {
      for (let trailers = 0; trailers < 1000; trailers++) {
        const stop = buf.indexOf('\r\n', pos);
        if (stop < 0) return fail('chunk trailers truncated');
        if (stop === pos) {
          add('empty_line', pos, 2);
          pos += 2;
          return { length: pos - offset, complete: true, fields, data, problem: null };
        }
        const trailer = buf.toString('latin1', pos, stop);
        if (!TRAILER.test(trailer)) return fail('invalid chunk trailer');
        add('trailer', pos, stop + 2 - pos, trailer);
        pos = stop + 2;
      }
      return fail('chunk trailer count exceeds limit');
    }
    if (size > buf.length - pos) return fail('chunk data truncated');
    add('chunk_data', pos, size);
    data.push({ offset: pos, length: size });
    pos += size;
    if (pos + 2 > buf.length) return fail('chunk data terminator truncated');
    if (buf[pos] !== 13 || buf[pos + 1] !== 10) return fail('invalid chunk data terminator');
    add('crlf', pos, 2);
    pos += 2;
  }
  return fail('chunk count exceeds limit');
}
