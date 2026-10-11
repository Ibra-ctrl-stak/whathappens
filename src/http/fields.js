// HTTP/1.1 message as a field tree over the decrypted stream (timeline buffer http/out|in):
// head (start line tokens, each header: name, colon, optional whitespace, value, CRLF; the empty
// line), body and any extra bytes. Children tile their parent, so every byte has a field.
import { field } from '../fields.js';
import { parseHttpMessage } from './message.js';

const CRLF = 2;
const leaf = (name, offset, length, value = null) => field(name, offset, length, { value });

function startLine(s, kind) {
  const children = kind === 'request'
    ? [
      leaf('method', 0, s.method.length, s.method),
      leaf('sp', s.method.length, 1),
      leaf('request_target', s.method.length + 1, s.target.length, s.target),
      leaf('sp', s.method.length + 1 + s.target.length, 1),
      leaf('http_version', s.method.length + 2 + s.target.length, s.version.length, s.version),
    ]
    : [
      leaf('http_version', 0, s.version.length, s.version),
      leaf('sp', s.version.length, 1),
      leaf('status_code', s.version.length + 1, 3, s.status),
      // "HTTP/1.1 200" may come without a reason phrase (and without its separator)
      ...(s.length > s.version.length + 4
        ? [leaf('sp', s.version.length + 4, 1), leaf('reason_phrase', s.version.length + 5, s.length - s.version.length - 5, s.reason)]
        : []),
    ];
  return field('start_line', 0, s.length + CRLF, { children: [...children, leaf('crlf', s.length, CRLF)] });
}

/** Split "name:  value  " the same way message.js trims the value. */
function header(h, text) {
  const colonAt = h.offset + h.name.length;
  const rest = text.slice(colonAt + 1, h.offset + h.length);
  const leading = rest.length - rest.trimStart().length;
  const trailing = h.value === '' ? 0 : rest.length - rest.trimEnd().length;
  const valueAt = colonAt + 1 + leading;
  const children = [
    leaf('field_name', h.offset, h.name.length, h.name),
    leaf('colon', colonAt, 1),
    ...(leading > 0 ? [leaf('ows', colonAt + 1, leading)] : []),
    leaf('field_value', valueAt, rest.length - leading - trailing, h.value),
    ...(trailing > 0 ? [leaf('ows', valueAt + h.value.length, trailing)] : []),
    leaf('crlf', h.offset + h.length, CRLF),
  ];
  return field('header', h.offset, h.length + CRLF, { label: h.name, children });
}

/** buf: one direction's decrypted application data. Never throws: a broken message is one field with a problem. */
export function httpFields(buf) {
  let msg;
  try {
    msg = parseHttpMessage(buf);
  } catch (err) {
    return field('message', 0, buf.length, { problem: err.message });
  }
  const text = buf.toString('latin1');
  const { body, extra, problems } = msg;
  const head = field('head', 0, msg.head.length, {
    children: [startLine(msg.startLine, msg.kind), ...msg.headers.map((h) => header(h, text)), leaf('empty_line', msg.head.length - CRLF, CRLF)],
  });
  const children = [
    head,
    ...(body.length > 0 ? [field('body', body.offset, body.length, { label: body.framing })] : []),
    ...(extra ? [leaf('extra', extra.offset, extra.length)] : []),
  ];
  return field(msg.kind, 0, buf.length, { children, problems });
}
