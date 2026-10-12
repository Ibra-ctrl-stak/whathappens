// HTTP/1.1 message as a field tree over the decrypted stream (timeline buffer http/out|in):
// head (start line tokens, each header: name, colon, optional whitespace, value, CRLF; the empty
// line), body and any extra bytes. Children tile their parent, so every byte has a field.
import { field } from '../fields.js';
import { parseHttpMessage } from './message.js';

const CRLF = 2;
const leaf = (name, offset, length, value = null) => field(name, offset, length, { value });

/** s.offset is the absolute start of the line; every token is placed relative to it. */
function startLine(s, kind) {
  const at = s.offset;
  const children = kind === 'request'
    ? [
      leaf('method', at, s.method.length, s.method),
      leaf('sp', at + s.method.length, 1),
      leaf('request_target', at + s.method.length + 1, s.target.length, s.target),
      leaf('sp', at + s.method.length + 1 + s.target.length, 1),
      leaf('http_version', at + s.method.length + 2 + s.target.length, s.version.length, s.version),
    ]
    : [
      leaf('http_version', at, s.version.length, s.version),
      leaf('sp', at + s.version.length, 1),
      leaf('status_code', at + s.version.length + 1, 3, s.status),
      // "HTTP/1.1 200" may come without a reason phrase (and without its separator)
      ...(s.length > s.version.length + 4
        ? [leaf('sp', at + s.version.length + 4, 1), leaf('reason_phrase', at + s.version.length + 5, s.length - s.version.length - 5, s.reason)]
        : []),
    ];
  return field('start_line', at, s.length + CRLF, { children: [...children, leaf('crlf', at + s.length, CRLF)] });
}

function headField(msg, text) {
  const end = msg.head.offset + msg.head.length;
  return field('head', msg.head.offset, msg.head.length, {
    children: [startLine(msg.startLine, msg.kind), ...msg.headers.map((h) => header(h, text)), leaf('empty_line', end - CRLF, CRLF)],
  });
}

/** head, body (with chunk fields) and extra bytes of one parsed message. */
function messageParts(msg, text) {
  const { body, extra } = msg;
  return [
    headField(msg, text),
    ...(body.length > 0 ? [field('body', body.offset, body.length, { label: body.framing, children: msg.chunks?.fields ?? [], problem: msg.chunks?.problem ?? null })] : []),
    ...(extra ? [leaf('extra', extra.offset, extra.length)] : []),
  ];
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
export function httpFields(buf, parsed = null) {
  let msg;
  try {
    msg = parsed ?? parseHttpMessage(buf);
  } catch (err) {
    return field('message', 0, buf.length, { problem: err.message });
  }
  return field(msg.kind, 0, buf.length, { children: messageParts(msg, buf.toString('latin1')), problems: msg.problems });
}

/**
 * The server's whole http/in stream as fields, from parseHttpResponses(buf): each interim (1xx)
 * head, a 101 head, the final response (head, body, extra), and the bytes that could not be
 * parsed. Children tile the stream, so every byte still belongs to exactly one leaf.
 */
export function httpResponseFields(buf, seq) {
  const text = buf.toString('latin1');
  const wrap = (name, msg, children) => field(name, msg.head.offset, children.reduce((n, c) => n + c.length, 0), {
    label: `${msg.startLine.status} ${msg.startLine.reason}`.trim(), children,
  });
  const children = [
    ...seq.interim.map((m) => wrap('interim_response', m, [headField(m, text)])),
    ...(seq.switched ? [wrap('switching_protocols', seq.switched, [headField(seq.switched, text)])] : []),
    ...(seq.final ? [wrap('response', seq.final, messageParts(seq.final, text))] : []),
    ...(seq.rest?.length ? [field('unparsed', seq.rest.offset, seq.rest.length, { problem: seq.rest.problem })] : []),
  ];
  return field('responses', 0, buf.length, { children });
}
