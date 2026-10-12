// HTTP/1.1 message head parser (RFC 9112) that keeps a byte range for every piece.
// Content decoding is separate; these ranges always address the wire representation.
import { parseChunked } from './chunked.js';

const CRLF = '\r\n';
const HEAD_END = '\r\n\r\n';
const REQUEST_LINE = /^([A-Z]+) (\S+) (HTTP\/\d\.\d)$/;
const STATUS_LINE = /^(HTTP\/\d\.\d) (\d{3})(?: (.*))?$/;

function parseStartLine(text) {
  const req = REQUEST_LINE.exec(text);
  if (req) return { kind: 'request', fields: { method: req[1], target: req[2], version: req[3] } };
  const res = STATUS_LINE.exec(text);
  if (res) return { kind: 'response', fields: { version: res[1], status: Number(res[2]), reason: res[3] ?? '' } };
  throw new Error(`not an HTTP/1.x start line: ${JSON.stringify(text.slice(0, 80))}`);
}

function parseHeaders(text, baseOffset) {
  const headers = [];
  let offset = baseOffset;
  for (const line of text.split(CRLF)) {
    const colon = line.indexOf(':');
    if (colon <= 0) throw new Error(`malformed header line at byte ${offset}: ${JSON.stringify(line.slice(0, 80))}`);
    headers.push({ name: line.slice(0, colon), value: line.slice(colon + 1).trim(), offset, length: line.length });
    offset += line.length + CRLF.length;
  }
  return headers;
}

export function headerValue(message, name) {
  const lower = name.toLowerCase();
  return message.headers.find((h) => h.name.toLowerCase() === lower)?.value;
}

const DECIMAL = /^\d+$/;

/** Body by Content-Length: never longer than declared; leftovers and shortfalls are reported. */
function frameByLength(declared, offset, available) {
  if (!DECIMAL.test(declared) || !Number.isSafeInteger(Number(declared))) {
    return {
      body: { offset, length: available, framing: 'invalid', declaredLength: null, complete: null },
      extra: null,
      problems: [`invalid Content-Length ${JSON.stringify(declared)}`],
    };
  }
  const declaredLength = Number(declared);
  const length = Math.min(declaredLength, available);
  const surplus = available - length;
  const problems = [
    ...(available < declaredLength ? [`body truncated: ${available} of ${declaredLength} bytes`] : []),
    ...(surplus > 0 ? [`${surplus} bytes after the declared body`] : []),
  ];
  return {
    body: { offset, length, framing: 'content-length', declaredLength, complete: available >= declaredLength },
    extra: surplus > 0 ? { offset: offset + length, length: surplus } : null,
    problems,
  };
}

export function headerValues(message, name) {
  return message.headers.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);
}

function frameBody(kind, message, offset, available, buf) {
  const status = message.startLine.status;
  if (kind === 'response' && (status < 200 || status === 204 || status === 304)) {
    return { body: { offset, length: 0, framing: 'none', declaredLength: 0, complete: true },
      extra: available ? { offset, length: available } : null,
      problems: available ? [`${available} bytes after a bodyless response`] : [] };
  }
  const transfer = headerValues(message, 'transfer-encoding');
  const lengths = headerValues(message, 'content-length');
  if (transfer.length) {
    const codings = transfer.join(',').toLowerCase().split(',').map((v) => v.trim());
    const problems = lengths.length ? ['Transfer-Encoding conflicts with Content-Length'] : [];
    if (codings.at(-1) === 'chunked' && codings.filter((v) => v === 'chunked').length === 1) {
      const chunks = parseChunked(buf, offset);
      if (chunks.problem) problems.push(chunks.problem);
      const surplus = available - chunks.length;
      if (surplus) problems.push(`${surplus} bytes after the chunked body`);
      return { body: { offset, length: chunks.length, framing: 'chunked', declaredLength: null, complete: chunks.complete },
        chunks, extra: surplus ? { offset: offset + chunks.length, length: surplus } : null, problems };
    }
    return { body: { offset, length: available, framing: 'invalid', declaredLength: null, complete: false },
      extra: null, problems: [...problems, 'unsupported or invalid Transfer-Encoding'] };
  }
  if (lengths.length > 1) {
    return { body: { offset, length: available, framing: 'invalid', declaredLength: null, complete: false },
      extra: null, problems: ['multiple Content-Length headers are not supported'] };
  }
  const declared = headerValue(message, 'content-length');
  if (declared !== undefined) return frameByLength(declared, offset, available);
  // A request without either header has no body; a response then runs until the connection closes.
  const body = kind === 'request'
    ? { offset, length: 0, framing: 'none', declaredLength: 0, complete: true }
    : { offset, length: available, framing: 'close', declaredLength: null, complete: true };
  const surplus = available - body.length;
  return {
    body,
    extra: surplus > 0 ? { offset: offset + body.length, length: surplus } : null,
    problems: surplus > 0 ? [`${surplus} bytes after a request without a body`] : [],
  };
}

/** Parse one HTTP/1.x message at the start of `buf` (latin1: header bytes map 1:1 to chars). */
export function parseHttpMessage(buf) {
  const text = buf.toString('latin1');
  const headEnd = text.indexOf(HEAD_END);
  if (headEnd < 0) throw new Error('HTTP head incomplete: no blank line yet');
  const startEnd = text.indexOf(CRLF);
  const { kind, fields } = parseStartLine(text.slice(0, startEnd));
  const headerText = text.slice(startEnd + CRLF.length, headEnd);
  const headers = headerText ? parseHeaders(headerText, startEnd + CRLF.length) : [];
  const head = { offset: 0, length: headEnd + HEAD_END.length };
  const message = { kind, startLine: { offset: 0, length: startEnd, ...fields }, headers, head };
  return { ...message, ...frameBody(kind, message, head.length, buf.length - head.length, buf) };
}
