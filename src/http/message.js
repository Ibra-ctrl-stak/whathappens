// HTTP/1.1 message head parser (RFC 9112) that keeps a byte range for every piece.
// The body is located and framed, not decoded: chunked/gzip decoding comes later.

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

function frameBody(kind, message, bodyOffset, available) {
  const range = { offset: bodyOffset, length: available };
  if (headerValue(message, 'transfer-encoding')?.toLowerCase().includes('chunked')) {
    return { ...range, framing: 'chunked', declaredLength: null };
  }
  const declared = headerValue(message, 'content-length');
  if (declared !== undefined) return { ...range, framing: 'content-length', declaredLength: Number(declared) };
  // A request without either header has no body; a response then runs until the connection closes.
  return kind === 'request'
    ? { ...range, framing: 'none', declaredLength: 0 }
    : { ...range, framing: 'close', declaredLength: null };
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
  return { ...message, body: frameBody(kind, message, head.length, buf.length - head.length) };
}
