// Extract the TLS 1.3 test vectors we use from RFC 8448 §3 ("Simple 1-RTT Handshake").
// Usage: node tools/extract-rfc8448.mjs <rfc8448.txt> > test/vectors/rfc8448-simple-1rtt.json
// Source text: https://www.rfc-editor.org/rfc/rfc8448.txt
import { readFileSync } from 'node:fs';

const SECTION_START = /^3\.\s+Simple 1-RTT Handshake/;
const SECTION_END = /^4\.\s+Resumed 0-RTT Handshake/;
const BLOCK = /^ {3}\{(client|server)\}\s+(.+?):?$/;
const FIELD = /^ {6}(.+?) \((\d+) octets\):\s+([0-9a-f ]+)$/;
const CONTINUATION = /^ {9}([0-9a-f]{2}( [0-9a-f]{2})*)\s*$/;
const PAGE_NOISE = /^(Thomson\s+Informational|RFC 8448\s+TLS 1\.3 Traces)|\f/;

/** Parse §3 into [{ party, title, line, fields: { label: hex } }]. */
function parseSection(text) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((l) => SECTION_START.test(l));
  const end = lines.findIndex((l, i) => i > start && SECTION_END.test(l));
  if (start < 0 || end < 0) throw new Error('RFC 8448 §3 not found');

  const blocks = [];
  let block = null;
  let field = null;
  const finishField = () => {
    if (!field) return;
    const hex = field.parts.join('').replace(/ /g, '');
    if (hex.length !== field.octets * 2) {
      throw new Error(`${block.title} / ${field.label}: ${hex.length / 2} octets, RFC says ${field.octets}`);
    }
    block.fields[field.label] = hex;
    field = null;
  };

  for (let i = start + 1; i < end; i += 1) {
    const line = lines[i];
    if (PAGE_NOISE.test(line)) continue;
    const b = BLOCK.exec(line);
    if (b) {
      finishField();
      block = { party: b[1], title: b[2].trim(), line: i + 1, fields: {} };
      blocks.push(block);
      continue;
    }
    const f = FIELD.exec(line);
    if (f && block) {
      finishField();
      field = { label: f[1], octets: Number(f[2]), parts: [f[3]] };
      continue;
    }
    const c = CONTINUATION.exec(line);
    if (c && field) {
      field.parts.push(` ${c[1]}`);
      continue;
    }
    if (line.trim() && field) finishField(); // any other text ends the current hex field
  }
  finishField();
  return blocks;
}

function pick(blocks, party, title, nth = 0) {
  const found = blocks.filter((b) => b.party === party && b.title.startsWith(title));
  if (!found[nth]) throw new Error(`block not found: {${party}} ${title} #${nth}`);
  return found[nth];
}

const keys = (b) => ({ rfcLine: b.line, secret: b.fields.PRK, key: b.fields['key expanded'], iv: b.fields['iv expanded'] });
const record = (b, seq) => ({ rfcLine: b.line, seq, payload: b.fields.payload, record: b.fields['complete record'] });

const blocks = parseSection(readFileSync(process.argv[2], 'utf8'));
const sHsSecret = pick(blocks, 'server', 'derive secret "tls13 s hs traffic"');
const vectors = {
  source: 'RFC 8448 §3 Simple 1-RTT Handshake (cipher suite TLS_AES_128_GCM_SHA256)',
  expandLabel: {
    rfcLine: sHsSecret.line,
    label: 's hs traffic',
    secret: sHsSecret.fields.PRK,
    context: sHsSecret.fields.hash,
    info: sHsSecret.fields.info,
    expanded: sHsSecret.fields.expanded,
  },
  keys: {
    serverHandshake: keys(pick(blocks, 'server', 'derive write traffic keys for handshake data')),
    serverApplication: keys(pick(blocks, 'server', 'derive write traffic keys for application data')),
    // The RFC prints the client's handshake write keys only as the server's read keys.
    clientHandshake: keys(pick(blocks, 'server', 'derive read traffic keys for handshake data')),
    clientApplication: keys(pick(blocks, 'client', 'derive write traffic keys for application data')),
  },
  // Sequence numbers count per direction and per epoch (RFC 8446 §5.3).
  records: {
    serverHandshake: record(pick(blocks, 'server', 'send handshake record', 1), 0), // #0 is plaintext ServerHello
    clientFinished: record(pick(blocks, 'client', 'send handshake record', 1), 0), // #0 is plaintext ClientHello
    serverNewSessionTicket: record(pick(blocks, 'server', 'send handshake record', 2), 0),
    clientApplicationData: record(pick(blocks, 'client', 'send application_data record'), 0),
    serverApplicationData: record(pick(blocks, 'server', 'send application_data record'), 1),
    clientAlert: record(pick(blocks, 'client', 'send alert record'), 1),
    serverAlert: record(pick(blocks, 'server', 'send alert record'), 2),
  },
};

const missing = JSON.stringify(vectors, (k, v) => (v === undefined ? '<<MISSING>>' : v)).match(/"[^"]+":"<<MISSING>>"/g);
if (missing) throw new Error(`vector fields not found: ${missing.join(', ')}`);
process.stdout.write(`${JSON.stringify(vectors, null, 2)}\n`);
