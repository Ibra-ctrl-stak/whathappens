// DNS wire format (RFC 1035) — building queries and parsing responses by hand.

export const TYPE = Object.freeze({ A: 1, NS: 2, CNAME: 5, SOA: 6, AAAA: 28, OPT: 41 });
const TYPE_NAME = Object.freeze(Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k])));
const CLASS_IN = 1;
const EDNS_UDP_SIZE = 1232;
const MAX_POINTER_JUMPS = 64;

function encodeName(name) {
  const labels = name.replace(/\.$/, '').split('.').filter(Boolean);
  const parts = labels.map((label) => {
    const bytes = Buffer.from(label, 'ascii');
    if (bytes.length > 63) throw new Error(`DNS label too long: ${label}`);
    return Buffer.concat([Buffer.from([bytes.length]), bytes]);
  });
  return Buffer.concat([...parts, Buffer.from([0])]);
}

/** Non-recursive query (RD=0) with an EDNS0 OPT record so referrals are not truncated. */
export function buildQuery({ id, name, type = TYPE.A }) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0000, 2); // QR=0, OPCODE=0, RD=0
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(1, 10); // ARCOUNT (OPT)
  const question = Buffer.alloc(4);
  question.writeUInt16BE(type, 0);
  question.writeUInt16BE(CLASS_IN, 2);
  const opt = Buffer.alloc(11);
  opt.writeUInt8(0, 0); // root name
  opt.writeUInt16BE(TYPE.OPT, 1);
  opt.writeUInt16BE(EDNS_UDP_SIZE, 3);
  return Buffer.concat([header, encodeName(name), question, opt]);
}

const DOT = 0x2e;
const BACKSLASH = 0x5c;

/**
 * Label bytes -> presentation format (RFC 1035 §5.1): "." and "\" are backslash-escaped,
 * bytes outside printable ASCII become \DDD. Names from the network can then never carry
 * terminal escapes or markup, and a dot inside a label cannot fake a label boundary.
 */
function escapeLabel(bytes) {
  return [...bytes]
    .map((b) => {
      if (b === DOT || b === BACKSLASH) return `\\${String.fromCharCode(b)}`;
      if (b < 0x21 || b > 0x7e) return `\\${String(b).padStart(3, '0')}`;
      return String.fromCharCode(b);
    })
    .join('');
}

function readName(buf, offset) {
  const labels = [];
  let pos = offset;
  let end = null;
  for (let jumps = 0; jumps <= MAX_POINTER_JUMPS; ) {
    if (pos >= buf.length) throw new Error('DNS name runs past end of packet');
    const len = buf[pos];
    if (len === 0) {
      return { name: labels.join('.') || '.', next: end ?? pos + 1 };
    }
    if ((len & 0xc0) === 0xc0) {
      if (end === null) end = pos + 2;
      pos = ((len & 0x3f) << 8) | buf[pos + 1];
      jumps += 1;
      continue;
    }
    labels.push(escapeLabel(buf.subarray(pos + 1, pos + 1 + len)));
    pos += 1 + len;
  }
  throw new Error('DNS name compression loop');
}

function readRdata(buf, type, offset, length) {
  if (type === TYPE.A && length === 4) return [...buf.subarray(offset, offset + 4)].join('.');
  if (type === TYPE.AAAA && length === 16) {
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(offset + i).toString(16));
    return groups.join(':');
  }
  if (type === TYPE.NS || type === TYPE.CNAME) return readName(buf, offset).name;
  return buf.subarray(offset, offset + length).toString('hex');
}

function readRecord(buf, offset) {
  const { name, next } = readName(buf, offset);
  const type = buf.readUInt16BE(next);
  const klass = buf.readUInt16BE(next + 2);
  const ttl = buf.readUInt32BE(next + 4);
  const rdlength = buf.readUInt16BE(next + 8);
  const rdataOffset = next + 10;
  if (rdataOffset + rdlength > buf.length) throw new Error('DNS record runs past end of packet');
  return {
    record: {
      name: name.toLowerCase(),
      type,
      typeName: TYPE_NAME[type] ?? `TYPE${type}`,
      class: klass,
      ttl,
      data: readRdata(buf, type, rdataOffset, rdlength),
    },
    next: rdataOffset + rdlength,
  };
}

function readSection(buf, offset, count) {
  const records = [];
  let pos = offset;
  for (let i = 0; i < count; i += 1) {
    const { record, next } = readRecord(buf, pos);
    records.push(record);
    pos = next;
  }
  return { records, next: pos };
}

function readQuestion(buf) {
  if (buf.length < 12 || buf.readUInt16BE(4) !== 1) return null;
  const { name, next } = readName(buf, 12);
  if (next + 4 > buf.length) return null;
  return { name: name.toLowerCase(), type: buf.readUInt16BE(next), klass: buf.readUInt16BE(next + 2) };
}

/**
 * Is `response` an answer to `query`? Same transaction id, QR bit set, and the very same
 * question (name compared case-insensitively). Anything malformed is simply "not an answer".
 */
export function isAnswerTo(query, response) {
  try {
    if (response.length < 12 || response.readUInt16BE(0) !== query.readUInt16BE(0)) return false;
    if (!(response.readUInt16BE(2) & 0x8000)) return false;
    const asked = readQuestion(query);
    const answered = readQuestion(response);
    return Boolean(asked && answered) && asked.name === answered.name && asked.type === answered.type && asked.klass === answered.klass;
  } catch {
    return false; // undecodable question section
  }
}

export function parseResponse(buf) {
  if (buf.length < 12) throw new Error(`DNS response too short: ${buf.length} bytes`);
  const flags = buf.readUInt16BE(2);
  const counts = [4, 6, 8, 10].map((o) => buf.readUInt16BE(o));
  let pos = 12;
  const questions = [];
  for (let i = 0; i < counts[0]; i += 1) {
    const { name, next } = readName(buf, pos);
    questions.push({ name: name.toLowerCase(), type: buf.readUInt16BE(next) });
    pos = next + 4;
  }
  const answers = readSection(buf, pos, counts[1]);
  const authority = readSection(buf, answers.next, counts[2]);
  const additional = readSection(buf, authority.next, counts[3]);
  return {
    id: buf.readUInt16BE(0),
    isResponse: Boolean(flags & 0x8000),
    authoritative: Boolean(flags & 0x0400),
    truncated: Boolean(flags & 0x0200),
    rcode: flags & 0x000f,
    questions,
    answers: answers.records,
    authority: authority.records,
    additional: additional.records,
  };
}
