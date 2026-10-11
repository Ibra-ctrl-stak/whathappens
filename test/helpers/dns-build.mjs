// Build DNS responses for tests (no name compression).
import { TYPE } from '../../src/dns/packet.js';

const OPT_RECORD_LEN = 11; // buildQuery appends one EDNS0 OPT record

export const encodeName = (name) =>
  Buffer.concat([...name.split('.').filter(Boolean).map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);

export function encodeRecord({ name, type, data }) {
  const rdata = type === TYPE.A ? Buffer.from(data.split('.').map(Number)) : encodeName(data);
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(type, 0);
  fixed.writeUInt16BE(1, 2); // IN
  fixed.writeUInt32BE(60, 4);
  fixed.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([encodeName(name), fixed, rdata]);
}

/** A response to `query` (question copied verbatim) with the given flags and sections. */
export function respond(query, { aa = false, rcode = 0, answers = [], authority = [], additional = [] } = {}) {
  const header = Buffer.from(query.subarray(0, 12));
  header.writeUInt16BE(0x8000 | (aa ? 0x0400 : 0) | rcode, 2);
  header.writeUInt16BE(answers.length, 6);
  header.writeUInt16BE(authority.length, 8);
  header.writeUInt16BE(additional.length, 10);
  const question = query.subarray(12, query.length - OPT_RECORD_LEN);
  return Buffer.concat([header, question, ...[...answers, ...authority, ...additional].map(encodeRecord)]);
}

export const NS = (name, data) => ({ name, type: TYPE.NS, data });
export const A = (name, data) => ({ name, type: TYPE.A, data });
export const CNAME = (name, data) => ({ name, type: TYPE.CNAME, data });
