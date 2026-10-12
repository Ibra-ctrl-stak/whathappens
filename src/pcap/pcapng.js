// pcapng reader (https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng): bounded, defensive,
// keeps what it could read. Supports Section Header, Interface Description and Enhanced Packet
// blocks; other packet blocks are reported, the rest are skipped.

export const LIMITS = Object.freeze({ maxBytes: 64 * 1024 * 1024, maxBlocks: 500_000, maxPackets: 200_000 });

const SHB = 0x0a0d0d0a;
const IDB = 1;
const OBSOLETE_PB = 2;
const SPB = 3;
const EPB = 6;
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;
const OPT_TSRESOL = 9;
const OPT_TSOFFSET = 14;
const CLASSIC_PCAP = new Set(['a1b2c3d4', 'd4c3b2a1', 'a1b23c4d', '4d3cb2a1']);
const NS_PER_S = 1_000_000_000n;

/** Units per second for an if_tsresol byte, or null when unusable. */
function unitsPerSecond(tsresol) {
  const exp = tsresol & 0x7f;
  if (tsresol & 0x80) return exp <= 63 ? 1n << BigInt(exp) : null;
  return exp <= 18 ? 10n ** BigInt(exp) : null;
}

function toTime(ts, iface) {
  const ns = (ts * NS_PER_S) / iface.unitsPerSecond + iface.tsoffset * NS_PER_S;
  const seconds = ns / NS_PER_S;
  const fraction = (ns % NS_PER_S).toString().padStart(9, '0');
  const iso = new Date(Number(seconds) * 1000).toISOString().replace(/\.\d{3}Z$/, `.${fraction}Z`);
  return { timeNs: ns, timeMs: Number(ns / 1000n) / 1000, captureTime: iso };
}

function readOptions(buf, from, to, u16, problems, where) {
  const options = new Map();
  let pos = from;
  while (pos + 4 <= to) {
    const code = u16(pos);
    const length = u16(pos + 2);
    if (code === 0) break;
    if (pos + 4 + length > to) {
      problems.push(`${where}: option ${code} runs past its block`);
      break;
    }
    options.set(code, buf.subarray(pos + 4, pos + 4 + length));
    pos += 4 + length + ((4 - (length % 4)) % 4);
  }
  return options;
}

function interfaceFrom(buf, at, total, endian, problems, index) {
  const u16 = (p) => (endian === 'le' ? buf.readUInt16LE(p) : buf.readUInt16BE(p));
  const u32 = (p) => (endian === 'le' ? buf.readUInt32LE(p) : buf.readUInt32BE(p));
  const where = `interface ${index}`;
  const options = total > 20 ? readOptions(buf, at + 16, at + total - 4, u16, problems, where) : new Map();
  const tsresol = options.get(OPT_TSRESOL)?.[0] ?? 6;
  const units = unitsPerSecond(tsresol);
  if (units === null) problems.push(`${where}: unsupported timestamp resolution 0x${tsresol.toString(16)}`);
  const offset = options.get(OPT_TSOFFSET);
  return {
    linkType: u16(at + 8),
    snaplen: u32(at + 12),
    unitsPerSecond: units,
    tsoffset: offset?.length === 8 ? (endian === 'le' ? offset.readBigInt64LE() : offset.readBigInt64BE()) : 0n,
  };
}

/**
 * buf -> { interfaces, packets, problems, truncated }. Throws only when the input is not a pcapng
 * file at all or exceeds limits.maxBytes; everything else is a problem string and reading goes on
 * (or stops, keeping what was read). Frame numbers count packet blocks in file order (as Wireshark).
 */
export function readPcapng(buf, limits = LIMITS) {
  const { maxBytes, maxBlocks, maxPackets } = { ...LIMITS, ...limits };
  if (buf.length > maxBytes) throw new Error(`capture is larger than ${maxBytes} bytes`);
  if (buf.length >= 4 && CLASSIC_PCAP.has(buf.subarray(0, 4).toString('hex'))) {
    throw new Error('this is a classic pcap file; save it as pcapng (e.g. in Wireshark: File > Save As > pcapng)');
  }
  if (buf.length < 12 || buf.readUInt32LE(0) !== SHB) throw new Error('not a pcapng file: it does not start with a Section Header Block');

  const problems = [];
  const packets = [];
  let interfaces = [];
  let endian = 'le';
  let truncated = false;
  let frame = 0;
  let blocks = 0;
  let pos = 0;
  while (pos < buf.length) {
    if (buf.length - pos < 12) { truncated = true; problems.push(`file ends inside a block header at byte ${pos}`); break; }
    if (blocks === maxBlocks) { problems.push(`block limit (${maxBlocks}) reached; the rest of the file is not read`); break; }
    const type0 = buf.readUInt32LE(pos);
    if (type0 === SHB) {
      const magic = buf.readUInt32LE(pos + 8);
      if (magic === BYTE_ORDER_MAGIC) endian = 'le';
      else if (buf.readUInt32BE(pos + 8) === BYTE_ORDER_MAGIC) endian = 'be';
      else { problems.push(`section at byte ${pos}: bad byte-order magic`); break; }
      interfaces = []; // interface ids are per section
    }
    const u32 = (p) => (endian === 'le' ? buf.readUInt32LE(p) : buf.readUInt32BE(p));
    const type = u32(pos);
    const total = u32(pos + 4);
    if (total < 12 || total % 4 !== 0) { problems.push(`invalid block length ${total} at byte ${pos}`); break; }
    if (pos + total > buf.length) { truncated = true; problems.push(`file ends inside a block at byte ${pos} (${total} bytes declared)`); break; }
    if (u32(pos + total - 4) !== total) { problems.push(`block at byte ${pos}: trailing length does not match`); break; }
    blocks += 1;

    if (type === IDB) {
      if (total < 20) problems.push(`interface block at byte ${pos} is too short`);
      else interfaces.push(interfaceFrom(buf, pos, total, endian, problems, interfaces.length));
    } else if (type === EPB || type === SPB || type === OBSOLETE_PB) {
      frame += 1;
      if (packets.length === maxPackets) { problems.push(`packet limit (${maxPackets}) reached; later packets are not read`); break; }
      if (type !== EPB) {
        problems.push(`frame ${frame}: ${type === SPB ? 'Simple' : 'obsolete'} Packet Block without per-packet interface/timestamp is not supported`);
      } else if (total < 32) {
        problems.push(`frame ${frame}: packet block too short`);
      } else {
        const interfaceId = u32(pos + 8);
        const capturedLength = u32(pos + 20);
        const originalLength = u32(pos + 24);
        const iface = interfaces[interfaceId];
        if (!iface) problems.push(`frame ${frame}: unknown interface ${interfaceId}`);
        else if (28 + capturedLength > total - 4) problems.push(`frame ${frame}: captured length ${capturedLength} runs past its block`);
        else if (capturedLength > originalLength) problems.push(`frame ${frame}: captured ${capturedLength} bytes over original length ${originalLength}`);
        else if (iface.snaplen > 0 && capturedLength > iface.snaplen) problems.push(`frame ${frame}: captured ${capturedLength} bytes over snaplen ${iface.snaplen}`);
        else if (iface.unitsPerSecond === null) problems.push(`frame ${frame}: interface ${interfaceId} has an unsupported timestamp resolution`);
        else {
          const ts = (BigInt(u32(pos + 12)) << 32n) | BigInt(u32(pos + 16));
          packets.push({
            frame, interfaceId, linkType: iface.linkType, capturedLength, originalLength,
            data: buf.subarray(pos + 28, pos + 28 + capturedLength), ...toTime(ts, iface),
          });
        }
      }
    }
    pos += total;
  }
  return { interfaces, packets, problems, truncated };
}
