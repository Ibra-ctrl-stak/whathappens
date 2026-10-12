// Minimal pcapng writer (one section, given interfaces, Enhanced Packet Blocks, no other options
// than if_tsresol/if_tsoffset). Used to cut a fixture down to one connection and by tests.
const SHB = 0x0a0d0d0a;
const IDB = 1;
const EPB = 6;
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;
const OPT_END = 0;
const OPT_TSRESOL = 9;
const OPT_TSOFFSET = 14;

const pad4 = (n) => (4 - (n % 4)) % 4;

function block(type, body, le) {
  const total = 12 + body.length + pad4(body.length);
  const out = Buffer.alloc(total);
  const u32 = (v, at) => (le ? out.writeUInt32LE(v >>> 0, at) : out.writeUInt32BE(v >>> 0, at));
  u32(type, 0);
  u32(total, 4);
  body.copy(out, 8);
  u32(total, total - 4);
  return out;
}

function option(code, value, le) {
  const head = Buffer.alloc(4);
  if (le) { head.writeUInt16LE(code, 0); head.writeUInt16LE(value.length, 2); } else { head.writeUInt16BE(code, 0); head.writeUInt16BE(value.length, 2); }
  return Buffer.concat([head, value, Buffer.alloc(pad4(value.length))]);
}

/**
 * interfaces: [{ linkType, snaplen = 0, tsresol = 6 (byte as in if_tsresol), tsoffset = 0n }]
 * packets: [{ interfaceId = 0, ts: BigInt in interface units, data: Buffer, originalLength? }]
 */
export function writePcapng({ interfaces, packets, littleEndian = true }) {
  const le = littleEndian;
  const shb = Buffer.alloc(16);
  if (le) { shb.writeUInt32LE(BYTE_ORDER_MAGIC, 0); shb.writeUInt16LE(1, 4); shb.writeUInt16LE(0, 6); }
  else { shb.writeUInt32BE(BYTE_ORDER_MAGIC, 0); shb.writeUInt16BE(1, 4); shb.writeUInt16BE(0, 6); }
  shb.writeBigInt64LE(-1n, 8); // section length unknown (same bytes in either order)
  const idbs = interfaces.map((i) => {
    const fixed = Buffer.alloc(8);
    if (le) { fixed.writeUInt16LE(i.linkType, 0); fixed.writeUInt32LE(i.snaplen ?? 0, 4); } else { fixed.writeUInt16BE(i.linkType, 0); fixed.writeUInt32BE(i.snaplen ?? 0, 4); }
    const opts = [];
    if ((i.tsresol ?? 6) !== 6) opts.push(option(OPT_TSRESOL, Buffer.from([i.tsresol]), le));
    if (i.tsoffset) {
      const v = Buffer.alloc(8);
      if (le) v.writeBigInt64LE(BigInt(i.tsoffset)); else v.writeBigInt64BE(BigInt(i.tsoffset));
      opts.push(option(OPT_TSOFFSET, v, le));
    }
    if (opts.length) opts.push(option(OPT_END, Buffer.alloc(0), le));
    return block(IDB, Buffer.concat([fixed, ...opts]), le);
  });
  const epbs = packets.map((p) => {
    const head = Buffer.alloc(20);
    const ts = BigInt(p.ts);
    const u32 = (v, at) => (le ? head.writeUInt32LE(v >>> 0, at) : head.writeUInt32BE(v >>> 0, at));
    u32(p.interfaceId ?? 0, 0);
    u32(Number(ts >> 32n), 4);
    u32(Number(ts & 0xffffffffn), 8);
    u32(p.data.length, 12);
    u32(p.originalLength ?? p.data.length, 16);
    return block(EPB, Buffer.concat([head, p.data, Buffer.alloc(pad4(p.data.length))]), le);
  });
  return Buffer.concat([block(SHB, shb, le), ...idbs, ...epbs]);
}
