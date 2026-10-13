// Synthetic IPv4/TCP captures of a recorded session's connection, for capture tests.
import { writePcapng } from '../../src/pcap/pcapng-write.js';

const MOD = 2 ** 32;
const FLAGS = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10 };
const SYN_OPTIONS = Buffer.from([0x02, 0x04, 0x05, 0x64, 0x01, 0x03, 0x03, 0x08]); // MSS 1380, NOP, WS 8

const ip = (a) => Buffer.from(a.split('.').map(Number));

/** One IPv4 packet carrying one TCP segment (checksums are not computed: readers do not check them). */
export function ipv4Tcp({ src, dst, seq, ack = 0, flags = [], window = 512, payload = Buffer.alloc(0), options = Buffer.alloc(0), fragment = 0 }) {
  const tcp = Buffer.alloc(20 + options.length);
  tcp.writeUInt16BE(src.port, 0);
  tcp.writeUInt16BE(dst.port, 2);
  tcp.writeUInt32BE(seq % MOD, 4);
  tcp.writeUInt32BE(ack % MOD, 8);
  tcp[12] = ((20 + options.length) / 4) << 4;
  tcp[13] = flags.reduce((b, f) => b | FLAGS[f], 0);
  tcp.writeUInt16BE(window, 14);
  options.copy(tcp, 20);
  const ipHeader = Buffer.alloc(20);
  ipHeader[0] = 0x45;
  ipHeader.writeUInt16BE(20 + tcp.length + payload.length, 2);
  ipHeader.writeUInt16BE(fragment, 6);
  ipHeader[8] = 64;
  ipHeader[9] = 6;
  ip(src.address).copy(ipHeader, 12);
  ip(dst.address).copy(ipHeader, 16);
  return Buffer.concat([ipHeader, tcp, payload]);
}

/**
 * Packets of a clean connection replaying the recorded streams: SYN, SYN-ACK, ACK, client and
 * server data in `mss`-sized segments, FINs. Each: { data, timeMs, dir, payloadFrom?, payloadTo? }.
 */
export function flowFromSession(session, { clientIsn = 1000, serverIsn = 500000, mss = 1200, stepMs = 1 } = {}) {
  const local = session.tls.local;
  const remote = { address: session.tls.ip, port: session.tls.port };
  const join = (dir) => Buffer.concat(session.tls.raw.filter((c) => c.dir === dir).map((c) => c.bytes));
  const streams = { out: join('out'), in: join('in') };
  const firstWrite = session.tls.raw.find((c) => c.dir === 'out').at;
  let t = firstWrite - 3 * stepMs; // the handshake packets come before the ClientHello write
  const packets = [];
  const push = (dir, fields, extra = {}) => {
    const [src, dst] = dir === 'out' ? [local, remote] : [remote, local];
    packets.push({ dir, timeMs: t, data: ipv4Tcp({ src, dst, ...fields }), ...extra });
    t += stepMs;
  };
  const c = clientIsn;
  const s = serverIsn;
  push('out', { seq: c, flags: ['SYN'], options: SYN_OPTIONS });
  push('in', { seq: s, ack: c + 1, flags: ['SYN', 'ACK'], options: SYN_OPTIONS });
  push('out', { seq: c + 1, ack: s + 1, flags: ['ACK'] });
  t = firstWrite; // ClientHello leaves when Node wrote it
  for (const [dir, isn, peerIsn] of [['out', c, s], ['in', s, c]]) {
    const stream = streams[dir];
    const peerAck = peerIsn + 1 + (dir === 'in' ? streams.out.length : 0);
    for (let off = 0; off < stream.length; off += mss) {
      const payload = stream.subarray(off, off + mss);
      push(dir, { seq: isn + 1 + off, ack: peerAck, flags: ['ACK', 'PSH'], payload }, { payloadFrom: off, payloadTo: off + payload.length });
    }
  }
  push('in', { seq: s + 1 + streams.in.length, ack: c + 1 + streams.out.length, flags: ['FIN', 'ACK'] });
  push('out', { seq: c + 1 + streams.out.length, ack: s + 2 + streams.in.length, flags: ['FIN', 'ACK'] });
  return { packets, streams, local, remote };
}

/** The server's ACK of the client FIN that ends flowFromSession(...) (pass the same ISNs). */
export function finalAckOf(flow, { clientIsn = 1000, serverIsn = 500000 } = {}) {
  return { dir: 'in', timeMs: flow.packets.at(-1).timeMs + 1, data: ipv4Tcp({ src: flow.remote, dst: flow.local,
    seq: serverIsn + 2 + flow.streams.in.length, ack: clientIsn + 2 + flow.streams.out.length, flags: ['ACK'] }) };
}

const LINK = { RAW: 101, ETHERNET: 1, NULL: 0 };

/** pcapng of packets; link: 'RAW' | 'ETHERNET' | 'NULL'; tsresol: if_tsresol byte (6 = microseconds). */
export function toPcapng(packets, { link = 'RAW', tsresol = 6 } = {}) {
  const wrap = (d) => {
    if (link === 'ETHERNET') return Buffer.concat([Buffer.alloc(12), Buffer.from([0x08, 0x00]), d]);
    if (link === 'NULL') return Buffer.concat([Buffer.from([2, 0, 0, 0]), d]);
    return d;
  };
  const unitsPerSecond = tsresol & 0x80 ? 2 ** (tsresol & 0x7f) : 10 ** tsresol;
  return writePcapng({
    interfaces: [{ linkType: LINK[link], tsresol }],
    packets: packets.map((p) => ({ ts: BigInt(Math.round((p.timeMs / 1000) * unitsPerSecond)), data: wrap(p.data) })),
  });
}
