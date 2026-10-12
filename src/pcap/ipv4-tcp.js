// Link layer -> IPv4 -> TCP for captured packets. Anything else is skipped with a reason.
// IP fragments are not reassembled, so they are never treated as TCP segments.

const LINK = Object.freeze({ NULL: 0, ETHERNET: 1, RAW: 101, LOOP: 108, IPV4: 228 });
const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_VLAN = 0x8100;
const AF_INET = 2;
const PROTO_TCP = 6;
const FLAG_NAMES = [['CWR', 0x80], ['ECE', 0x40], ['URG', 0x20], ['ACK', 0x10], ['PSH', 0x08], ['RST', 0x04], ['SYN', 0x02], ['FIN', 0x01]];

const skip = (reason) => ({ skip: reason });
const ip4 = (b, at) => `${b[at]}.${b[at + 1]}.${b[at + 2]}.${b[at + 3]}`;

/** Offset of the IPv4 header in the packet, or a skip reason. */
function ipStart(data, linkType) {
  if (linkType === LINK.RAW || linkType === LINK.IPV4) return data.length && data[0] >> 4 === 4 ? 0 : skip('not IPv4');
  if (linkType === LINK.NULL || linkType === LINK.LOOP) {
    if (data.length < 4) return skip('truncated loopback header');
    const family = linkType === LINK.LOOP ? data.readUInt32BE(0) : Math.min(data.readUInt32LE(0), data.readUInt32BE(0));
    return family === AF_INET ? 4 : skip('not IPv4');
  }
  if (linkType === LINK.ETHERNET) {
    if (data.length < 14) return skip('truncated Ethernet header');
    let type = data.readUInt16BE(12);
    let at = 14;
    if (type === ETHERTYPE_VLAN) {
      if (data.length < 18) return skip('truncated VLAN header');
      type = data.readUInt16BE(16);
      at = 18;
    }
    return type === ETHERTYPE_IPV4 ? at : skip('not IPv4');
  }
  return skip(`unsupported link type ${linkType}`);
}

function tcpOptions(b, from, to) {
  const out = {};
  let pos = from;
  while (pos < to) {
    const kind = b[pos];
    if (kind === 0) break;
    if (kind === 1) { pos += 1; continue; }
    const len = b[pos + 1];
    if (len === undefined || len < 2 || pos + len > to) { out.malformed = true; break; }
    if (kind === 2 && len === 4) out.mss = b.readUInt16BE(pos + 2);
    else if (kind === 3 && len === 3) out.windowScale = b[pos + 2];
    else if (kind === 4 && len === 2) out.sackPermitted = true;
    else if (kind === 5) out.sackBlocks = (len - 2) / 8;
    else if (kind === 8 && len === 10) out.timestamps = true;
    pos += len;
  }
  return out;
}

/**
 * packet (from readPcapng) -> { tcp } or { skip }. payloadLength comes from the IP header;
 * payload holds only the captured part (payloadTruncated when the capture cut it short).
 */
export function decodeTcp(packet) {
  const { data } = packet;
  const at = ipStart(data, packet.linkType);
  if (typeof at !== 'number') return at;
  if (data.length - at < 20) return skip('truncated IPv4 header');
  if (data[at] >> 4 !== 4) return skip('not IPv4');
  const ihl = (data[at] & 0x0f) * 4;
  const totalLength = data.readUInt16BE(at + 2);
  if (ihl < 20 || totalLength < ihl || data.length - at < ihl) return skip('malformed IPv4 header');
  const fragment = data.readUInt16BE(at + 6);
  if (fragment & 0x2000 || fragment & 0x1fff) return skip('IPv4 fragment (fragments are not reassembled)');
  if (data[at + 9] !== PROTO_TCP) return skip('not TCP');
  const tcpAt = at + ihl;
  const ipEnd = at + totalLength;
  const captured = Math.min(ipEnd, data.length);
  if (captured - tcpAt < 20) return skip('truncated TCP header');
  const dataOffset = (data[tcpAt + 12] >> 4) * 4;
  if (dataOffset < 20 || totalLength - ihl < dataOffset) return skip('malformed TCP header');
  if (captured - tcpAt < dataOffset) return skip('truncated TCP options');
  const flagsByte = data[tcpAt + 13];
  const payloadLength = totalLength - ihl - dataOffset;
  return {
    tcp: {
      src: { address: ip4(data, at + 12), port: data.readUInt16BE(tcpAt) },
      dst: { address: ip4(data, at + 16), port: data.readUInt16BE(tcpAt + 2) },
      seq: data.readUInt32BE(tcpAt + 4),
      ack: data.readUInt32BE(tcpAt + 8),
      flags: FLAG_NAMES.filter(([, bit]) => flagsByte & bit).map(([name]) => name).reverse(),
      window: data.readUInt16BE(tcpAt + 14),
      options: tcpOptions(data, tcpAt + 20, tcpAt + dataOffset),
      payloadLength,
      payload: data.subarray(tcpAt + dataOffset, captured),
      payloadTruncated: captured < ipEnd,
    },
  };
}
