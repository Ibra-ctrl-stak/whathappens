// Cut a capture down to the one TCP connection of a recording, for a shareable fixture.
// Writes a fresh pcapng: one section without options (no OS/hardware/application metadata),
// one interface (same link type, nanosecond timestamps), and only that connection's packets.
// Usage: node tools/trim-pcapng.mjs <capture.pcapng> <session.json> <out.pcapng>
import { readFileSync, writeFileSync } from 'node:fs';
import { readPcapng } from '../src/pcap/pcapng.js';
import { writePcapng } from '../src/pcap/pcapng-write.js';
import { analyzeCapture } from '../src/pcap/connection.js';
import { loadSession } from '../src/session.js';

const [input, sessionPath, output] = process.argv.slice(2);
if (!output) throw new Error('usage: trim-pcapng.mjs <capture.pcapng> <session.json> <out.pcapng>');
const capture = readFileSync(input);
const analysis = analyzeCapture(capture, loadSession(JSON.parse(readFileSync(sessionPath, 'utf8'))));
if (analysis.status !== 'matched') throw new Error(`no connection to keep: ${analysis.reason}`);

const keep = new Set(analysis.segments.map((s) => s.frame));
const packets = readPcapng(capture).packets.filter((p) => keep.has(p.frame));
const linkTypes = [...new Set(packets.map((p) => p.linkType))];
if (linkTypes.length !== 1) throw new Error(`the connection spans ${linkTypes.length} link types; not supported`);
const NANOSECONDS = 9;
writeFileSync(output, writePcapng({
  interfaces: [{ linkType: linkTypes[0], tsresol: NANOSECONDS }],
  packets: packets.map((p) => ({ ts: p.timeNs, data: p.data, originalLength: p.originalLength })),
}));
console.log(`kept ${packets.length} of ${readPcapng(capture).packets.length} packets (${analysis.reason}) -> ${output}`);
