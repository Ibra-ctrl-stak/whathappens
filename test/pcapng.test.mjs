// pcapng reader: bounds, byte order, per-interface timestamp resolution, diagnostics, truncation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readPcapng } from '../src/pcap/pcapng.js';
import { writePcapng } from '../src/pcap/pcapng-write.js';

const RAW_IP = 101;
const data = (n) => Buffer.alloc(n, 0x45);
// 2026-10-11T18:00:00.123456Z
const SECONDS = 1791741600n;

test('little- and big-endian sections read the same packets', () => {
  for (const littleEndian of [true, false]) {
    const file = writePcapng({ littleEndian, interfaces: [{ linkType: RAW_IP }], packets: [{ ts: SECONDS * 1000000n + 123456n, data: data(40) }] });
    const { packets, problems, truncated } = readPcapng(file);
    assert.deepEqual([packets.length, problems, truncated], [1, [], false], `littleEndian=${littleEndian}`);
    assert.equal(packets[0].captureTime, '2026-10-11T18:00:00.123456000Z');
    assert.equal(packets[0].linkType, RAW_IP);
  }
});

test('timestamp resolution and offset are applied per interface', () => {
  const file = writePcapng({
    interfaces: [{ linkType: RAW_IP }, { linkType: RAW_IP, tsresol: 9 }, { linkType: RAW_IP, tsresol: 0x80 | 20 }, { linkType: RAW_IP, tsoffset: 10n }],
    packets: [
      { interfaceId: 0, ts: SECONDS * 1000000n + 123456n, data: data(20) }, // microseconds (default)
      { interfaceId: 1, ts: SECONDS * 1000000000n + 123456789n, data: data(20) }, // nanoseconds
      { interfaceId: 2, ts: SECONDS * (1n << 20n) + (1n << 19n), data: data(20) }, // 2^-20 s: +0.5 s
      { interfaceId: 3, ts: 123456n, data: data(20) }, // microseconds after a 10 s offset
    ],
  });
  const times = readPcapng(file).packets.map((p) => p.captureTime);
  assert.deepEqual(times, ['2026-10-11T18:00:00.123456000Z', '2026-10-11T18:00:00.123456789Z', '2026-10-11T18:00:00.500000000Z', '1970-01-01T00:00:10.123456000Z']);
  const [first] = readPcapng(file).packets;
  assert.equal(first.timeMs, Number(SECONDS) * 1000 + 123.456);
});

test('an EPB naming an unknown interface is reported and skipped', () => {
  const file = writePcapng({ interfaces: [{ linkType: RAW_IP }], packets: [{ ts: 1n, data: data(20) }, { interfaceId: 5, ts: 2n, data: data(20) }] });
  const { packets, problems } = readPcapng(file);
  assert.equal(packets.length, 1);
  assert.match(problems.join(), /frame 2: unknown interface 5/);
});

test('a file cut inside its last block keeps the packets read so far', () => {
  const file = writePcapng({ interfaces: [{ linkType: RAW_IP }], packets: [1, 2, 3].map((i) => ({ ts: BigInt(i), data: data(60) })) });
  const { packets, truncated, problems } = readPcapng(file.subarray(0, file.length - 30));
  assert.equal(packets.length, 2);
  assert.equal(truncated, true);
  assert.match(problems.join(), /ends inside a block/);
});

test('limits: file size, blocks and packets', () => {
  const file = writePcapng({ interfaces: [{ linkType: RAW_IP }], packets: [1, 2, 3].map((i) => ({ ts: BigInt(i), data: data(20) })) });
  assert.throws(() => readPcapng(file, { maxBytes: 100 }), /larger than/);
  const fewPackets = readPcapng(file, { maxPackets: 2 });
  assert.equal(fewPackets.packets.length, 2);
  assert.match(fewPackets.problems.join(), /packet limit/);
  assert.match(readPcapng(file, { maxBlocks: 3 }).problems.join(), /block limit/);
});

test('classic pcap and garbage are refused with a clear reason', () => {
  assert.throws(() => readPcapng(Buffer.from('d4c3b2a1020004000000000000000000ffff000001000000', 'hex')), /classic pcap/);
  assert.throws(() => readPcapng(Buffer.from('not a capture at all')), /not a pcapng/);
});

test('a block with an impossible length stops reading with a problem', () => {
  const file = Buffer.from(writePcapng({ interfaces: [{ linkType: RAW_IP }], packets: [{ ts: 1n, data: data(20) }] }));
  const epbAt = file.length - (12 + 20 + 20);
  file.writeUInt32LE(13, epbAt + 4); // not a multiple of 4
  const { packets, problems } = readPcapng(file);
  assert.equal(packets.length, 0);
  assert.match(problems.join(), /invalid block length/);
});

test('captured length over snaplen or over original length is reported', () => {
  const file = writePcapng({
    interfaces: [{ linkType: RAW_IP, snaplen: 30 }],
    packets: [{ ts: 1n, data: data(40) }, { ts: 2n, data: data(20), originalLength: 10 }],
  });
  const { packets, problems } = readPcapng(file);
  assert.equal(packets.length, 0);
  assert.match(problems.join(), /frame 1: captured 40 bytes over snaplen 30/);
  assert.match(problems.join(), /frame 2: captured 20 bytes over original length 10/);
});
