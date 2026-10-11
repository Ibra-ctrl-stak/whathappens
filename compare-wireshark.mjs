// Step 4: compare what day1.mjs recorded with what Wireshark (tshark) captured on the wire.
// Usage: node compare-wireshark.mjs [capture.pcapng] [out/session.json]
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { decryptSession } from './src/tls/decrypt.js';

const run = promisify(execFile);
const CAPTURE = process.argv[2] ?? fileURLToPath(new URL('./out/capture.pcapng', import.meta.url));
const SESSION = process.argv[3] ?? fileURLToPath(new URL('./out/session.json', import.meta.url));
const KEYLOG = fileURLToPath(new URL('./out/keylog.txt', import.meta.url));
const TSHARK_CANDIDATES = [process.env.TSHARK, 'C:\\Program Files\\Wireshark\\tshark.exe', 'tshark'].filter(Boolean);

function findTshark() {
  const found = TSHARK_CANDIDATES.find((p) => p === 'tshark' || existsSync(p));
  if (!found) throw new Error('tshark not found: install Wireshark or set TSHARK=<path to tshark.exe>');
  return found;
}

async function tshark(args) {
  const { stdout } = await run(findTshark(), ['-r', CAPTURE, ...args], { maxBuffer: 64 * 1024 * 1024 });
  return stdout;
}

const cleanHex = (s) => (s ?? '').replace(/[^0-9a-f]/gi, '').toLowerCase();

function check(label, ok, detail = '') {
  console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}`);
  return ok;
}

function firstDiff(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) if (a[i] !== b[i]) return i;
  return a.length === b.length ? -1 : n;
}

function compareBytes(label, ours, theirs) {
  const diff = firstDiff(ours, theirs);
  return check(
    label,
    diff === -1,
    diff === -1 ? `${ours.length} B identical` : `first difference at byte ${diff} (ours ${ours.length} B, capture ${theirs.length} B)`,
  );
}

async function compareDns(dns) {
  const out = await tshark([
    '-Y', 'udp.port == 53',
    '-T', 'fields', '-E', 'separator=|',
    '-e', 'ip.src', '-e', 'udp.srcport', '-e', 'ip.dst', '-e', 'udp.dstport', '-e', 'udp.payload',
  ]);
  const packets = out
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      const [src, sport, dst, dport, payload] = line.split('|');
      return { src, sport: Number(sport), dst, dport: Number(dport), payload: Buffer.from(cleanHex(payload), 'hex') };
    });
  console.log(`\n[DNS] ${packets.length} UDP/53 packets in capture, ${dns.length} exchanges recorded`);
  return dns.flatMap((e, i) => {
    const query = packets.find((p) => p.dst === e.server.ip && p.sport === e.localPort && p.dport === 53);
    const response = packets.find((p) => p.src === e.server.ip && p.dport === e.localPort && p.sport === 53);
    const tag = `#${i + 1} ${e.server.name} :${e.localPort}`;
    return [
      query ? compareBytes(`${tag} query`, Buffer.from(e.queryHex, 'hex'), query.payload) : check(`${tag} query`, false, 'not in capture'),
      response
        ? compareBytes(`${tag} response`, Buffer.from(e.responseHex, 'hex'), response.payload)
        : check(`${tag} response`, false, 'not in capture'),
    ];
  });
}

/** Parse `tshark -z follow,<proto>,raw,N` into per-node byte streams. */
function parseFollowRaw(text) {
  const nodes = [...text.matchAll(/^Node ([01]): (.+)$/gm)].map((m) => m[2].trim());
  const body = text.split(/^Node 1: .+$/m)[1] ?? '';
  const chunks = { 0: [], 1: [] };
  for (const line of body.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('=')) continue;
    const node = line.startsWith('\t') ? 1 : 0;
    chunks[node].push(Buffer.from(cleanHex(line), 'hex'));
  }
  return { nodes, streams: [Buffer.concat(chunks[0]), Buffer.concat(chunks[1])] };
}

function orient(parsed, localPort) {
  const clientIsNode0 = parsed.nodes[0]?.endsWith(`:${localPort}`);
  return clientIsNode0
    ? { client: parsed.streams[0], server: parsed.streams[1] }
    : { client: parsed.streams[1], server: parsed.streams[0] };
}

async function compareTls(tls) {
  const streamIds = await tshark([
    '-Y', `ip.addr == ${tls.ip} && tcp.port == ${tls.local.port}`,
    '-T', 'fields', '-e', 'tcp.stream',
  ]);
  const streamId = streamIds.split(/\r?\n/).find(Boolean);
  console.log(`\n[TLS] ${tls.ip}:443 <- local port ${tls.local.port}`);
  if (streamId === undefined) return [check('TCP stream found in capture', false)];

  const wire = orient(parseFollowRaw(await tshark(['-q', '-z', `follow,tcp,raw,${streamId}`])), tls.local.port);
  const raw = tls.raw.map((c) => ({ dir: c.dir, bytes: Buffer.from(c.hex, 'hex') }));
  const ours = {
    client: Buffer.concat(raw.filter((c) => c.dir === 'out').map((c) => c.bytes)),
    server: Buffer.concat(raw.filter((c) => c.dir === 'in').map((c) => c.bytes)),
  };
  const dec = decryptSession({ raw, keylog: tls.keylog });
  const handshakeEnd = (records) => {
    const lastHs = records.filter((r) => r.epoch !== 'application').at(-1);
    const next = records.find((r) => r.offset > lastHs.offset);
    return next ? next.offset : Infinity;
  };
  const cEnd = handshakeEnd(dec.client.records);
  const sEnd = handshakeEnd(dec.server.records);

  const results = [
    compareBytes('client handshake (ClientHello..Finished)', ours.client.subarray(0, cEnd), wire.client.subarray(0, cEnd)),
    compareBytes('server handshake (ServerHello..Finished)', ours.server.subarray(0, sEnd), wire.server.subarray(0, sEnd)),
    compareBytes('whole client->server TCP stream', ours.client, wire.client),
    compareBytes('whole server->client TCP stream', ours.server, wire.server),
  ];

  // Independent cross-check: Wireshark's own TLS decryption with our keylog vs our decryption.
  // Two passes + out-of-order reassembly: over a lossy tunnel the ServerHello segment may arrive
  // as a retransmission, and single-pass dissection then never sees the handshake.
  const tlsOpts = ['-2', '-o', 'tcp.reassemble_out_of_order:TRUE', '-o', `tls.keylog_file:${KEYLOG.replace(/\\/g, '/')}`];
  const tlsStreamIds = await tshark([...tlsOpts, '-Y', `tcp.stream == ${streamId} && tls`, '-T', 'fields', '-e', 'tls.stream']);
  const tlsStreamId = tlsStreamIds.split(/[\r\n,]+/).find(Boolean) ?? streamId;
  const ws = orient(
    parseFollowRaw(await tshark([...tlsOpts, '-q', '-z', `follow,tls,raw,${tlsStreamId}`])),
    tls.local.port,
  );
  results.push(
    compareBytes('Wireshark-decrypted request == ours', dec.client.appData, ws.client),
    compareBytes('Wireshark-decrypted response == ours', dec.server.appData, ws.server),
  );
  return results;
}

async function main() {
  if (!existsSync(CAPTURE)) throw new Error(`capture not found: ${CAPTURE}`);
  const session = JSON.parse(await readFile(SESSION, 'utf8'));
  console.log(`session ${session.startedAt}, capture ${CAPTURE}`);
  const results = [...(await compareDns(session.dns)), ...(await compareTls(session.tls))];
  const ok = results.every(Boolean);
  console.log(ok ? '\nSTEP 4: MATCH — alive' : '\nSTEP 4: MISMATCH');
  process.exitCode = ok ? 0 : 1;
}

main().catch((err) => {
  console.error(`\nSTEP 4 ERROR: ${err.message}`);
  process.exitCode = 2;
});
