// Day 1 viability check: own DNS -> recorded TLS -> own decryption, all for one github.com request.
// Writes out/session.json (every byte) and out/keylog.txt (SSLKEYLOGFILE format for Wireshark).
import { mkdir, writeFile } from 'node:fs/promises';
import { resolveA } from './src/dns/iterative.js';
import { recordHttpsGet } from './src/tls/recorder.js';
import { decryptSession } from './src/tls/decrypt.js';
import { serializeSession } from './src/session.js';
import { nowMs } from './src/clock.js';

const HOST = 'github.com';
const PATH = process.argv[2] ?? '/robots.txt';
const OUT_DIR = new URL('./out/', import.meta.url);
const HANDSHAKE_NAMES = { 4: 'NewSessionTicket', 8: 'EncryptedExtensions', 11: 'Certificate', 15: 'CertificateVerify', 20: 'Finished' };
const CONTENT_NAMES = { 20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'ApplicationData' };

function check(label, ok, detail = '') {
  console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}`);
  return ok;
}

function describeRecord(r) {
  if (r.epoch === 'plaintext') return `${CONTENT_NAMES[r.outerType]} (plaintext, ${r.length} B)`;
  const inner = CONTENT_NAMES[r.contentType] ?? r.contentType;
  const hs = r.handshakeTypes?.length ? ` [${r.handshakeTypes.map((t) => HANDSHAKE_NAMES[t] ?? t).join(', ')}]` : '';
  return `${r.epoch} #${r.seq}: ${inner}, ${r.content.length} B${hs}`;
}

async function main() {
  const startedAt = nowMs();

  console.log(`\n[1] Iterative DNS: A ${HOST}`);
  const dns = [];
  const ips = await resolveA(HOST, {
    onExchange: (e) => {
      dns.push(e);
      if (e.error) {
        console.log(`  ${e.server.name} (${e.server.ip}) :${e.localPort}  LOST — ${e.error}, retrying`);
        return;
      }
      const ns = e.parsed.authority.filter((r) => r.typeName === 'NS').map((r) => r.data);
      const what = e.parsed.answers.length
        ? `answer: ${e.parsed.answers.map((r) => `${r.typeName} ${r.data}`).join(', ')}`
        : `referral -> ${ns.slice(0, 2).join(', ')}${ns.length > 2 ? ` (+${ns.length - 2})` : ''}`;
      console.log(`  ${e.server.name} (${e.server.ip}) :${e.localPort} ${Math.round(e.rttMs)}ms  ${what}`);
    },
  });
  const ip = ips[0];
  console.log(`  => ${HOST} = ${ips.join(', ')}`);

  console.log(`\n[2] TLS to ${ip}:443 (SNI ${HOST}), GET ${PATH}`);
  const session = await recordHttpsGet({ ip, servername: HOST, path: PATH });
  const bytes = (dir) => session.raw.filter((c) => c.dir === dir).reduce((n, c) => n + c.bytes.length, 0);
  console.log(`  local ${session.local.address}:${session.local.port}, ${session.tls.protocol}, ${session.tls.cipher.standardName}, ALPN ${session.tls.alpn}, cert ok: ${session.tls.authorized}`);
  console.log(`  wire: ${session.raw.length} chunks, out ${bytes('out')} B, in ${bytes('in')} B; keylog: ${session.keylog.length} secrets`);

  console.log('\n[3] Own decryption from keylog + recorded bytes');
  const dec = decryptSession({ raw: session.raw, keylog: session.keylog });
  console.log(`  suite ${dec.suite.name}; server records:`);
  dec.server.records.slice(0, 12).forEach((r) => console.log(`    ${describeRecord(r)}`));
  if (dec.server.records.length > 12) console.log(`    ... ${dec.server.records.length - 12} more`);

  const head = dec.server.appData.toString('latin1').split('\r\n\r\n')[0];
  console.log(`\n  First HTTP response (decrypted by us):\n    ${head.split('\r\n').slice(0, 8).join('\n    ')}`);

  console.log('\n  Checks:');
  const results = [
    check('DNS answer came from an authoritative server', dns.at(-1).parsed.authoritative),
    check('TLS 1.3', session.tls.protocol === 'TLSv1.3'),
    check('no trailing partial records', dec.trailingBytes.client === 0 && dec.trailingBytes.server === 0),
    check(
      'our decrypted request == bytes Node sent',
      dec.client.appData.equals(session.plaintext.sent),
      `${dec.client.appData.length} B`,
    ),
    check(
      'our decrypted response == bytes Node received',
      dec.server.appData.equals(session.plaintext.received),
      `${dec.server.appData.length} B`,
    ),
    check('response starts with HTTP/1.1', head.startsWith('HTTP/1.1 ')),
  ];

  await mkdir(OUT_DIR, { recursive: true });
  await writeFile(new URL('keylog.txt', OUT_DIR), `${session.keylog.join('\n')}\n`);
  const saved = serializeSession({ startedAt, host: HOST, path: PATH, dns, tls: session });
  await writeFile(new URL('session.json', OUT_DIR), `${JSON.stringify(saved, null, 2)}\n`);
  console.log('\n  saved out/session.json, out/keylog.txt');

  const alive = results.every(Boolean);
  console.log(alive ? '\nSTEPS 1-3: ALIVE' : '\nSTEPS 1-3: FAILED');
  process.exitCode = alive ? 0 : 1;
}

main().catch((err) => {
  console.error(`\nDEAD: ${err.stack ?? err.message}`);
  process.exitCode = 2;
});
