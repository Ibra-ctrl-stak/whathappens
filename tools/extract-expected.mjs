// Ask Wireshark (tshark) what it sees in a capture of a recorded session, and save that as the
// independent oracle for fixture tests: our parsers must reproduce these values.
// Usage: node tools/extract-expected.mjs <capture.pcapng> <session.json> <keylog.txt> > expected.json
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';

const run = promisify(execFile);
const TSHARK = process.env.TSHARK ?? 'C:\\Program Files\\Wireshark\\tshark.exe';
const [capture, sessionPath, keylogPath] = process.argv.slice(2);
if (!keylogPath) throw new Error('usage: extract-expected.mjs <capture.pcapng> <session.json> <keylog.txt>');

const session = JSON.parse(readFileSync(sessionPath, 'utf8'));
const TLS_OPTS = ['-2', '-o', 'tcp.reassemble_out_of_order:TRUE', '-o', `tls.keylog_file:${keylogPath.replace(/\\/g, '/')}`];

async function fields(filter, names, extra = []) {
  const args = ['-r', capture, ...extra, '-Y', filter, '-T', 'fields', '-E', 'separator=|', '-E', 'occurrence=a', '-E', 'aggregator=,'];
  const { stdout } = await run(TSHARK, [...args, ...names.flatMap((n) => ['-e', n])], { maxBuffer: 64 * 1024 * 1024 });
  return stdout
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => Object.fromEntries(line.split('|').map((v, i) => [names[i], v])));
}

const list = (s) => (s ? s.split(',') : []);
const nums = (s) => list(s).map(Number);
const bool = (s) => s === 'True' || s === '1';

async function dnsExpected() {
  const answered = session.dns.filter((e) => e.responseHex !== null);
  const ports = answered.map((e) => e.localPort).join(',');
  const rows = await fields(`dns.flags.response == 1 && udp.dstport in {${ports}}`, [
    'udp.dstport', 'dns.id', 'dns.qry.name', 'dns.flags.authoritative', 'dns.flags.truncated', 'dns.flags.rcode',
    'dns.count.answers', 'dns.count.auth_rr', 'dns.count.add_rr', 'dns.a', 'dns.ns',
  ]);
  return answered.map((e) => {
    const r = rows.find((row) => Number(row['udp.dstport']) === e.localPort);
    if (!r) throw new Error(`no DNS response in capture for port ${e.localPort}`);
    return {
      localPort: e.localPort,
      id: Number(r['dns.id']),
      qname: r['dns.qry.name'],
      authoritative: bool(r['dns.flags.authoritative']),
      truncated: bool(r['dns.flags.truncated']),
      rcode: Number(r['dns.flags.rcode']),
      counts: {
        answers: Number(r['dns.count.answers']),
        authority: Number(r['dns.count.auth_rr']),
        additional: Number(r['dns.count.add_rr']),
      },
      a: list(r['dns.a']).sort(),
      ns: list(r['dns.ns']).sort(),
    };
  });
}

async function tlsExpected() {
  const port = session.tls.local.port;
  const rows = await fields(`tcp.port == ${port} && tls`, [
    'tcp.srcport', 'tls.record.content_type', 'tls.record.length', 'tls.handshake.type',
    'tls.handshake.random', 'tls.handshake.ciphersuite', 'tls.handshake.extensions_server_name',
    'tls.handshake.extensions_alpn_str',
  ], TLS_OPTS);
  const side = (fromClient) => rows.filter((r) => (Number(r['tcp.srcport']) === port) === fromClient);
  // Per record: [content type (inner one once decrypted), outer record length].
  const records = (rs) => rs.flatMap((r) => nums(r['tls.record.content_type']).map((t, i) => [t, nums(r['tls.record.length'])[i]]));
  const hsTypes = (rs) => rs.flatMap((r) => nums(r['tls.handshake.type']));
  const client = side(true);
  const server = side(false);
  const hello = (rs, type) => rs.find((r) => nums(r['tls.handshake.type']).includes(type));
  return {
    clientRandom: hello(client, 1)['tls.handshake.random'],
    serverRandom: hello(server, 2)['tls.handshake.random'],
    cipherSuite: Number(hello(server, 2)['tls.handshake.ciphersuite']),
    sni: hello(client, 1)['tls.handshake.extensions_server_name'],
    alpn: server.map((r) => r['tls.handshake.extensions_alpn_str']).find(Boolean),
    records: { client: records(client), server: records(server) },
    handshakeTypes: { client: hsTypes(client), server: hsTypes(server) },
  };
}

async function httpExpected() {
  const rows = await fields(`tcp.port == ${session.tls.local.port} && http`, [
    'http.request.method', 'http.request.uri', 'http.host', 'http.user_agent', 'http.response.code',
    'http.response.phrase', 'http.content_type', 'http.content_length', 'http.file_data',
  ], TLS_OPTS);
  const req = rows.find((r) => r['http.request.method']);
  const res = rows.find((r) => r['http.response.code']);
  return {
    request: { method: req['http.request.method'], uri: req['http.request.uri'], host: req['http.host'], userAgent: req['http.user_agent'] },
    response: {
      code: Number(res['http.response.code']),
      phrase: res['http.response.phrase'],
      contentType: res['http.content_type'],
      contentLength: Number(res['http.content_length']),
      bodySha256: createHash('sha256').update(Buffer.from(res['http.file_data'], 'hex')).digest('hex'),
    },
  };
}

const { stdout: version } = await run(TSHARK, ['--version']);
const expected = {
  source: `${version.split(/\r?\n/)[0]} on a capture of session ${session.startedAt}`,
  dns: await dnsExpected(),
  tls: await tlsExpected(),
  http: await httpExpected(),
};
process.stdout.write(`${JSON.stringify(expected, null, 2)}\n`);
