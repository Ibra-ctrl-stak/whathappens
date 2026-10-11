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

/** One tshark field across all matching frames, as a flat list ('|' aggregator: values may contain commas). */
async function column(filter, name) {
  const { stdout } = await run(
    TSHARK,
    ['-r', capture, ...TLS_OPTS, '-Y', filter, '-T', 'fields', '-E', 'occurrence=a', '-E', 'aggregator=|', '-e', name],
    { maxBuffer: 64 * 1024 * 1024 },
  );
  return stdout.split(/\r?\n/).filter(Boolean).flatMap((line) => line.split('|'));
}

const hexNum = (s) => Number.parseInt(s, 16);
const stripCrlf = (line) => line.replace(/\\r\\n$/, ''); // tshark prints the CRLF as the text "\r\n"
const normSerial = (s) => s.replace(/^(00)+/, '').toLowerCase();

/** Day 4 fields. Only per-message-unambiguous tshark fields: ServerHello and EE share a frame. */
async function handshakeFieldsExpected() {
  const port = session.tls.local.port;
  const on = (type) => `tcp.port == ${port} && tls.handshake.type == ${type}`;
  const [ch] = await fields(on(1), [
    'tls.handshake.extensions_server_name', 'tls.handshake.extensions_alpn_str', 'tls.handshake.extensions.supported_version',
    'tls.handshake.extensions_key_share_group', 'tls.handshake.extensions_key_share_key_exchange_length', 'tls.handshake.extension.type',
  ], TLS_OPTS);
  const [sh] = await fields(on(2), ['tls.handshake.extensions.supported_version', 'tls.handshake.extensions_key_share_group',
    'tls.handshake.extensions_key_share_key_exchange_length'], TLS_OPTS);
  const ders = await column(on(11), 'tls.handshake.certificate');
  const serials = await column(on(11), 'x509af.serialNumber');
  const times = await column(on(11), 'x509af.utcTime');
  const keyGroups = nums(ch['tls.handshake.extensions_key_share_group']);
  const keyLengths = nums(ch['tls.handshake.extensions_key_share_key_exchange_length']);
  const tickets = await fields(on(4), ['tls.handshake.session_ticket_lifetime_hint', 'tls.handshake.session_ticket_age_add',
    'tls.handshake.session_ticket_nonce', 'tls.handshake.session_ticket_length'], TLS_OPTS);
  return {
    clientHello: {
      sni: ch['tls.handshake.extensions_server_name'],
      alpn: list(ch['tls.handshake.extensions_alpn_str']),
      supportedVersions: list(ch['tls.handshake.extensions.supported_version']).map(hexNum),
      keyShare: keyGroups.map((group, i) => ({ group, keyLength: keyLengths[i] })),
      extensionTypes: nums(ch['tls.handshake.extension.type']),
    },
    serverHello: {
      supportedVersion: hexNum(sh['tls.handshake.extensions.supported_version']),
      keyShare: { group: Number(sh['tls.handshake.extensions_key_share_group']), keyLength: Number(sh['tls.handshake.extensions_key_share_key_exchange_length']) },
    },
    encryptedExtensions: { alpn: (await column(on(8), 'tls.handshake.extensions_alpn_str'))[0] },
    certificates: ders.map((der, i) => ({
      length: der.length / 2,
      derSha256: createHash('sha256').update(Buffer.from(der, 'hex')).digest('hex'),
      serial: normSerial(serials[i]),
      notBefore: times[2 * i],
      notAfter: times[2 * i + 1],
    })),
    leafDnsNames: await column(on(11), 'x509ce.dNSName'),
    certificateVerifyScheme: hexNum((await column(on(15), 'tls.handshake.sig_hash_alg'))[0]),
    newSessionTickets: tickets.map((t) => ({
      lifetime: Number(t['tls.handshake.session_ticket_lifetime_hint']),
      ageAdd: Number(t['tls.handshake.session_ticket_age_add']),
      nonce: t['tls.handshake.session_ticket_nonce'],
      ticketLength: Number(t['tls.handshake.session_ticket_length']),
    })),
  };
}

async function headerLinesExpected() {
  const port = session.tls.local.port;
  return {
    request: (await column(`tcp.port == ${port} && http.request`, 'http.request.line')).map(stripCrlf),
    response: (await column(`tcp.port == ${port} && http.response`, 'http.response.line')).map(stripCrlf),
  };
}

const { stdout: version } = await run(TSHARK, ['--version']);
const expected = {
  source: `${version.split(/\r?\n/)[0]} on a capture of session ${session.startedAt}`,
  dns: await dnsExpected(),
  tls: { ...(await tlsExpected()), ...(await handshakeFieldsExpected()) },
  http: { ...(await httpExpected()), headerLines: await headerLinesExpected() },
};
process.stdout.write(`${JSON.stringify(expected, null, 2)}\n`);
