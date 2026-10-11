// Iterative resolution against a fake, in-memory DNS: walks referrals, and stays bounded
// when a hostile or broken zone loops CNAMEs or fans out into many unglued nameservers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveA, ROOT_SERVERS, MAX_QUERIES } from '../src/dns/iterative.js';
import { TYPE } from '../src/dns/packet.js';

const BOUNDED_MS = 2000;

const encodeName = (name) =>
  Buffer.concat([...name.split('.').filter(Boolean).map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);

function encodeRecord({ name, type, data }) {
  const rdata = type === TYPE.A ? Buffer.from(data.split('.').map(Number)) : encodeName(data);
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(type, 0);
  fixed.writeUInt16BE(1, 2); // IN
  fixed.writeUInt32BE(60, 4);
  fixed.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([encodeName(name), fixed, rdata]);
}

/** A response to `query` (question copied verbatim) with the given sections. */
function respond(query, { aa = false, answers = [], authority = [], additional = [] }) {
  const qEnd = query.length - 11; // buildQuery appends an 11-byte OPT record
  const header = Buffer.from(query.subarray(0, 12));
  header.writeUInt16BE(0x8000 | (aa ? 0x0400 : 0), 2);
  header.writeUInt16BE(answers.length, 6);
  header.writeUInt16BE(authority.length, 8);
  header.writeUInt16BE(additional.length, 10);
  return Buffer.concat([header, query.subarray(12, qEnd), ...[...answers, ...authority, ...additional].map(encodeRecord)]);
}

const questionName = (query) => {
  const labels = [];
  for (let pos = 12; query[pos] !== 0; pos += query[pos] + 1) labels.push(query.toString('latin1', pos + 1, pos + 1 + query[pos]));
  return labels.join('.');
};

/** Fake network: world(ip, qname) -> response sections, or null for "no answer". */
function fakeTransport(world) {
  const calls = [];
  const transport = async (server, query) => {
    calls.push({ ip: server.ip, qname: questionName(query) });
    const sections = world(server.ip, questionName(query));
    if (!sections) throw Object.assign(new Error('timeout (fake)'), { sentAt: 0, localPort: 1, failedAt: 1 });
    return { response: respond(query, sections), localPort: 1, sentAt: 0, receivedAt: 1 };
  };
  return { transport, calls };
}

const isRoot = (ip) => ROOT_SERVERS.some((s) => s.ip === ip);
const NS = (name, data) => ({ name, type: TYPE.NS, data });
const A = (name, data) => ({ name, type: TYPE.A, data });
const CNAME = (name, data) => ({ name, type: TYPE.CNAME, data });

test('walks root -> TLD -> authoritative and returns the A record', async () => {
  const { transport, calls } = fakeTransport((ip) => {
    if (isRoot(ip)) return { authority: [NS('test', 'ns.tld.test')], additional: [A('ns.tld.test', '192.0.2.1')] };
    if (ip === '192.0.2.1') return { authority: [NS('example.test', 'ns1.example.test')], additional: [A('ns1.example.test', '192.0.2.2')] };
    if (ip === '192.0.2.2') return { aa: true, answers: [A('www.example.test', '203.0.113.7')] };
    return null;
  });
  assert.deepEqual(await resolveA('www.example.test', { transport }), ['203.0.113.7']);
  assert.deepEqual(calls.map((c) => c.ip), ['198.41.0.4', '192.0.2.1', '192.0.2.2']);
});

const authoritativeFor = (answer) => (ip, qname) => {
  if (isRoot(ip)) return { authority: [NS('test', 'ns.test')], additional: [A('ns.test', '192.0.2.9')] };
  return { aa: true, answers: answer(qname) };
};

test('a CNAME loop spread over separate responses ends with an error', { timeout: BOUNDED_MS }, async () => {
  const { transport, calls } = fakeTransport(
    authoritativeFor((q) => [CNAME(q, q === 'a.test' ? 'b.test' : 'a.test')]),
  );
  await assert.rejects(resolveA('a.test', { transport }), /CNAME/);
  assert.ok(calls.length <= MAX_QUERIES, `${calls.length} queries`);
});

test('a referral to many unglued nameservers cannot fan out without bound', { timeout: BOUNDED_MS }, async () => {
  // Every name is delegated to 50 nameservers that have no glue and live under the same broken zone.
  const fanOut = Array.from({ length: 50 }, (_, i) => NS('broken.test', `ns${i}.broken.test`));
  const { transport, calls } = fakeTransport((ip) => (isRoot(ip) ? { authority: fanOut } : null));
  await assert.rejects(resolveA('victim.broken.test', { transport }));
  assert.ok(calls.length <= MAX_QUERIES, `${calls.length} queries`);
});
