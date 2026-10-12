// Iterative resolution against a fake, in-memory DNS: walks referrals, and stays bounded
// when a hostile or broken zone loops CNAMEs or fans out into many unglued nameservers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveA, ROOT_SERVERS, MAX_QUERIES } from '../src/dns/iterative.js';
import { respond, NS, A, CNAME } from './helpers/dns-build.mjs';

const BOUNDED_MS = 2000;

const questionName = (query) => {
  const labels = [];
  for (let pos = 12; query[pos] !== 0; pos += query[pos] + 1) labels.push(query.toString('latin1', pos + 1, pos + 1 + query[pos]));
  return labels.join('.');
};

/** Fake network: world(ip, qname, query) -> response sections, raw response bytes, or null for "no answer". */
function fakeTransport(world) {
  const calls = [];
  const transport = async (server, query) => {
    calls.push({ ip: server.ip, qname: questionName(query) });
    const reply = world(server.ip, questionName(query), query);
    if (!reply) throw Object.assign(new Error('timeout (fake)'), { sentAt: 0, localPort: 1, failedAt: 1 });
    return { response: Buffer.isBuffer(reply) ? reply : respond(query, reply), localPort: 1, sentAt: 0, receivedAt: 1 };
  };
  return { transport, calls };
}

const isRoot = (ip) => ROOT_SERVERS.some((s) => s.ip === ip);

test('cancellation is not swallowed by nameserver retry/fallback', async () => {
  const controller = new AbortController();
  let calls = 0;
  await assert.rejects(resolveA('example.com', {
    signal: controller.signal,
    transport: async () => {
      calls += 1;
      controller.abort(new Error('stop resolution'));
      throw controller.signal.reason;
    },
  }), /stop resolution/);
  assert.equal(calls, 1);
});

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

test('a malformed answer is recorded with its bytes and the reason, then the next server is asked', async () => {
  const malformed = (query) => {
    const bad = respond(query, {});
    bad.writeUInt16BE(1, 6); // claims one answer record that is not there
    return bad;
  };
  const { transport } = fakeTransport((ip, qname, query) => {
    if (ip === ROOT_SERVERS[0].ip) return malformed(query);
    if (isRoot(ip)) return { aa: true, answers: [A('www.example.test', '203.0.113.7')] };
    return null;
  });
  const exchanges = [];
  assert.deepEqual(await resolveA('www.example.test', { transport, onExchange: (e) => exchanges.push(e) }), ['203.0.113.7']);
  const [first, second] = exchanges;
  assert.equal(first.server.ip, ROOT_SERVERS[0].ip);
  assert.ok(Buffer.isBuffer(first.response) && first.response.length > 12, 'malformed bytes are kept');
  assert.match(first.error, /malformed response/);
  assert.equal(first.parsed, null);
  assert.equal(second.server.ip, ROOT_SERVERS[1].ip);
  assert.equal(second.error, undefined);
});
