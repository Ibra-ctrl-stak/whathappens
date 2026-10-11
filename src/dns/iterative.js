// Iterative resolver: root -> TLD -> authoritative, over raw UDP sockets (no dns.lookup).
import dgram from 'node:dgram';
import { randomInt } from 'node:crypto';
import { buildQuery, parseResponse, isAnswerTo, TYPE } from './packet.js';
import { nowMs } from '../clock.js';

// IANA root hints (named.root), IPv4 only.
export const ROOT_SERVERS = Object.freeze([
  { name: 'a.root-servers.net', ip: '198.41.0.4' },
  { name: 'b.root-servers.net', ip: '170.247.170.2' },
  { name: 'c.root-servers.net', ip: '192.33.4.12' },
  { name: 'f.root-servers.net', ip: '192.5.5.241' },
  { name: 'k.root-servers.net', ip: '193.0.14.129' },
  { name: 'm.root-servers.net', ip: '202.12.27.33' },
]);

const DNS_PORT = 53;
const QUERY_TIMEOUT_MS = 2500;
const MAX_REFERRALS = 16;
const MAX_NS_DEPTH = 4;
const ATTEMPTS_PER_SERVER = 2;

/**
 * One UDP request/response, with the exact bytes on both sides. Only a datagram from the
 * server's own address and port that answers this very question ends the wait; anything else
 * (spoofed, stale, or malformed) is ignored. server.port is for loopback tests; default 53.
 */
export function exchange(server, query) {
  const port = server.port ?? DNS_PORT;
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let sentAt = null;
    let localPort = null;
    // Failures carry what did happen on the wire, so a lost datagram still shows up in the record.
    const fail = (err) => Object.assign(err, { sentAt, localPort, failedAt: nowMs() });
    const timer = setTimeout(() => {
      socket.close();
      reject(fail(new Error(`timeout ${QUERY_TIMEOUT_MS}ms from ${server.name} (${server.ip})`)));
    }, QUERY_TIMEOUT_MS);

    socket.on('error', (err) => {
      clearTimeout(timer);
      socket.close();
      reject(fail(err));
    });
    socket.on('message', (msg, rinfo) => {
      if (rinfo.address !== server.ip || rinfo.port !== port || !isAnswerTo(query, msg)) return;
      const receivedAt = nowMs();
      clearTimeout(timer);
      socket.close();
      resolve({ response: msg, localPort, sentAt, receivedAt });
    });
    socket.bind(0, () => {
      localPort = socket.address().port;
      sentAt = nowMs();
      socket.send(query, port, server.ip);
    });
  });
}

async function askOnce(server, name, onExchange) {
  const id = randomInt(0, 0x10000);
  const query = buildQuery({ id, name, type: TYPE.A });
  let result;
  try {
    result = await exchange(server, query);
  } catch (err) {
    const { sentAt = null, localPort = null, failedAt = null } = err;
    onExchange({ server, localPort, qname: name, query, response: null, sentAt, receivedAt: null, failedAt, error: err.message, parsed: null });
    throw err;
  }
  const { response, localPort, sentAt, receivedAt } = result;
  const parsed = parseResponse(response);
  onExchange({ server, localPort, qname: name, query, response, sentAt, receivedAt, rttMs: receivedAt - sentAt, parsed });
  return parsed;
}

/** Try each server; UDP datagrams get lost, so every server gets a second chance. */
async function askAny(servers, name, onExchange, errors = []) {
  for (let attempt = 0; attempt < ATTEMPTS_PER_SERVER; attempt += 1) {
    for (const server of servers) {
      try {
        return await askOnce(server, name, onExchange);
      } catch (err) {
        errors.push(err.message);
      }
    }
  }
  throw new Error(`no server answered for ${name}: ${errors.join('; ')}`);
}

/** Glued nameservers first; if all of them stay silent, resolve the unglued NS names. */
async function askDelegation({ glue, unglued }, name, onExchange, depth) {
  const errors = [];
  if (glue.length > 0) {
    try {
      return await askAny(glue, name, onExchange, errors);
    } catch {
      // fall through to unglued nameservers
    }
  }
  if (depth >= MAX_NS_DEPTH) throw new Error('nameserver resolution nested too deep');
  for (const nsName of unglued) {
    try {
      const ips = await resolveA(nsName, { onExchange, depth: depth + 1 });
      return await askAny(ips.map((ip) => ({ name: nsName, ip })), name, onExchange, errors);
    } catch (err) {
      errors.push(`${nsName}: ${err.message}`);
    }
  }
  throw new Error(`no nameserver answered for ${name}: ${errors.join('; ')}`);
}

function followAnswer(answers, name) {
  let target = name;
  for (let hops = 0; hops < 10; hops += 1) {
    const a = answers.filter((r) => r.name === target && r.type === TYPE.A).map((r) => r.data);
    if (a.length > 0) return { ips: a, cname: null };
    const cname = answers.find((r) => r.name === target && r.type === TYPE.CNAME);
    if (!cname) return { ips: [], cname: target === name ? null : target };
    target = cname.data;
  }
  throw new Error(`CNAME chain too long for ${name}`);
}

/** Referral -> nameservers with glue addresses + out-of-bailiwick names to resolve from the root. */
function delegation(resp) {
  const nsNames = resp.authority.filter((r) => r.type === TYPE.NS).map((r) => r.data);
  if (nsNames.length === 0) throw new Error('response is neither an answer nor a referral');
  const glue = resp.additional
    .filter((r) => r.type === TYPE.A && nsNames.includes(r.name))
    .map((r) => ({ name: r.name, ip: r.data }));
  const glued = new Set(glue.map((s) => s.name));
  return { glue, unglued: nsNames.filter((n) => !glued.has(n)) };
}

/**
 * Resolve an A record iteratively starting from the root servers.
 * Every UDP exchange is reported via onExchange (exact query/response bytes).
 */
export async function resolveA(name, { onExchange = () => {}, depth = 0 } = {}) {
  const qname = name.toLowerCase().replace(/\.$/, '');
  let servers = { glue: ROOT_SERVERS, unglued: [] };
  for (let step = 0; step < MAX_REFERRALS; step += 1) {
    const resp = await askDelegation(servers, qname, onExchange, depth);
    if (resp.rcode !== 0) throw new Error(`rcode ${resp.rcode} for ${qname}`);
    const { ips, cname } = followAnswer(resp.answers, qname);
    if (ips.length > 0) return ips;
    if (cname) return resolveA(cname, { onExchange, depth });
    servers = delegation(resp);
  }
  throw new Error(`too many referrals for ${qname}`);
}
