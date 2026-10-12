import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { resolveA } from './dns/iterative.js';
import { recordHttpsGet } from './tls/recorder.js';
import { serializeSession } from './session.js';
import { nowMs } from './clock.js';
import { parseTarget } from './target.js';

/** The deadline covers DNS, retries, TCP, TLS and the HTTP response together. */
export async function capture(input, { timeoutMs = 30000, signal, onProgress = () => {} } = {},
  { resolveHost = resolveA, record = recordHttpsGet } = {}) {
  const target = parseTarget(input);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) throw new Error('Timeout must be between 1ms and 300s.');
  signal?.throwIfAborted();
  const deadline = new AbortController();
  const activeSignal = signal ? AbortSignal.any([deadline.signal, signal]) : deadline.signal;
  const timer = setTimeout(() => deadline.abort(new Error(`Request timed out after ${timeoutMs / 1000}s (DNS + TCP + TLS + HTTP).`)), timeoutMs);
  const startedAt = nowMs();
  const dns = [];
  let stage = 'DNS resolution';
  try {
    onProgress(`DNS: resolving ${target.host} from the root servers...`);
    const ips = await resolveHost(target.host, {
      signal: activeSignal,
      onExchange: (event) => {
        dns.push(event);
        onProgress(`DNS: ${event.server.name} — ${event.error ? 'no usable answer; retrying' : 'answer received'}`);
      },
    });
    activeSignal.throwIfAborted();
    if (!ips.length) throw new Error('No IPv4 address was returned.');
    stage = 'TLS/HTTP request';
    onProgress(`TLS 1.3: ${target.host}:${target.port} (${ips[0]}); GET ${target.path}`);
    const tls = await record({ ip: ips[0], servername: target.host, path: target.path,
      port: target.port, signal: activeSignal, timeoutMs });
    activeSignal.throwIfAborted();
    return serializeSession({ startedAt, host: target.host, path: target.path, dns, tls });
  } catch (err) {
    if (activeSignal.aborted) throw activeSignal.reason;
    throw new Error(`${stage} failed: ${err.message}`, { cause: err });
  } finally {
    clearTimeout(timer);
  }
}

/** Save each successful recording separately; never overwrite a previous session. */
export async function saveRecording(session, directory = 'out') {
  const root = resolve(directory);
  await mkdir(root, { recursive: true, mode: 0o700 });
  const folder = await mkdtemp(join(root, 'run-'));
  const path = join(folder, 'session.json');
  await writeFile(path, `${JSON.stringify(session, null, 2)}\n`, { mode: 0o600 });
  await writeFile(join(folder, 'keylog.txt'), `${session.tls.keylog.join('\n')}\n`, { mode: 0o600 });
  return path;
}
