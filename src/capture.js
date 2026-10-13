import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { resolveA } from './dns/iterative.js';
import { recordHttpsGet } from './tls/recorder.js';
import { serializeSession } from './session.js';
import { nowMs } from './clock.js';
import { parseTarget } from './target.js';
import { startCapture as startDumpcap, CLOSE_WAIT_MS } from './pcap/dumpcap.js';
import { LIMITS } from './pcap/pcapng.js';
import { captureRunRecord, CAPTURE_RUN_FILE } from './pcap/capture-run.js';

/** The deadline covers DNS, retries, TCP, TLS and the HTTP response together. */
export async function capture(input, options = {}, deps = {}) {
  return (await captureLive(input, { ...options, packetCapture: null }, deps)).session;
}

/**
 * capture(), optionally with dumpcap running around the TCP connection.
 * packetCapture: { dumpcap, iface } or null. Returns { session, packets }; packets is null without
 * packetCapture, else { data, stopReason, warnings } (see src/pcap/dumpcap.js describeStop).
 * dumpcap starts after DNS (its filter needs the address) and before the TCP connection, and is
 * stopped and awaited on success, error, timeout and cancel.
 */
export async function captureLive(input, { timeoutMs = 30000, signal, onProgress = () => {}, packetCapture = null } = {},
  { resolveHost = resolveA, record = recordHttpsGet, startCapture = startDumpcap } = {}) {
  const target = parseTarget(input);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) throw new Error('Timeout must be between 1ms and 300s.');
  signal?.throwIfAborted();
  const deadline = new AbortController();
  const activeSignal = signal ? AbortSignal.any([deadline.signal, signal]) : deadline.signal;
  const timer = setTimeout(() => deadline.abort(new Error(`Request timed out after ${timeoutMs / 1000}s (DNS + TCP + TLS + HTTP).`)), timeoutMs);
  const startedAt = nowMs();
  const dns = [];
  let stage = 'DNS resolution';
  let sniffer = null;
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
    if (packetCapture) {
      stage = 'Packet capture start';
      onProgress(`Capture: starting dumpcap on ${packetCapture.iface} (host ${ips[0]} and tcp port ${target.port})...`);
      sniffer = await startCapture({ dumpcap: packetCapture.dumpcap, iface: packetCapture.iface, ip: ips[0], port: target.port,
        maxSeconds: Math.ceil((timeoutMs + CLOSE_WAIT_MS) / 1000) + 5, maxBytes: LIMITS.maxBytes, signal: activeSignal });
      onProgress('Capture: dumpcap is capturing.');
    }
    stage = 'TLS/HTTP request';
    onProgress(`TLS 1.3: ${target.host}:${target.port} (${ips[0]}); GET ${target.path}`);
    const tls = await record({ ip: ips[0], servername: target.host, path: target.path,
      port: target.port, signal: activeSignal, timeoutMs });
    activeSignal.throwIfAborted();
    const session = serializeSession({ startedAt, host: target.host, path: target.path, dns, tls });
    if (!sniffer) return { session, packets: null };
    clearTimeout(timer); // the request is done; waiting for the capture must not fail it
    const ended = await sniffer.waitForEnd({ local: tls.local, remote: { address: ips[0], port: target.port }, signal });
    const packets = await sniffer.stop({ connectionEnded: ended });
    sniffer = null;
    return { session, packets };
  } catch (err) {
    if (activeSignal.aborted) throw activeSignal.reason;
    throw new Error(`${stage} failed: ${err.message}`, { cause: err });
  } finally {
    clearTimeout(timer);
    await sniffer?.stop();
  }
}

/**
 * Save each successful recording separately; never overwrite a previous session. capture: optional
 * pcapng bytes from the live capture, saved next to it as capture.pcapng; captureRun: how dumpcap
 * ran ({ iface, stopReason, warnings }), saved with it as capture.json (src/pcap/capture-run.js).
 */
export async function saveRecording(session, directory = 'out', { capture = null, captureRun = null } = {}) {
  const root = resolve(directory);
  await mkdir(root, { recursive: true, mode: 0o700 });
  const folder = await mkdtemp(join(root, 'run-'));
  const path = join(folder, 'session.json');
  await writeFile(path, `${JSON.stringify(session, null, 2)}\n`, { mode: 0o600 });
  await writeFile(join(folder, 'keylog.txt'), `${session.tls.keylog.join('\n')}\n`, { mode: 0o600 });
  if (capture) {
    await writeFile(join(folder, 'capture.pcapng'), capture, { mode: 0o600 });
    if (captureRun) {
      const record = captureRunRecord(captureRun, capture);
      await writeFile(join(folder, CAPTURE_RUN_FILE), `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
    }
  }
  return path;
}
