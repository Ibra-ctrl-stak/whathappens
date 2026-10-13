import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { capture, saveRecording } from '../src/capture.js';
import { loadSession } from '../src/session.js';
import { decryptSession } from '../src/tls/decrypt.js';

const fixture = JSON.parse(await readFile(new URL('fixtures/github-robots/session.json', import.meta.url), 'utf8'));

test('capture propagates the chosen hostname, path and port and serializes the DNS trace', async () => {
  const session = loadSession(fixture);
  const decrypted = decryptSession(session.tls);
  const progress = [];
  const result = await capture('https://example.com:8443/a?x=1', { onProgress: (line) => progress.push(line) }, {
    resolveHost: async (name, options) => {
      assert.equal(name, 'example.com');
      session.dns.forEach(options.onExchange);
      return ['192.0.2.10'];
    },
    record: async (options) => {
      assert.equal(options.servername, 'example.com');
      assert.equal(options.ip, '192.0.2.10');
      assert.equal(options.port, 8443);
      assert.equal(options.path, '/a?x=1');
      return { ...session.tls, tls: session.tls.info,
        plaintext: { sent: decrypted.client.appData, received: decrypted.server.appData } };
    },
  });
  assert.equal(result.host, 'example.com');
  assert.equal(result.path, '/a?x=1');
  assert.equal(result.dns.length, fixture.dns.length);
  assert.ok(progress.length > 1);
  assert.doesNotThrow(() => loadSession(result));
});

test('the total request deadline aborts DNS before a TLS attempt', { timeout: 1000 }, async () => {
  let recordCalls = 0;
  await assert.rejects(capture('example.com', { timeoutMs: 25 }, {
    resolveHost: (_name, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    }),
    record: async () => { recordCalls += 1; },
  }), /timed out.*DNS/);
  assert.equal(recordCalls, 0);
});

test('separate recordings never overwrite each other and can be loaded again', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'whathappens-save-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = await saveRecording(fixture, directory);
  const second = await saveRecording({ ...fixture, host: 'second.example' }, directory);
  assert.notEqual(first, second);
  assert.equal(JSON.parse(await readFile(first, 'utf8')).host, fixture.host);
  assert.equal(JSON.parse(await readFile(second, 'utf8')).host, 'second.example');
  const loaded = loadSession(JSON.parse(await readFile(first, 'utf8')));
  assert.deepEqual(decryptSession(loaded.tls).server.appData, decryptSession(loadSession(fixture).tls).server.appData);
  assert.equal(await readFile(join(dirname(first), 'keylog.txt'), 'utf8'), `${fixture.tls.keylog.join('\n')}\n`);
  if (process.platform !== 'win32') assert.equal((await stat(first)).mode & 0o777, 0o600);
});

// ---- optional dumpcap around the request (the process itself: test/dumpcap.test.mjs) -----------

const { captureLive } = await import('../src/capture.js');
const { LIMITS } = await import('../src/pcap/pcapng.js');

/** resolveHost / record / startCapture stand-ins that log the order of events. */
function liveDeps({ recordFails = null, recordWaits = false, startFails = null } = {}) {
  const log = [];
  const session = loadSession(fixture);
  const decrypted = decryptSession(session.tls);
  const sniffer = {
    waitForEnd: async (options) => { log.push(['waitForEnd', options]); return true; },
    stop: async (options) => { log.push(['stop', options]); return { data: Buffer.from('pcapng'), complete: true, warnings: [] }; },
  };
  return { log, deps: {
    resolveHost: async (_name, options) => { session.dns.forEach(options.onExchange); log.push(['dns']); return ['192.0.2.10']; },
    startCapture: async (options) => { log.push(['start', options]); if (startFails) throw startFails; return sniffer; },
    record: async ({ signal }) => {
      log.push(['record']);
      if (recordFails) throw recordFails;
      if (recordWaits) await new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
      return { ...session.tls, tls: session.tls.info, plaintext: { sent: decrypted.client.appData, received: decrypted.server.appData } };
    },
  } };
}

test('with a capture: dumpcap starts after DNS and before TCP, filtered to the answer, stopped after the connection ends', async () => {
  const { log, deps } = liveDeps();
  const { session, packets } = await captureLive('https://example.com:8443/', { timeoutMs: 20000, packetCapture: { dumpcap: 'dc', iface: '3' } }, deps);
  assert.deepEqual(log.map(([step]) => step), ['dns', 'start', 'record', 'waitForEnd', 'stop']);
  const start = log[1][1];
  assert.deepEqual([start.dumpcap, start.iface, start.ip, start.port, start.maxBytes], ['dc', '3', '192.0.2.10', 8443, LIMITS.maxBytes]);
  assert.equal(start.maxSeconds, 27, 'request deadline + close wait + margin, so dumpcap ends even if we do not');
  assert.deepEqual(log[3][1].local, fixture.tls.local);
  assert.deepEqual(log[3][1].remote, { address: '192.0.2.10', port: 8443 });
  assert.deepEqual(log[4][1], { connectionEnded: true });
  assert.deepEqual(packets, { data: Buffer.from('pcapng'), complete: true, warnings: [] });
  assert.doesNotThrow(() => loadSession(session));
});

test('without a capture nothing is started and packets is null', async () => {
  const { log, deps } = liveDeps();
  const { packets } = await captureLive('example.com', {}, deps);
  assert.equal(packets, null);
  assert.ok(!log.some(([step]) => step === 'start'));
});

test('dumpcap failing to start stops the run before any TCP connection, with its reason', async () => {
  const { log, deps } = liveDeps({ startFails: new Error('interface "9" is not available') });
  await assert.rejects(captureLive('example.com', { packetCapture: { dumpcap: 'dc', iface: '9' } }, deps), /^Error: Packet capture start failed: interface "9" is not available/);
  assert.ok(!log.some(([step]) => step === 'record'));
});

test('a failed request still stops our dumpcap', async () => {
  const { log, deps } = liveDeps({ recordFails: new Error('ECONNRESET') });
  await assert.rejects(captureLive('example.com', { packetCapture: { dumpcap: 'dc', iface: '3' } }, deps), /TLS\/HTTP request failed: ECONNRESET/);
  assert.deepEqual(log.at(-1)[0], 'stop');
});

test('timeout and Ctrl+C during the request stop our dumpcap too', async () => {
  const timed = liveDeps({ recordWaits: true });
  await assert.rejects(captureLive('example.com', { timeoutMs: 50, packetCapture: { dumpcap: 'dc', iface: '3' } }, timed.deps), /timed out/);
  assert.equal(timed.log.at(-1)[0], 'stop');
  const cancelled = liveDeps({ recordWaits: true });
  const controller = new AbortController();
  setTimeout(() => controller.abort(new Error('Cancelled.')), 50);
  await assert.rejects(captureLive('example.com', { signal: controller.signal, packetCapture: { dumpcap: 'dc', iface: '3' } }, cancelled.deps), /^Error: Cancelled\.$/);
  assert.equal(cancelled.log.at(-1)[0], 'stop');
});

test('the capture is saved as capture.pcapng next to its recording', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'whathappens-save-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = await saveRecording(fixture, directory, { capture: Buffer.from('pcapng bytes') });
  assert.equal(await readFile(join(dirname(file), 'capture.pcapng'), 'utf8'), 'pcapng bytes');
  const without = await saveRecording(fixture, directory);
  await assert.rejects(stat(join(dirname(without), 'capture.pcapng')), { code: 'ENOENT' });
});
