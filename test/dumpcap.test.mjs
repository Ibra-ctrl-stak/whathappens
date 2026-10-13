// dumpcap process lifecycle (src/pcap/dumpcap.js) with a stand-in process: no Wireshark needed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn as nodeSpawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSession } from '../src/session.js';
import { findDumpcap, startCapture, explainFailure, connectionEnded } from '../src/pcap/dumpcap.js';
import { analyzeCapture } from '../src/pcap/connection.js';
import { packetWarnings } from '../src/pcap/completeness.js';
import { flowFromSession, toPcapng, ipv4Tcp } from './helpers/tcp-capture-build.mjs';

const FAKE = fileURLToPath(new URL('./helpers/fake-dumpcap.mjs', import.meta.url));
const session = loadSession(JSON.parse(readFileSync(new URL('./fixtures/github-robots/session.json', import.meta.url))));
const flow = flowFromSession(session);
const full = toPcapng(flow.packets);
const withoutFins = toPcapng(flow.packets.filter((p) => !(p.data[20 + 13] & 0x01))); // TCP flags byte, FIN bit
// Another connection that the capture filter (server address and port) also lets through.
const foreignLocal = { ...session.tls.local, port: session.tls.local.port + 1 };
const foreign = flowFromSession({ ...session, tls: { ...session.tls, local: foreignLocal } }, { clientIsn: 7000, serverIsn: 9000 });
const foreignRst = { dir: 'out', timeMs: foreign.packets.at(-1).timeMs + 1, data: ipv4Tcp({ src: foreignLocal, dst: flow.remote, seq: 1, flags: ['RST'] }) };
const oursOpenForeignClosed = toPcapng([...flow.packets.filter((p) => !(p.data[20 + 13] & 0x01)), ...foreign.packets, foreignRst]);
const target = { ip: session.tls.ip, port: session.tls.port };
const ends = { local: flow.local, remote: flow.remote };
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

/** Run the stand-in instead of dumpcap; returns the options for startCapture and what was spawned. */
function fake(t, mode, pcap = null) {
  const dir = mkdtempSync(join(tmpdir(), 'whathappens-dumpcap-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const env = { ...process.env, FAKE_DUMPCAP_MODE: mode, FAKE_DUMPCAP_ARGS: join(dir, 'args.json') };
  if (pcap) { env.FAKE_DUMPCAP_PCAP = join(dir, 'in.pcapng'); writeFileSync(env.FAKE_DUMPCAP_PCAP, pcap); }
  const spawned = {};
  const spawn = (command, args, options) => {
    Object.assign(spawned, { command, options });
    spawned.child = nodeSpawn(process.execPath, [FAKE, ...args], { ...options, env });
    t.after(() => { if (alive(spawned.child.pid)) spawned.child.kill(); });
    return spawned.child;
  };
  const args = () => JSON.parse(readFileSync(env.FAKE_DUMPCAP_ARGS, 'utf8'));
  return { spawned, args, options: { dumpcap: 'C:\\fake\\dumpcap.exe', iface: 'Ethernet 2', ...target, maxSeconds: 40, maxBytes: 64 * 1024 * 1024, settleMs: 20, spawn } };
}

// ---- finding the program ------------------------------------------------------------------------

test('findDumpcap: an explicit path wins, else PATH, else the standard Wireshark folder', () => {
  const has = (...paths) => (p) => paths.includes(p);
  assert.equal(findDumpcap({ explicit: 'D:\\ws\\dumpcap.exe', exists: has('D:\\ws\\dumpcap.exe') }), 'D:\\ws\\dumpcap.exe');
  assert.throws(() => findDumpcap({ explicit: 'D:\\none.exe', exists: has() }), /dumpcap not found at D:\\none\.exe \(--dumpcap\)/);
  const env = { PATH: ['C:\\tools', 'C:\\ws'].join(process.platform === 'win32' ? ';' : ':') };
  const viaPath = findDumpcap({ env, platform: 'win32', exists: (p) => /ws[\\/]dumpcap\.exe$/.test(p) });
  assert.match(viaPath, /^C:\\ws[\\/]dumpcap\.exe$/);
  assert.equal(findDumpcap({ env: {}, platform: 'win32', exists: has('C:\\Program Files\\Wireshark\\dumpcap.exe') }), 'C:\\Program Files\\Wireshark\\dumpcap.exe');
  assert.throws(() => findDumpcap({ env: {}, platform: 'win32', exists: has() }),
    /not found in PATH or C:\\Program Files\\Wireshark\\dumpcap\.exe.*--dumpcap <path>.*Without --capture no capture program is needed/);
});

// ---- a normal run ---------------------------------------------------------------------------------

test('started without a shell, filtered to the server, ready on "Capturing on"; stopped after both FINs', async (t) => {
  const f = fake(t, 'ready', full);
  const capture = await startCapture(f.options);
  assert.equal(f.spawned.command, 'C:\\fake\\dumpcap.exe');
  assert.equal(f.spawned.options.shell, false);
  assert.deepEqual(f.args(), ['-i', 'Ethernet 2', '-f', `host ${target.ip} and tcp port ${target.port}`, '-w', '-', '-q', '-a', 'duration:40']);
  assert.equal(await capture.waitForEnd({ ...ends, timeoutMs: 5000 }), true);
  const result = await capture.stop({ connectionEnded: true });
  assert.deepEqual([result.stopReason, result.warnings], ['connection-end', []]);
  assert.deepEqual(result.data, full, 'the pcapng bytes as dumpcap wrote them');
  assert.equal(alive(capture.pid), false, 'our dumpcap is no longer running');
  assert.deepEqual(await capture.stop({ connectionEnded: true }), result, 'stop is idempotent');
});

test('no FIN/RST before the wait ends: stopped anyway, and the reason is kept', async (t) => {
  const f = fake(t, 'ready', withoutFins);
  const capture = await startCapture(f.options);
  assert.equal(await capture.waitForEnd({ ...ends, timeoutMs: 300 }), false);
  const result = await capture.stop({ connectionEnded: false });
  assert.equal(result.stopReason, 'wait-timeout');
  assert.match(result.warnings.join('\n'), /stopped before the end of the connection \(FIN from both sides, or RST\) appeared/);
  assert.ok(result.data.length > 0, 'what arrived is kept');
  assert.equal(alive(capture.pid), false);
});

test('a pcapng cut inside its last block: kept as delivered; the cut is visible in the packets', async (t) => {
  const f = fake(t, 'ready', full.subarray(0, full.length - 20));
  const capture = await startCapture(f.options);
  assert.equal(await capture.waitForEnd({ ...ends, timeoutMs: 300 }), false, 'the cut block held the last FIN');
  const result = await capture.stop();
  assert.equal(result.stopReason, 'wait-timeout');
  assert.match(packetWarnings(analyzeCapture(result.data, session)).join('\n'), /cut inside its last block/);
});

test('dumpcap ending by itself before the connection ended is an incomplete capture', async (t) => {
  const f = fake(t, 'early-exit', withoutFins);
  const capture = await startCapture(f.options);
  assert.equal(await capture.waitForEnd({ ...ends, timeoutMs: 2000 }), false, 'the wait stops when dumpcap is gone');
  const result = await capture.stop();
  assert.equal(result.stopReason, 'dumpcap-exited');
  assert.match(result.warnings.join('\n'), /dumpcap stopped by itself before the connection ended/);
});

test('the size limit stops dumpcap and is reported', async (t) => {
  const f = fake(t, 'ready', full);
  const capture = await startCapture({ ...f.options, maxBytes: 1024 });
  await capture.waitForEnd({ ...ends, timeoutMs: 1000 });
  const result = await capture.stop();
  assert.equal(result.stopReason, 'size-limit');
  assert.match(result.warnings.join('\n'), /reached its .* MiB limit; later packets were not kept/);
  assert.ok(!/stopped by itself|stopped early/.test(result.warnings.join('\n')), 'our own kill at the limit is not reported as dumpcap stopping by itself');
  assert.equal(alive(capture.pid), false);
});

// ---- failures to start ---------------------------------------------------------------------------

test('access denied: a clear reason, and nothing left running', async (t) => {
  const f = fake(t, 'denied');
  await assert.rejects(startCapture(f.options), /access denied: dumpcap may not capture here .*Access is denied.*does not change Npcap settings/);
  assert.equal(alive(f.spawned.child.pid), false);
});

test('an unknown interface: named, with the command that lists interfaces', async (t) => {
  const f = fake(t, 'bad-interface');
  await assert.rejects(startCapture(f.options), /interface "Ethernet 2" is not available .*cannot find the device.*dumpcap -D/);
});

test('dumpcap failing during the settle pause after "Capturing on" is a start failure, not a capture', async (t) => {
  const f = fake(t, 'fail-after-ready');
  await assert.rejects(startCapture({ ...f.options, settleMs: 1000 }), /dumpcap failed \(exit code 1\): dumpcap: Error while capturing packets: The adapter was removed\./);
});

test('no "Capturing on" in time: the process is stopped and awaited, then the error is thrown', async (t) => {
  const f = fake(t, 'silent');
  await assert.rejects(startCapture({ ...f.options, readyTimeoutMs: 400 }), /did not report "Capturing on" within 0\.4 s/);
  assert.equal(alive(f.spawned.child.pid), false);
});

test('Ctrl+C while dumpcap is starting: stopped, and the cancel reason is thrown', async (t) => {
  const f = fake(t, 'silent');
  const controller = new AbortController();
  setTimeout(() => controller.abort(new Error('Cancelled.')), 200);
  await assert.rejects(startCapture({ ...f.options, signal: controller.signal }), /^Error: Cancelled\.$/);
  assert.equal(alive(f.spawned.child.pid), false);
});

test('a missing program is named; bad interface strings and addresses are refused before spawning', async () => {
  await assert.rejects(startCapture({ ...target, dumpcap: join(tmpdir(), 'no-such-dumpcap.exe'), iface: '1', maxSeconds: 5, maxBytes: 1000 }), /dumpcap not found at/);
  const never = () => { throw new Error('spawned'); };
  await assert.rejects(startCapture({ ...target, dumpcap: 'x', iface: 'eth0\n-w', maxSeconds: 5, maxBytes: 1000, spawn: never }), /interface name or number/);
  await assert.rejects(startCapture({ dumpcap: 'x', iface: '1', ip: '::1', port: 443, maxSeconds: 5, maxBytes: 1000, spawn: never }), /IPv4 address and TCP port/);
});

// ---- pieces ----------------------------------------------------------------------------------------

test('explainFailure: unknown failures keep dumpcap\'s own line and exit code', () => {
  assert.equal(explainFailure('Capturing on x\r\ndumpcap: Something odd happened\r\n', 'x', 3), 'dumpcap failed (exit code 3): dumpcap: Something odd happened');
  assert.equal(explainFailure('', 'x', 1), 'dumpcap exited (exit code 1) without a message');
});

test('connectionEnded: both FINs, or one RST, of this connection only', () => {
  assert.equal(connectionEnded(full, flow.local, flow.remote), true);
  assert.equal(connectionEnded(withoutFins, flow.local, flow.remote), false);
  assert.equal(connectionEnded(full, { ...flow.local, port: flow.local.port + 1 }, flow.remote), false, 'another connection');
  assert.equal(connectionEnded(Buffer.from('not pcapng'), flow.local, flow.remote), false);
  assert.equal(connectionEnded(oursOpenForeignClosed, flow.local, flow.remote), false,
    'FINs and an RST of another connection through the same filter do not end ours');
});

test('waiting for the end: a foreign connection closing in the same capture does not stop the wait', async (t) => {
  const f = fake(t, 'ready', oursOpenForeignClosed);
  const capture = await startCapture(f.options);
  assert.equal(await capture.waitForEnd({ ...ends, timeoutMs: 400 }), false);
  const result = await capture.stop({ connectionEnded: false });
  assert.equal(result.stopReason, 'wait-timeout');
});
