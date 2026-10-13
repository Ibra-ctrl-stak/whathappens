// Capture completeness: packet checks for every capture, dumpcap facts saved in capture.json and
// merged again when a recording is reopened (src/pcap/completeness.js, src/pcap/capture-run.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSession } from '../src/session.js';
import { analyzeCapture } from '../src/pcap/connection.js';
import { packetWarnings, captureCompleteness } from '../src/pcap/completeness.js';
import { captureRunRecord, readCaptureRun } from '../src/pcap/capture-run.js';
import { saveRecording } from '../src/capture.js';
import { flowFromSession, toPcapng, ipv4Tcp, finalAckOf } from './helpers/tcp-capture-build.mjs';

const fixtureJson = JSON.parse(readFileSync(new URL('./fixtures/github-robots/session.json', import.meta.url), 'utf8'));
const session = loadSession(fixtureJson);
const flow = flowFromSession(session);
const finalAck = finalAckOf(flow);
const closed = toPcapng([...flow.packets, finalAck]); // SYN ... both FINs and the ACK of the last one
const noSyn = toPcapng([...flow.packets.slice(1), finalAck]);
const analyze = (pcap) => analyzeCapture(pcap, session);
const SYN_MISSING = 'the client SYN is not in the capture (the capture probably started after it)';
const CLI = fileURLToPath(new URL('../cli.mjs', import.meta.url));

/** Reopen a saved recording through the CLI (--session --pcap) and return its output and capture overview. */
async function reopen(t, folder) {
  const child = spawn(process.execPath, [CLI, '--session', join(folder, 'session.json'), '--pcap', join(folder, 'capture.pcapng')], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => child.kill());
  let out = '';
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no URL: ${out}`)), 10000);
    child.stdout.on('data', (d) => { out += d; const m = /Open (http\S+)/.exec(out); if (m) { clearTimeout(timer); resolve(m[1]); } });
    child.stderr.on('data', (d) => { out += d; });
    child.once('exit', () => reject(new Error(`exited: ${out}`)));
  });
  const view = await (await fetch(new URL('timeline.json', url))).json();
  return { out, overview: view.events.find((e) => e.kind === 'capture') };
}

async function savedRun(t, pcap, run) {
  const directory = await mkdtemp(join(tmpdir(), 'whathappens-reopen-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return dirname(await saveRecording(fixtureJson, directory, { capture: pcap, captureRun: run }));
}

// ---- packet checks ---------------------------------------------------------------------------------

test('packet checks: SYN, coverage, both FINs with their ACKs; any one missing is named', () => {
  assert.deepEqual(packetWarnings(analyze(closed)), []);
  assert.deepEqual(packetWarnings(analyze(noSyn)), [SYN_MISSING]);
  assert.deepEqual(packetWarnings(analyze(toPcapng(flow.packets))), [
    `the ACK of the client FIN (frame ${flow.packets.length}) is not in the capture; the end of the connection is captured only in part`]);
  const noFins = toPcapng(flow.packets.filter((p) => !(p.data[20 + 13] & 0x01)));
  assert.deepEqual(packetWarnings(analyze(noFins)), ['the end of the connection is not in the capture: no client or server FIN, and no RST']);
  const rst = { dir: 'out', timeMs: flow.packets.at(-1).timeMs, data: ipv4Tcp({ src: flow.local, dst: flow.remote, seq: 1000 + 1 + flow.streams.out.length, flags: ['RST'] }) };
  assert.deepEqual(packetWarnings(analyze(toPcapng([...flow.packets.filter((p) => !(p.data[20 + 13] & 0x01)), rst]))), [], 'an RST ends it');
  const dataAt = flow.packets.findIndex((p) => p.dir === 'in' && p.payloadFrom === 0);
  assert.match(packetWarnings(analyze(toPcapng([...flow.packets.filter((_p, i) => i !== dataAt + 1), finalAck]))).join('\n'),
    /1 byte range\(s\) .* not in the capture \(gaps; not proof of loss on the network\)/);
  assert.match(packetWarnings(analyze(closed.subarray(0, closed.length - 20))).join('\n'), /cut inside its last block/);
  assert.deepEqual(packetWarnings(analyze(toPcapng([]))), ['the recorded connection was not identified in the capture (no-match)']);
});

test('complete only when the packets show nothing missing AND how dumpcap ran is known and clean', () => {
  const live = { status: 'live', iface: '7', stopReason: 'connection-end', warnings: [] };
  assert.equal(captureCompleteness(analyze(closed), live).complete, true);
  assert.equal(captureCompleteness(analyze(closed), null).complete, null, 'clean packets alone do not make it complete');
  const limited = captureCompleteness(analyze(closed), { ...live, stopReason: 'size-limit', warnings: ['limit'] });
  assert.deepEqual([limited.complete, limited.dumpcapWarnings], [false, ['limit']]);
  const both = captureCompleteness(analyze(noSyn), { ...live, warnings: ['early'] });
  assert.deepEqual([both.packetWarnings, both.dumpcapWarnings], [[SYN_MISSING], ['early']], 'neither level hides the other');
});

// ---- saved and reopened ----------------------------------------------------------------------------

test('capture.json keeps only what the pcapng cannot say, bound to that file', async (t) => {
  const run = { iface: '7', stopReason: 'wait-timeout', warnings: ['stopped before the end'] };
  const folder = await savedRun(t, noSyn, run);
  const saved = JSON.parse(await readFile(join(folder, 'capture.json'), 'utf8'));
  assert.deepEqual(Object.keys(saved).sort(), ['capture', 'format', 'iface', 'stopReason', 'tool', 'warnings']);
  assert.deepEqual(saved, captureRunRecord(run, noSyn));
  assert.deepEqual(Object.keys(saved.capture).sort(), ['bytes', 'file', 'sha256']);
});

test('reopening an incomplete live capture: packet and dumpcap warnings both survive', async (t) => {
  const folder = await savedRun(t, noSyn, { iface: '7', stopReason: 'wait-timeout', warnings: ['dumpcap was stopped before the end of the connection appeared'] });
  const { out, overview } = await reopen(t, folder);
  const s = overview.capture.source;
  assert.equal(s.metadata, 'saved');
  assert.equal(s.complete, false);
  assert.deepEqual(s.packetWarnings, [SYN_MISSING]);
  assert.deepEqual(s.dumpcapWarnings, ['dumpcap was stopped before the end of the connection appeared']);
  assert.deepEqual([s.iface, s.stopReason], ['7', 'wait-timeout']);
  assert.match(overview.summary, /^INCOMPLETE capture/);
  assert.match(out, /Capture INCOMPLETE: the client SYN is not in the capture.*; dumpcap was stopped before the end/);
});

test('a saved size-limit or early-exit warning makes a capture with clean packets incomplete', async (t) => {
  for (const [stopReason, warning] of [['size-limit', 'the capture reached its 64 MiB limit; later packets were not kept'],
    ['dumpcap-exited', 'dumpcap stopped early: dumpcap failed (exit code 1): adapter removed']]) {
    const folder = await savedRun(t, closed, { iface: '7', stopReason, warnings: [warning] });
    const s = (await reopen(t, folder)).overview.capture.source;
    assert.deepEqual([s.metadata, s.stopReason, s.complete, s.packetWarnings, s.dumpcapWarnings], ['saved', stopReason, false, [], [warning]]);
  }
});

test('an old pcapng without capture.json and without the client SYN: checked by packets, run unknown', async (t) => {
  const folder = await savedRun(t, noSyn, null);
  await assert.rejects(readFile(join(folder, 'capture.json')), { code: 'ENOENT' });
  const { out, overview } = await reopen(t, folder);
  const s = overview.capture.source;
  assert.deepEqual([s.metadata, s.complete, s.packetWarnings, s.dumpcapWarnings], ['missing', false, [SYN_MISSING], null]);
  assert.match(out, /How the capture was made is unknown \(no capture\.json next to it\); checked by its packets only\./);
  const clean = (await reopen(t, await savedRun(t, closed, null))).overview.capture.source;
  assert.deepEqual([clean.metadata, clean.complete, clean.packetWarnings], ['missing', null, []], 'not called complete on packets alone');
});

test('capture.json of another capture file is not applied; a broken one is reported, not trusted', async (t) => {
  const folder = await savedRun(t, closed, { iface: '7', stopReason: 'size-limit', warnings: ['limit of ANOTHER capture'] });
  await writeFile(join(folder, 'capture.pcapng'), noSyn); // replaced afterwards: metadata no longer matches
  const { out, overview } = await reopen(t, folder);
  const s = overview.capture.source;
  assert.deepEqual([s.metadata, s.dumpcapWarnings, s.stopReason, s.iface], ['mismatch', null, null, null]);
  assert.equal(s.metadataProblem, 'capture.json describes another capture file (size or SHA-256 differs)');
  assert.deepEqual(s.packetWarnings, [SYN_MISSING], 'the packets of the file actually opened are still checked');
  assert.ok(!out.includes('ANOTHER'), 'nothing of the other capture is shown');
  const sameSize = Buffer.from(closed);
  sameSize[sameSize.length - 30] ^= 0xff;
  assert.equal(readCaptureRun(JSON.stringify(captureRunRecord({ iface: '7', stopReason: 'connection-end', warnings: [] }, closed)), sameSize).status,
    'mismatch', 'same size, different bytes: caught by SHA-256');
  assert.deepEqual(readCaptureRun('{', closed), { status: 'invalid', problem: 'capture.json is not valid JSON' });
  assert.equal(readCaptureRun(JSON.stringify({ ...captureRunRecord({ iface: '7', stopReason: 'oops', warnings: [] }, closed) }), closed).status, 'invalid');
  assert.equal(readCaptureRun(JSON.stringify({ ...captureRunRecord({ iface: '7', stopReason: 'connection-end', warnings: [] }, closed), format: 2 }), closed).status, 'invalid');
});
