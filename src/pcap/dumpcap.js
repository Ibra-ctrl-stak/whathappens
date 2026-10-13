// Run dumpcap (Wireshark's capture engine) around one live request. Optional: nothing here is
// needed unless --capture is given.
//
// Why pcapng goes through stdout (-w -): on Windows a child process cannot be sent SIGINT; Node's
// kill() is TerminateProcess, and a dumpcap writing its own file loses every buffered packet
// (verified: 0 packets in the file). With -w - the packets reach us as dumpcap flushes them; we
// wait until our connection's FIN/RST has arrived, then stop dumpcap and write the file ourselves.
// Measured on Windows (loopback, 4 runs): this gave the same packets as a dumpcap that stopped by
// itself (-a duration). Anything not seen before the stop is reported, never assumed.
import { spawn as nodeSpawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import net from 'node:net';
import { readPcapng } from './pcapng.js';
import { decodeTcp } from './ipv4-tcp.js';

const READY = /Capturing on /;
const STANDARD_PATHS = {
  win32: ['C:\\Program Files\\Wireshark\\dumpcap.exe', 'C:\\Program Files (x86)\\Wireshark\\dumpcap.exe'],
  darwin: ['/Applications/Wireshark.app/Contents/MacOS/dumpcap'],
  linux: ['/usr/bin/dumpcap', '/usr/sbin/dumpcap'],
};
export const READY_TIMEOUT_MS = 10000;
// "Capturing on" is printed before packets reliably flow: on a WireGuard interface the client SYN
// was missing in 3 of 5 live runs connecting at once, and present in 11 of 11 after this pause.
// A measured value, not a guarantee; completeness.js reports a missing SYN either way.
export const SETTLE_MS = 500;
export const CLOSE_WAIT_MS = 2000;
const EXIT_WAIT_MS = 5000;
const POLL_MS = 50;

/** explicit path, else PATH, else the standard install folder. Throws with what was tried. */
export function findDumpcap({ explicit, env = process.env, platform = process.platform, exists = existsSync } = {}) {
  if (explicit !== undefined) {
    if (exists(explicit)) return explicit;
    throw new Error(`dumpcap not found at ${explicit} (--dumpcap).`);
  }
  const name = platform === 'win32' ? 'dumpcap.exe' : 'dumpcap';
  const standard = STANDARD_PATHS[platform] ?? [];
  const fromPath = (env.PATH ?? env.Path ?? '').split(delimiter).filter(Boolean).map((dir) => join(dir, name));
  const found = [...fromPath, ...standard].find((p) => exists(p));
  if (found) return found;
  throw new Error(`dumpcap was not found in PATH${standard.length ? ` or ${standard.join(', ')}` : ''}. Install Wireshark (with Npcap on Windows) or pass --dumpcap <path>. Without --capture no capture program is needed.`);
}

/** Turn dumpcap's stderr into one clear reason. */
export function explainFailure(stderr, iface, exitCode = null) {
  const text = stderr.replace(/\r/g, '').trim();
  const lines = text.split('\n').filter((l) => l && !READY.test(l) && !/^File: /.test(l));
  const line = lines.find((l) => /error|denied|permission|privilege|no such|not |failed|couldn't|unable/i.test(l)) ?? lines.at(-1) ?? '';
  if (/permission|denied|privilege|not permitted|administrator/i.test(text)) {
    return `access denied: dumpcap may not capture here (${line}). On Windows, Npcap may be limited to administrators; this tool does not change Npcap settings.`;
  }
  if (/no such device|doesn't exist|does not exist|not a valid interface|no capture devices|there is no device|is not a known interface|couldn't be found|error opening adapter|interface.*not found/i.test(text)) {
    return `interface ${JSON.stringify(iface)} is not available (${line}). List interfaces with: dumpcap -D`;
  }
  const code = exitCode === null ? '' : ` (exit code ${exitCode})`;
  return line ? `dumpcap failed${code}: ${line}` : `dumpcap exited${code} without a message`;
}

const sleep = (ms, signal) => new Promise((resolve) => {
  const timer = setTimeout(done, ms);
  signal?.addEventListener('abort', done, { once: true });
  function done() { clearTimeout(timer); signal?.removeEventListener('abort', done); resolve(); }
});

/**
 * Start dumpcap on `iface`, keeping only TCP to ip:port; resolves once dumpcap reports it is
 * capturing (so the SYN is not missed). Returns { pid, waitForEnd(), stop() }. On any failure
 * the process is stopped and awaited before the error is thrown.
 */
export async function startCapture({
  dumpcap, iface, ip, port, maxSeconds, maxBytes, signal,
  readyTimeoutMs = READY_TIMEOUT_MS, settleMs = SETTLE_MS, spawn = nodeSpawn,
}) {
  if (typeof iface !== 'string' || !iface || /[\0-\x1f]/.test(iface)) throw new Error('--capture needs an interface name or number (see dumpcap -D).');
  if (!net.isIPv4(ip) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Capture needs the target IPv4 address and TCP port.');
  if (!Number.isInteger(maxSeconds) || maxSeconds < 1 || !Number.isInteger(maxBytes) || maxBytes < 1) throw new Error('Invalid capture limits.');
  signal?.throwIfAborted();
  // -a duration: dumpcap stops by itself even if this process dies first. Size is limited here.
  const args = ['-i', iface, '-f', `host ${ip} and tcp port ${port}`, '-w', '-', '-q', '-a', `duration:${maxSeconds}`];
  const child = spawn(dumpcap, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false });
  const chunks = [];
  let bytes = 0;
  let limitReached = false;
  let stderr = '';
  let stopRequested = false;
  const exited = new Promise((resolve) => {
    child.once('exit', (code, sig) => resolve({ code, signal: sig }));
    child.once('error', (err) => resolve({ code: null, signal: null, spawnError: err }));
  });
  const running = () => child.exitCode === null && child.signalCode === null;
  const terminate = async () => {
    if (running() && child.pid !== undefined) child.kill();
    return Promise.race([exited, new Promise((r) => setTimeout(() => r(null), EXIT_WAIT_MS).unref())]);
  };
  child.stdout.on('data', (d) => {
    if (limitReached) return;
    if (bytes + d.length > maxBytes) { limitReached = true; child.kill(); return; }
    chunks.push(d);
    bytes += d.length;
  });
  child.stderr.on('data', (d) => { stderr += d; });

  const ready = await new Promise((resolve) => {
    const timer = setTimeout(() => finish({ error: new Error(`dumpcap did not report "Capturing on" within ${readyTimeoutMs / 1000} s${stderr.trim() ? `: ${explainFailure(stderr, iface)}` : ''}`) }), readyTimeoutMs);
    const onAbort = () => finish({ error: signal.reason });
    const check = () => { if (READY.test(stderr)) finish({}); };
    signal?.addEventListener('abort', onAbort, { once: true });
    child.stderr.on('data', check);
    exited.then((exit) => finish({ error: exit.spawnError
      ? new Error(exit.spawnError.code === 'ENOENT' ? `dumpcap not found at ${dumpcap}` : `cannot run dumpcap: ${exit.spawnError.message}`)
      : new Error(explainFailure(stderr, iface, exit.code)) }));
    function finish(result) {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      child.stderr.off('data', check);
      resolve(result);
    }
  });
  if (!ready.error) await sleep(settleMs, signal);
  const failure = ready.error ?? (signal?.aborted ? signal.reason : null)
    ?? (running() ? null : new Error(explainFailure(stderr, iface, child.exitCode)));
  if (failure) {
    await terminate();
    throw failure;
  }

  const data = () => Buffer.concat(chunks);
  return {
    pid: child.pid,
    /** Wait until both FINs (or an RST) of local<->remote are in the capture; false otherwise. */
    async waitForEnd({ local, remote, timeoutMs = CLOSE_WAIT_MS, signal: waitSignal }) {
      const deadline = Date.now() + timeoutMs;
      let parsed = -1;
      for (;;) {
        if (bytes !== parsed) {
          parsed = bytes;
          if (connectionEnded(data(), local, remote)) return true;
        }
        if (Date.now() >= deadline || limitReached || !running() || waitSignal?.aborted) return false;
        await sleep(POLL_MS, waitSignal);
      }
    },
    /** Stop our dumpcap (idempotent), wait for it to exit, and say what the data is worth. */
    async stop({ connectionEnded: ended = false } = {}) {
      const endedEarly = !stopRequested && !running();
      stopRequested = true;
      const exit = endedEarly ? await exited : await terminate();
      return describeStop({ data: data(), ended, endedEarly, limitReached, exit, stderr, iface, maxSeconds, maxBytes });
    },
  };
}

export const STOP_REASONS = Object.freeze(['connection-end', 'wait-timeout', 'dumpcap-exited', 'size-limit']);

/**
 * { data, stopReason, warnings }: how dumpcap ran, i.e. what cannot be seen in the pcapng later.
 * What the packets show (SYN, data, FIN/ACK, a cut file) is checked by completeness.js.
 */
export function describeStop({ data, ended, endedEarly, limitReached, exit, stderr, iface, maxSeconds, maxBytes }) {
  const selfExit = endedEarly && !limitReached; // at the size limit we kill dumpcap ourselves
  const stopReason = limitReached ? 'size-limit' : selfExit ? 'dumpcap-exited' : ended ? 'connection-end' : 'wait-timeout';
  const warnings = [];
  if (exit === null) warnings.push(`dumpcap did not exit within ${EXIT_WAIT_MS / 1000} s after being stopped; check for a leftover dumpcap process`);
  if (selfExit) {
    warnings.push(exit?.code === 0
      ? `dumpcap stopped by itself before the connection ended (duration limit ${maxSeconds} s?)`
      : `dumpcap stopped early: ${explainFailure(stderr, iface, exit?.code ?? null)}`);
  }
  if (limitReached) warnings.push(`the capture reached its ${maxBytes / 1024 / 1024} MiB limit; later packets were not kept`);
  if (stopReason === 'wait-timeout') warnings.push('dumpcap was stopped before the end of the connection (FIN from both sides, or RST) appeared in the capture; packets it had not yet passed on are missing');
  if (!data.length) return { data: null, stopReason, warnings: [...warnings, 'dumpcap delivered no capture data'] };
  return { data, stopReason, warnings };
}

/** Did both sides send FIN, or either side RST, between local and remote? */
export function connectionEnded(buf, local, remote) {
  let read;
  try { read = readPcapng(buf); } catch { return false; }
  const fin = { out: false, in: false };
  for (const p of read.packets) {
    const { tcp } = decodeTcp(p);
    if (!tcp) continue;
    const out = tcp.src.address === local.address && tcp.src.port === local.port && tcp.dst.address === remote.address && tcp.dst.port === remote.port;
    const back = tcp.src.address === remote.address && tcp.src.port === remote.port && tcp.dst.address === local.address && tcp.dst.port === local.port;
    if (!out && !back) continue;
    if (tcp.flags.includes('RST')) return true;
    if (tcp.flags.includes('FIN')) fin[out ? 'out' : 'in'] = true;
  }
  return fin.out && fin.in;
}
