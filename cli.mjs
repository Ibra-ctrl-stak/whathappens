#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { readFile } from 'node:fs/promises';
import { capture, saveRecording } from './src/capture.js';
import { openViewer } from './src/viewer.js';
import { printable } from './src/text.js';
import { stat } from 'node:fs/promises';
import { LIMITS } from './src/pcap/pcapng.js';

/** A pcapng file, refused before reading when it exceeds the reader's size limit. */
async function readCapture(file) {
  let info;
  try { info = await stat(file); } catch (err) {
    throw new Error(err.code === 'ENOENT' ? 'Capture file not found. Check the --pcap path.' : `Cannot read the capture: ${err.message}`);
  }
  if (info.size > LIMITS.maxBytes) throw new Error(`The capture is larger than ${LIMITS.maxBytes / 1024 / 1024} MiB; cut it to this connection first (e.g. Wireshark: Export Specified Packets).`);
  return readFile(file);
}

const HELP = `whathappens — watch your own HTTPS request, byte by byte.

Usage:
  node cli.mjs <hostname-or-https-url> [--timeout seconds] [--out directory]
  node cli.mjs --demo
  node cli.mjs --session path/to/session.json

Options:
  --demo             Open the bundled reference trace; no external requests
  --session <file>   Open a previously recorded session
  --pcap <file>      With --session or --demo: add real TCP segments of that connection
                     from a pcapng capture made during the recording (e.g. with Wireshark)
  --timeout <sec>    Total live-request deadline, 1–300 seconds (default: 30)
  --out <directory>  Save a new recording under this directory (default: out)
  --help, -h         Show this help
  --version, -v      Show the version

Examples:
  node cli.mjs github.com/robots.txt
  node cli.mjs "https://example.com/?a=1&b=2" --timeout 60
  npm run demo

Node.js 24+. HTTPS / TLS 1.3 / HTTP/1.1 / IPv4. Redirects are shown, not followed.
The page listens on 127.0.0.1; open the printed URL. Ctrl+C stops it.
`;

let viewer;
const controller = new AbortController();
const stop = () => {
  if (viewer) viewer.close();
  else controller.abort(new Error('Cancelled.'));
};

async function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, strict: true, options: {
    demo: { type: 'boolean' }, session: { type: 'string' }, pcap: { type: 'string' },
    timeout: { type: 'string' }, out: { type: 'string' },
    help: { type: 'boolean', short: 'h' }, version: { type: 'boolean', short: 'v' },
  } });
  if (values.help) { console.log(HELP); return; }
  if (values.version) {
    const pkg = JSON.parse(await readFile(new URL('./package.json', import.meta.url), 'utf8'));
    console.log(pkg.version);
    return;
  }
  if (!positionals.length && !values.demo && values.session === undefined) {
    console.log(HELP);
    return;
  }
  if (positionals.length > 1 || Number(positionals.length > 0) + Number(Boolean(values.demo)) + Number(values.session !== undefined) !== 1) {
    throw new Error('Choose one mode: a URL, --demo, or --session <file>.');
  }
  if (!positionals.length && (values.timeout !== undefined || values.out !== undefined)) {
    throw new Error('--timeout and --out apply only to live requests.');
  }
  if (values.session === '' || values.out === '' || values.pcap === '') throw new Error('A file or directory path cannot be empty.');
  if (values.pcap !== undefined && positionals.length) throw new Error('--pcap applies to --session or --demo (a capture made during that recording).');
  const seconds = values.timeout ?? '30';
  if (!/^\d+$/.test(seconds) || Number(seconds) < 1 || Number(seconds) > 300) {
    throw new Error('--timeout must be a whole number from 1 to 300 seconds.');
  }
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  let session;
  if (values.demo || values.session !== undefined) {
    const file = values.demo ? new URL('./test/fixtures/github-robots/session.json', import.meta.url) : values.session;
    try { session = JSON.parse(await readFile(file, 'utf8')); }
    catch (err) {
      if (err.code === 'ENOENT') throw new Error('Session file not found. Check its path, or try --demo.');
      throw new Error(`Cannot read the session: ${err.message}`);
    }
    if (values.demo) console.log('Demo: recorded github.com/robots.txt session (no external requests).');
  } else {
    session = await capture(positionals[0], { timeoutMs: Number(seconds) * 1000,
      signal: controller.signal, onProgress: (message) => console.log(printable(message)) });
    controller.signal.throwIfAborted();
    const file = await saveRecording(session, values.out ?? 'out');
    console.log(`Saved: ${printable(file)}`);
  }
  controller.signal.throwIfAborted();
  viewer = await openViewer(session, { capture: values.pcap === undefined ? null : await readCapture(values.pcap) });
  if (controller.signal.aborted) { viewer.close(); controller.signal.throwIfAborted(); }
  console.log(`whathappens: ${viewer.eventCount} events`);
  if (viewer.capture) {
    const c = viewer.capture;
    console.log(printable(c.status === 'matched'
      ? `Capture: ${c.segments} TCP segments (${c.reason}); time ${c.alignment === 'aligned' ? 'aligned by the ClientHello' : 'NOT aligned: capture clock used as is'}.`
      : `Capture not used (${c.status}): ${c.reason}`));
  }
  if (viewer.damagedCount) console.log(`${viewer.damagedCount} events could not be fully decoded; see their explanations on the timeline.`);
  console.log(`Open ${viewer.url}`);
  console.log('Local only. Press Ctrl+C to stop.');
}

main().catch((err) => {
  console.error(`whathappens: ${printable(err.message).slice(0, 800)}`);
  if (!controller.signal.aborted) console.error('Try --help for usage, or --demo to explore without a live request.');
  process.exitCode = controller.signal.aborted ? 130 : 1;
  viewer?.close();
}).finally(() => {
  if (!viewer) {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
});
