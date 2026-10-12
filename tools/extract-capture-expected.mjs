// What tshark sees in a capture, frame by frame, as the oracle for our pcapng/TCP parsing.
// Usage: node tools/extract-capture-expected.mjs <capture.pcapng> > expected-capture.json
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
const TSHARK = process.env.TSHARK ?? 'C:\\Program Files\\Wireshark\\tshark.exe';
const FIELDS = ['frame.number', 'frame.time_epoch', 'ip.src', 'tcp.srcport', 'ip.dst', 'tcp.dstport', 'tcp.seq_raw', 'tcp.ack_raw',
  'tcp.flags', 'tcp.window_size_value', 'tcp.len', 'tcp.options.mss_val', 'tcp.options.wscale.shift'];
const [capture] = process.argv.slice(2);
const { stdout } = await run(TSHARK, ['-r', capture, '-T', 'fields', '-E', 'separator=|', ...FIELDS.flatMap((f) => ['-e', f])]);
const { stdout: version } = await run(TSHARK, ['--version']);
const frames = stdout.split(/\r?\n/).filter(Boolean).map((line) => {
  const v = Object.fromEntries(line.split('|').map((x, i) => [FIELDS[i], x]));
  return {
    frame: Number(v['frame.number']),
    timeEpoch: v['frame.time_epoch'],
    src: `${v['ip.src']}:${v['tcp.srcport']}`, dst: `${v['ip.dst']}:${v['tcp.dstport']}`,
    seq: Number(v['tcp.seq_raw']), ack: Number(v['tcp.ack_raw']), flags: Number.parseInt(v['tcp.flags'], 16),
    window: Number(v['tcp.window_size_value']), len: Number(v['tcp.len']),
    mss: v['tcp.options.mss_val'] ? Number(v['tcp.options.mss_val']) : null,
    windowScale: v['tcp.options.wscale.shift'] ? Number(v['tcp.options.wscale.shift']) : null,
  };
});
process.stdout.write(`${JSON.stringify({ source: `${version.split(/\r?\n/)[0]} on ${capture.replace(/^.*[\\/]/, '')}`, frames }, null, 2)}\n`);
