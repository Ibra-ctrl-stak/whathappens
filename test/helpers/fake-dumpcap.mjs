// A stand-in for dumpcap in process lifecycle tests: no Wireshark/Npcap needed.
// Behaviour comes from the environment:
//   FAKE_DUMPCAP_MODE  ready | early-exit | denied | bad-interface | silent | fail-after-ready
//   FAKE_DUMPCAP_PCAP  file whose bytes are written to stdout (in two parts) after "Capturing on"
//   FAKE_DUMPCAP_ARGS  file that receives the received arguments as JSON
import { readFileSync, writeFileSync } from 'node:fs';

const mode = process.env.FAKE_DUMPCAP_MODE ?? 'ready';
if (process.env.FAKE_DUMPCAP_ARGS) writeFileSync(process.env.FAKE_DUMPCAP_ARGS, JSON.stringify(process.argv.slice(2)));
const iface = process.argv[process.argv.indexOf('-i') + 1];
const stayAlive = () => setInterval(() => {}, 1000);

if (mode === 'denied') {
  process.stderr.write(`dumpcap: The capture session could not be initiated on capture device "${iface}" (Error opening adapter: Access is denied.  (5)).\n`);
  process.exit(1);
}
if (mode === 'bad-interface') {
  process.stderr.write(`dumpcap: The capture session could not be initiated on capture device "${iface}" (Error opening adapter: The system cannot find the device specified.  (20)).\n`);
  process.exit(2);
}
if (mode === 'fail-after-ready') {
  process.stderr.write(`Capturing on '${iface}'\n`);
  setTimeout(() => {
    process.stderr.write('dumpcap: Error while capturing packets: The adapter was removed.\n');
    process.exit(1);
  }, 50);
} else if (mode === 'silent') {
  stayAlive();
} else {
  process.stderr.write(`Capturing on '${iface}'\n`);
  const pcap = process.env.FAKE_DUMPCAP_PCAP ? readFileSync(process.env.FAKE_DUMPCAP_PCAP) : Buffer.alloc(0);
  const half = Math.floor(pcap.length / 2);
  setTimeout(() => {
    process.stdout.write(pcap.subarray(0, half));
    setTimeout(() => {
      process.stdout.write(pcap.subarray(half), () => {
        if (mode === 'early-exit') process.exit(0);
      });
    }, 30);
  }, 30);
  if (mode !== 'early-exit') stayAlive();
}
