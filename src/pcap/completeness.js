// How complete is a capture of our connection? Two sources, kept apart:
// - the packets themselves (any pcapng: live, saved, or made with Wireshark), checked here;
// - how dumpcap ran (stop reason, limit, early exit), known only for our own live captures
//   (dumpcap.js describeStop), saved next to the file as capture.json (capture-run.js).
// "complete" is true only when both are known and nothing is missing; packets alone never prove it.

/** What packetWarnings() checks, for display. */
export const PACKET_CHECKS = Object.freeze([
  'the file is not cut inside a block',
  'the client SYN',
  'every recorded byte covered (no gaps)',
  'the end: both FINs and the ACK of each, or an RST',
]);

const MOD = 2 ** 32;

/** FIN segments that no segment from the other side acknowledges (raw ack at or past the FIN). */
function unackedFins(segments) {
  return segments.filter((s) => s.flags.includes('FIN')).filter((fin) => {
    const end = (fin.rawSeq + fin.payloadLength + 1) % MOD;
    return !segments.some((s) => s.dir !== fin.dir && s.rawAck !== null && (s.rawAck - end + MOD) % MOD < MOD / 2);
  });
}

/** What the packets show to be missing, from analyzeCapture (connection.js). [] = nothing seen missing. */
export function packetWarnings(analysis) {
  if (analysis.status !== 'matched') return [`the recorded connection was not identified in the capture (${analysis.status})`];
  const warnings = [];
  const { segments } = analysis;
  if (analysis.reader?.truncated) warnings.push('the capture file is cut inside its last block; packets after it are missing');
  if (!segments.some((s) => s.dir === 'out' && s.flags.includes('SYN') && !s.flags.includes('ACK'))) {
    warnings.push('the client SYN is not in the capture (the capture probably started after it)');
  }
  if (analysis.counts?.gaps) warnings.push(`${analysis.counts.gaps} byte range(s) of the recorded streams are not in the capture (gaps; not proof of loss on the network)`);
  if (!segments.some((s) => s.flags.includes('RST'))) {
    const without = ['out', 'in'].filter((dir) => !segments.some((s) => s.dir === dir && s.flags.includes('FIN')));
    if (without.length) {
      warnings.push(`the end of the connection is not in the capture: no ${without.map((d) => (d === 'out' ? 'client' : 'server')).join(' or ')} FIN, and no RST`);
    }
    for (const fin of unackedFins(segments)) {
      warnings.push(`the ACK of the ${fin.dir === 'out' ? 'client' : 'server'} FIN (frame ${fin.frame}) is not in the capture; the end of the connection is captured only in part`);
    }
  }
  return warnings;
}

/**
 * Both levels together. run: how the capture was made —
 *   { status: 'live' | 'saved', iface, stopReason, warnings }  dumpcap facts (now, or from capture.json);
 *   { status: 'mismatch' | 'invalid', problem }               capture.json exists but was not used;
 *   null                                                      nothing known (no capture.json).
 */
export function captureCompleteness(analysis, run = null) {
  const packets = packetWarnings(analysis);
  const known = run?.status === 'live' || run?.status === 'saved';
  const dumpcap = known ? [...run.warnings] : null;
  return {
    metadata: run?.status ?? 'missing',
    metadataProblem: known ? null : run?.problem ?? null,
    iface: known ? run.iface : null,
    stopReason: known ? run.stopReason : null,
    checked: [...PACKET_CHECKS],
    packetWarnings: packets,
    dumpcapWarnings: dumpcap,
    complete: packets.length || dumpcap?.length ? false : known ? true : null,
  };
}
