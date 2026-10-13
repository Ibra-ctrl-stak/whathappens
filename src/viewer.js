import { loadSession } from './session.js';
import { buildTimeline } from './timeline.js';
import { timelineView, eventBytes, eventFields } from './server/view-model.js';
import { startServer } from './server/server.js';
import { analyzeCapture } from './pcap/connection.js';
import { captureCompleteness } from './pcap/completeness.js';

/**
 * session: session.json content; capture: optional pcapng Buffer of the same connection;
 * captureRun: how that capture was made, see captureCompleteness() (src/pcap/completeness.js):
 * a live or saved dumpcap run, a capture.json that was not used, or null when nothing is known.
 * Packet checks run for every capture; it is called complete only when the run is known too.
 */
export async function openViewer(session, { capture = null, captureRun = null } = {}) {
  const loaded = loadSession(session);
  const found = capture ? analyzeCapture(capture, loaded) : null;
  const source = found && captureCompleteness(found, captureRun);
  const analysis = found && { ...found, source };
  const timeline = buildTimeline(loaded, { capture: analysis });
  const server = await startServer({
    view: timelineView(timeline), bytesOf: eventBytes(timeline), fieldsOf: eventFields(timeline),
  });
  return { ...server, eventCount: timeline.events.length,
    damagedCount: timeline.events.filter((event) => event.damaged).length,
    capture: analysis && { status: analysis.status, reason: analysis.reason, segments: analysis.segments.length,
      alignment: analysis.alignment?.status ?? null, ...source } };
}
