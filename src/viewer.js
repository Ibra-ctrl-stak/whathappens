import { loadSession } from './session.js';
import { buildTimeline } from './timeline.js';
import { timelineView, eventBytes, eventFields } from './server/view-model.js';
import { startServer } from './server/server.js';
import { analyzeCapture } from './pcap/connection.js';

/** session: session.json content; capture: optional pcapng Buffer of the same connection. */
export async function openViewer(session, { capture = null } = {}) {
  const loaded = loadSession(session);
  const analysis = capture ? analyzeCapture(capture, loaded) : null;
  const timeline = buildTimeline(loaded, { capture: analysis });
  const server = await startServer({
    view: timelineView(timeline), bytesOf: eventBytes(timeline), fieldsOf: eventFields(timeline),
  });
  return { ...server, eventCount: timeline.events.length,
    damagedCount: timeline.events.filter((event) => event.damaged).length,
    capture: analysis && { status: analysis.status, reason: analysis.reason, segments: analysis.segments.length, alignment: analysis.alignment?.status ?? null } };
}
