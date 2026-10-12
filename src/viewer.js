import { loadSession } from './session.js';
import { buildTimeline } from './timeline.js';
import { timelineView, eventBytes, eventFields } from './server/view-model.js';
import { startServer } from './server/server.js';

export async function openViewer(session) {
  const timeline = buildTimeline(loadSession(session));
  const server = await startServer({
    view: timelineView(timeline), bytesOf: eventBytes(timeline), fieldsOf: eventFields(timeline),
  });
  return { ...server, eventCount: timeline.events.length,
    damagedCount: timeline.events.filter((event) => event.damaged).length };
}
