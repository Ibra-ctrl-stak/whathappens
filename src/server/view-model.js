// What the page may see: an explicit allow-list of event properties. No buffers, no field
// trees yet (later slices), never the keylog or the raw session.
const EVENT_KEYS = Object.freeze(['t', 'layer', 'kind', 'dir', 'buffer', 'offset', 'length', 'summary', 'damaged', 'problem']);

const pick = (event) => Object.fromEntries(EVENT_KEYS.map((k) => [k, event[k]]));

export function timelineView(timeline) {
  const events = timeline.events.map(pick);
  return {
    durationMs: events.reduce((max, e) => Math.max(max, e.t), 0),
    events,
  };
}
