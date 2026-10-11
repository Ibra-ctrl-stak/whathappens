// What the page may see: an explicit allow-list of event properties. No buffers, no field
// trees yet (later slices), never the keylog or the raw session.
const EVENT_KEYS = Object.freeze(['t', 'layer', 'kind', 'dir', 'buffer', 'offset', 'length', 'summary', 'damaged', 'problem']);

const pick = (event) => Object.fromEntries(EVENT_KEYS.map((k) => [k, event[k]]));

/** (index) -> the bytes of that event, or null when it has none / does not exist. */
export function eventBytes(timeline) {
  return (index) => {
    const e = timeline.events[index];
    if (!e || e.buffer === null) return null;
    return timeline.buffers[e.buffer].subarray(e.offset, e.offset + e.length);
  };
}

export function timelineView(timeline) {
  const events = timeline.events.map(pick);
  return {
    durationMs: events.reduce((max, e) => Math.max(max, e.t), 0),
    events,
  };
}
