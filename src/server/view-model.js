// What the page may see: an explicit allow-list of event properties. No buffers, no field
// trees yet (later slices), never the keylog or the raw session.
const EVENT_KEYS = Object.freeze(['t', 'layer', 'kind', 'dir', 'buffer', 'offset', 'length', 'summary', 'damaged', 'problem']);

/** Our check results (see src/tls/certificates.js), reduced to what the panel prints. */
const checkView = (c) => ({
  id: c.id,
  title: c.title,
  status: c.status,
  explanation: c.explanation,
  reason: c.reason ?? null,
  steps: (c.steps ?? []).map((s) => ({ label: s.label, status: s.status, reason: s.reason ?? null })),
  notCovered: [...(c.notCovered ?? [])],
});

const only = (obj, keys) => (obj ? Object.fromEntries(keys.map((k) => [k, obj[k] ?? null])) : null);

/** Data of a captured TCP segment, or of the capture overview event. Never payload bytes. */
function captureView(c) {
  if ('frame' in c) {
    return {
      ...only(c, ['frame', 'flags', 'seq', 'rawSeq', 'ack', 'rawAck', 'window', 'payloadLength', 'captureTime', 'offsetMs']),
      options: only(c.options, ['mss', 'windowScale', 'sackPermitted', 'sackBlocks', 'timestamps', 'malformed']),
      mapping: only(c.mapping, ['status', 'offset', 'length', 'reason']),
      notes: [...(c.notes ?? [])],
    };
  }
  return {
    ...only(c, ['status', 'reason']),
    alignment: only(c.alignment, ['status', 'offsetMs', 'anchorFrame', 'rule', 'warning']),
    reader: only(c.reader, ['packets', 'truncated', 'problems', 'skipped']),
    connection: only(c.connection, ['firstFrame', 'packets', 'candidates', 'anchors']),
    counts: c.counts ?? null,
    source: c.source ? {
      ...only(c.source, ['metadata', 'metadataProblem', 'iface', 'stopReason', 'complete']),
      checked: [...c.source.checked],
      packetWarnings: [...c.source.packetWarnings],
      dumpcapWarnings: c.source.dumpcapWarnings ? [...c.source.dumpcapWarnings] : null,
    } : null,
  };
}

const pick = (event) => ({
  ...Object.fromEntries(EVENT_KEYS.map((k) => [k, event[k]])),
  checks: event.checks ? event.checks.map(checkView) : null,
  capture: event.capture ? captureView(event.capture) : null,
});

/** (index) -> the bytes of that event, or null when it has none / does not exist. */
export function eventBytes(timeline) {
  return (index) => {
    const e = timeline.events[index];
    if (!e || e.buffer === null) return null;
    return timeline.buffers[e.buffer].subarray(e.offset, e.offset + e.length);
  };
}

const X509_KEYS = Object.freeze(['subject', 'issuer', 'serialNumber', 'validFrom', 'validTo', 'dnsNames', 'signatureAlgorithm', 'publicKey', 'ca', 'fingerprint256']);

/** A field node as the page sees it: allow-listed keys only, recursively. */
function fieldView(node) {
  return {
    name: node.name,
    offset: node.offset,
    length: node.length,
    value: node.value ?? null,
    label: node.label ?? null,
    problem: node.problem ?? null,
    ...(node.x509 ? { x509: Object.fromEntries(X509_KEYS.map((k) => [k, node.x509[k]])) } : {}),
    children: node.children.map(fieldView),
  };
}

/** (index) -> { fields: tree | null }, or undefined when there is no such event. */
export function eventFields(timeline) {
  return (index) => {
    const e = timeline.events[index];
    if (!e) return undefined;
    return { fields: e.fields ? fieldView(e.fields) : null };
  };
}

export function timelineView(timeline) {
  const events = timeline.events.map(pick);
  return {
    durationMs: events.reduce((max, e) => (e.t === null ? max : Math.max(max, e.t)), 0), // t null: unaligned capture
    events,
  };
}
