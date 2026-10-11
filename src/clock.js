// One clock for every recorder: epoch milliseconds with sub-millisecond precision,
// so DNS, TCP and TLS events of a session land on the same timeline.
export const nowMs = () => performance.timeOrigin + performance.now();
