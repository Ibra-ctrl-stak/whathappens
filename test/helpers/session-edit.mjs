// Derive damaged variants of a recorded session (JSON form) without touching the original.

/**
 * Apply edit(stream) -> stream to one direction of the recorded TCP bytes. The edited stream is
 * cut back into the original chunks (same timestamps); the last chunk absorbs any growth, and
 * chunks past the end of a shortened stream disappear.
 */
export function editStream(sessionJson, dir, edit) {
  const ofDir = sessionJson.tls.raw.filter((c) => c.dir === dir);
  const edited = edit(Buffer.concat(ofDir.map((c) => Buffer.from(c.hex, 'hex'))));
  let pos = 0;
  let seen = 0;
  const raw = sessionJson.tls.raw.flatMap((c) => {
    if (c.dir !== dir) return [c];
    seen += 1;
    const room = Math.max(0, edited.length - pos);
    const length = seen === ofDir.length ? room : Math.min(c.hex.length / 2, room);
    const part = edited.subarray(pos, pos + length);
    pos += length;
    return part.length > 0 ? [{ ...c, hex: part.toString('hex') }] : [];
  });
  return { ...sessionJson, tls: { ...sessionJson.tls, raw } };
}

export const replaceBytes = (offset, oldLength, bytes) => (stream) =>
  Buffer.concat([stream.subarray(0, offset), bytes, stream.subarray(offset + oldLength)]);

export const flipByte = (pos) => (stream) => {
  const copy = Buffer.from(stream);
  copy[pos] ^= 0xff;
  return copy;
};

export const dropTail = (count) => (stream) => stream.subarray(0, stream.length - count);

/** Replace the DNS response of exchange i (hex form). */
export function withDnsResponse(sessionJson, i, response) {
  const dns = sessionJson.dns.map((e, k) => (k === i ? { ...e, responseHex: response.toString('hex') } : e));
  return { ...sessionJson, dns };
}
