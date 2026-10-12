// Derived bytes have their own coordinate space; never replace the recorded body.
import { gunzipSync } from 'node:zlib';
import { headerValues } from './message.js';
export const MAX_DECODED_BYTES = 4 * 1024 * 1024;
export function decodeHttpBody(buf, message, { maxOutputLength = MAX_DECODED_BYTES } = {}) {
  const { body } = message;
  const fail = (problem) => ({ bytes: null, transformed: false, problem });
  if (body.framing === 'none') return { bytes: null, transformed: false, problem: null };
  if (body.complete !== true || body.framing === 'invalid') return fail('body framing is incomplete or invalid');
  if (message.problems.some((p) => p.includes('conflicts'))) return fail('ambiguous HTTP body framing');
  const transfer = headerValues(message, 'transfer-encoding').join(',').toLowerCase();
  if (transfer && transfer.trim() !== 'chunked') return fail('unsupported Transfer-Encoding chain');
  const encodings = headerValues(message, 'content-encoding').join(',').toLowerCase().split(',').map((v) => v.trim()).filter(Boolean);
  if (encodings.some((v) => v !== 'gzip' && v !== 'identity') || encodings.length > 4) return fail('unsupported Content-Encoding');
  const transformed = body.framing === 'chunked' || encodings.includes('gzip');
  if (!transformed) return { bytes: null, transformed: false, problem: null };
  const ranges = message.chunks?.data ?? [body];
  if (ranges.reduce((n, r) => n + r.length, 0) > maxOutputLength) return fail('encoded body exceeds decoding limit');
  let bytes = Buffer.concat(ranges.map((r) => buf.subarray(r.offset, r.offset + r.length)));
  try {
    for (const coding of encodings.toReversed()) {
      if (coding === 'gzip') bytes = gunzipSync(bytes, { maxOutputLength });
    }
  } catch (err) {
    return fail(`gzip decoding failed (invalid, truncated or over ${maxOutputLength} bytes): ${err.code ?? 'error'}`);
  }
  return { bytes, transformed, problem: null };
}
