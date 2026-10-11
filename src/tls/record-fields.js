// TLS record layer (RFC 8446 §5.1, §5.2) as fields over the wire stream (timeline tcp/out|in).
import { cursor, field } from '../fields.js';
import { VERSIONS } from './names.js';

const CONTENT_TYPES = Object.freeze({ 20: 'change_cipher_spec', 21: 'alert', 22: 'handshake', 23: 'application_data' });
const APPLICATION_DATA = 23;
const AEAD_TAG_LEN = 16;

/** A complete record at stream[offset, offset + length). Encrypted records split into ciphertext + tag. */
export function recordFields(stream, offset, length) {
  const c = cursor(stream, offset, offset + length);
  const header = [c.uint('content_type', 1, CONTENT_TYPES), c.uint('legacy_record_version', 2, VERSIONS), c.uint('length', 2)];
  const encrypted = header[0].value === APPLICATION_DATA && c.left >= AEAD_TAG_LEN;
  const body = encrypted
    ? c.group('encrypted_record', [c.bytes('ciphertext', c.left - AEAD_TAG_LEN, () => null), c.bytes('auth_tag', AEAD_TAG_LEN)])
    : c.bytes('fragment', c.left, () => null);
  return field(encrypted ? 'TLSCiphertext' : 'TLSPlaintext', offset, length, { children: [...header, body] });
}
