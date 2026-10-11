// TLS 1.3 handshake messages (RFC 8446 §4) as field trees over a direction's handshake stream
// (decryptSession(...).client|server.handshake). Offsets are positions in that stream.
import { cursor, field } from '../fields.js';
import { extensions } from './extensions.js';
import { certificateBody } from './certificate-fields.js';
import { HANDSHAKE_TYPES, VERSIONS, CIPHER_SUITES, SIGNATURE_SCHEMES } from './names.js';

// RFC 8446 §4.1.3: a ServerHello with this random is a HelloRetryRequest
const HRR_RANDOM = 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c';

const clientHello = (c) => [
  c.uint('legacy_version', 2, VERSIONS),
  c.bytes('random', 32),
  c.opaque('legacy_session_id', 1),
  c.vector('cipher_suites', 2, (b) => b.many((x) => x.uint('cipher_suite', 2, CIPHER_SUITES))),
  c.vector('legacy_compression_methods', 1, (b) => b.many((x) => x.uint('compression_method', 1, { 0: 'null' }))),
  extensions(c, 'client_hello'),
];

function serverHello(c) {
  const head = [c.uint('legacy_version', 2, VERSIONS), c.bytes('random', 32)];
  const context = head[1].value === HRR_RANDOM ? 'hello_retry_request' : 'server_hello';
  return [
    ...head,
    c.opaque('legacy_session_id_echo', 1),
    c.uint('cipher_suite', 2, CIPHER_SUITES),
    c.uint('legacy_compression_method', 1, { 0: 'null' }),
    extensions(c, context),
  ];
}

const raw = (c) => (c.left > 0 ? [c.bytes('body', c.left)] : []);

const newSessionTicket = (c) => [
  c.uint('ticket_lifetime', 4),
  c.uint('ticket_age_add', 4),
  c.opaque('ticket_nonce', 1),
  c.opaque('ticket', 2, () => null), // opaque to the client by design
  extensions(c, 'new_session_ticket'),
];

const BODIES = Object.freeze({
  1: clientHello,
  2: serverHello,
  4: newSessionTicket,
  8: (c) => [extensions(c, 'encrypted_extensions')],
  11: certificateBody,
  15: (c) => [c.uint('algorithm', 2, SIGNATURE_SCHEMES), c.opaque('signature', 2)],
  20: (c) => [c.bytes('verify_data', c.left)],
});

/**
 * message: { type, offset, length } from the direction's message index.
 * A message that does not parse is returned as one field with a problem (no children),
 * so a broken message is still shown over its bytes.
 */
export function parseHandshake(stream, message) {
  const name = HANDSHAKE_TYPES[message.type] ?? `handshake_${message.type}`;
  const c = cursor(stream, message.offset, message.offset + message.length);
  try {
    const header = [c.uint('msg_type', 1, HANDSHAKE_TYPES), c.uint('length', 3)];
    const body = (BODIES[message.type] ?? raw)(c, stream);
    if (c.left !== 0) throw new Error(`${c.left} unparsed bytes at offset ${c.pos}`);
    return field(name, message.offset, message.length, { children: [...header, ...body] });
  } catch (err) {
    return field(name, message.offset, message.length, { problem: err.message });
  }
}
