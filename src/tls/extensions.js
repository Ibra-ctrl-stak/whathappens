// TLS extensions (RFC 8446 §4.2 and friends) as field trees. Some extensions mean different
// things in different messages, hence `context`: 'client_hello' | 'server_hello' |
// 'hello_retry_request' | 'encrypted_extensions' | 'certificate' | 'new_session_ticket'.
import { EXTENSION_TYPES, NAMED_GROUPS, VERSIONS, SIGNATURE_SCHEMES, PSK_MODES, EC_POINT_FORMATS } from './names.js';

const text = (bytes) => bytes.toString('latin1'); // display escaping happens at the timeline boundary

const keyShareEntry = (c, name = 'key_share_entry') =>
  c.group(name, [c.uint('group', 2, NAMED_GROUPS), c.opaque('key_exchange', 2)]);

const listOf = (name, lengthSize, read) => (c) => [c.vector(name, lengthSize, (body) => body.many(read))];

const DATA = {
  server_name: (c) => (c.left === 0 ? [] : listOf('server_name_list', 2, (x) =>
    x.group('server_name', [x.uint('name_type', 1, { 0: 'host_name' }), x.opaque('host_name', 2, text)]))(c)),
  application_layer_protocol_negotiation: listOf('protocol_name_list', 2, (x) => x.opaque('protocol_name', 1, text)),
  supported_groups: listOf('named_group_list', 2, (x) => x.uint('named_group', 2, NAMED_GROUPS)),
  signature_algorithms: listOf('supported_signature_algorithms', 2, (x) => x.uint('signature_scheme', 2, SIGNATURE_SCHEMES)),
  signature_algorithms_cert: listOf('supported_signature_algorithms', 2, (x) => x.uint('signature_scheme', 2, SIGNATURE_SCHEMES)),
  ec_point_formats: listOf('ec_point_format_list', 1, (x) => x.uint('ec_point_format', 1, EC_POINT_FORMATS)),
  psk_key_exchange_modes: listOf('ke_modes', 1, (x) => x.uint('ke_mode', 1, PSK_MODES)),
  supported_versions: (c, context) => (context === 'client_hello'
    ? listOf('versions', 1, (x) => x.uint('version', 2, VERSIONS))(c)
    : [c.uint('selected_version', 2, VERSIONS)]),
  key_share: (c, context) => {
    if (context === 'client_hello') return listOf('client_shares', 2, (x) => keyShareEntry(x))(c);
    if (context === 'hello_retry_request') return [c.uint('selected_group', 2, NAMED_GROUPS)];
    return [keyShareEntry(c, 'server_share')];
  },
  early_data: (c, context) => (context === 'new_session_ticket' ? [c.uint('max_early_data_size', 4)] : []),
};

const rawData = (c) => (c.left > 0 ? [c.bytes('data', c.left)] : []);

/**
 * One extension: [extension_type, extension_data{length, ...}]. If its body does not parse as
 * expected, the extension is kept as raw bytes with a problem, and parsing continues.
 */
function extension(c, context) {
  const type = c.uint('extension_type', 2, EXTENSION_TYPES);
  const name = EXTENSION_TYPES[type.value] ?? `unknown_extension_${type.value}`;
  const parse = DATA[name] ?? rawData;
  const dataAt = c.pos;
  try {
    return c.group(name, [type, c.vector('extension_data', 2, (body) => parse(body, context))]);
  } catch (err) {
    c.seek(dataAt);
    const data = c.vector('extension_data', 2, rawData); // a broken outer length still throws
    return c.group(name, [type, data], { problem: err.message });
  }
}

/** extensions<0..2^16-1> */
export const extensions = (c, context) => c.vector('extensions', 2, (body) => body.many((x) => extension(x, context)));
