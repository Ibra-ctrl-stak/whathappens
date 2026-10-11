// IANA TLS registries (the entries a visualizer is likely to meet).

export const HANDSHAKE_TYPES = Object.freeze({
  1: 'ClientHello', 2: 'ServerHello', 4: 'NewSessionTicket', 5: 'EndOfEarlyData', 8: 'EncryptedExtensions',
  11: 'Certificate', 13: 'CertificateRequest', 15: 'CertificateVerify', 20: 'Finished', 24: 'KeyUpdate', 254: 'message_hash',
});

export const EXTENSION_TYPES = Object.freeze({
  0: 'server_name', 1: 'max_fragment_length', 5: 'status_request', 10: 'supported_groups', 11: 'ec_point_formats',
  13: 'signature_algorithms', 14: 'use_srtp', 15: 'heartbeat', 16: 'application_layer_protocol_negotiation',
  18: 'signed_certificate_timestamp', 19: 'client_certificate_type', 20: 'server_certificate_type', 21: 'padding',
  22: 'encrypt_then_mac', 23: 'extended_master_secret', 27: 'compress_certificate', 28: 'record_size_limit',
  35: 'session_ticket', 41: 'pre_shared_key', 42: 'early_data', 43: 'supported_versions', 44: 'cookie',
  45: 'psk_key_exchange_modes', 47: 'certificate_authorities', 48: 'oid_filters', 49: 'post_handshake_auth',
  50: 'signature_algorithms_cert', 51: 'key_share', 17513: 'application_settings', 65037: 'encrypted_client_hello',
  65281: 'renegotiation_info',
});

export const NAMED_GROUPS = Object.freeze({
  23: 'secp256r1', 24: 'secp384r1', 25: 'secp521r1', 29: 'x25519', 30: 'x448',
  256: 'ffdhe2048', 257: 'ffdhe3072', 258: 'ffdhe4096', 259: 'ffdhe6144', 260: 'ffdhe8192',
  4587: 'SecP256r1MLKEM768', 4588: 'X25519MLKEM768', 4589: 'SecP384r1MLKEM1024', 25497: 'X25519Kyber768Draft00',
});

export const VERSIONS = Object.freeze({ 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' });

export const CIPHER_SUITES = Object.freeze({
  0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
});

export const SIGNATURE_SCHEMES = Object.freeze({
  0x0401: 'rsa_pkcs1_sha256', 0x0501: 'rsa_pkcs1_sha384', 0x0601: 'rsa_pkcs1_sha512',
  0x0403: 'ecdsa_secp256r1_sha256', 0x0503: 'ecdsa_secp384r1_sha384', 0x0603: 'ecdsa_secp521r1_sha512',
  0x0804: 'rsa_pss_rsae_sha256', 0x0805: 'rsa_pss_rsae_sha384', 0x0806: 'rsa_pss_rsae_sha512',
  0x0807: 'ed25519', 0x0808: 'ed448', 0x0809: 'rsa_pss_pss_sha256', 0x080a: 'rsa_pss_pss_sha384', 0x080b: 'rsa_pss_pss_sha512',
  0x0201: 'rsa_pkcs1_sha1', 0x0203: 'ecdsa_sha1',
});

export const PSK_MODES = Object.freeze({ 0: 'psk_ke', 1: 'psk_dhe_ke' });
export const EC_POINT_FORMATS = Object.freeze({ 0: 'uncompressed', 1: 'ansiX962_compressed_prime', 2: 'ansiX962_compressed_char2' });
